package pipeline

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coal/lobstertrap/internal/audit"
	"github.com/coal/lobstertrap/internal/inspector"
	"github.com/coal/lobstertrap/internal/metadata"
	"github.com/coal/lobstertrap/internal/policy"
)

var requestCounter atomic.Uint64

// bootNonce makes request IDs unique across proxy restarts (req-<nonce>-<n>), so a
// decision or paused run for an old ID can never attach to a new request.
var bootNonce = newBootNonce()

func newBootNonce() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("lobstertrap: cannot generate request ID nonce: %v", err))
	}
	return hex.EncodeToString(b)
}

// EventObserver is a callback function that receives pipeline events.
// direction is "ingress" or "egress".
type EventObserver func(event PipelineEvent)

// PipelineEvent represents a single pipeline event for observers.
type PipelineEvent struct {
	Timestamp time.Time                 `json:"timestamp"`
	Direction string                    `json:"direction"`
	RequestID string                    `json:"request_id"`
	Action    policy.Action             `json:"action"`
	RuleName  string                    `json:"rule_name,omitempty"`
	Metadata  *inspector.PromptMetadata `json:"metadata"`
	Blocked   bool                      `json:"blocked"`
	DenyMsg   string                    `json:"deny_message,omitempty"`
}

// Pipeline runs the ingress → inference → egress inspection flow.
type Pipeline struct {
	inspector    *inspector.Inspector
	ingressTable *policy.MatchActionTable
	egressTable  *policy.MatchActionTable
	pol          *policy.Policy
	auditLogger  *audit.Logger

	// agentKeys enables identity binding when non-nil (see identity.go).
	agentKeys map[string]string
	// authFailures locks out client IPs that keep failing agent authentication.
	authFailures *authFailureLimiter
	// approvals + reviews let a human-approved HUMAN_REVIEW request be replayed once.
	approvals ReviewApprovals
	reviews   *reviewLedger

	observerMu sync.RWMutex
	observers  []EventObserver
}

// Option configures optional Pipeline enforcement layers.
type Option func(*Pipeline)

// WithAgentIdentity binds agent_id claims to per-agent keys (agent_id → key) and
// enforces each agent's allowed intents from the policy `agents:` registry.
func WithAgentIdentity(keys map[string]string) Option {
	return func(p *Pipeline) {
		copied := make(map[string]string, len(keys))
		for id, key := range keys {
			copied[id] = key
		}
		p.agentKeys = copied
	}
}

// WithReviewApprovals lets a HUMAN_REVIEW request be replayed once after a human
// approves it (the caller sends the original request ID as an approval reference).
func WithReviewApprovals(approvals ReviewApprovals) Option {
	return func(p *Pipeline) {
		p.approvals = approvals
	}
}

// New creates a new Pipeline from a loaded policy.
func New(pol *policy.Policy, auditLogger *audit.Logger, opts ...Option) *Pipeline {
	ingress, egress := policy.BuildTables(pol)
	p := &Pipeline{
		inspector:    inspector.New(),
		ingressTable: ingress,
		egressTable:  egress,
		pol:          pol,
		auditLogger:  auditLogger,
		reviews:      newReviewLedger(),
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.agentKeys != nil && p.authFailures == nil {
		p.authFailures = newAuthFailureLimiter(DefaultAuthFailuresPerWindow, DefaultAuthFailureWindow, nil)
	}
	return p
}

// IngressRequest is everything the proxy knows about an inbound prompt.
type IngressRequest struct {
	Prompt   string
	Declared *metadata.RequestHeaders // nil if the agent sent no _lobstertrap field
	AgentKey string                   // X-Agent-Key header
	// ClientIP is the TCP peer address (never a forwarded-for header), used to
	// lock out sources that keep failing agent authentication.
	ClientIP string
	// Body is the forwarded request body (without _lobstertrap). An approval is
	// bound to it, so a replay cannot change the model, tools, or parameters.
	Body []byte
	// ReviewApprovalID is the request ID of an earlier HUMAN_REVIEW that a human
	// approved (X-Sentinel-Review-Approved header). Empty for normal requests.
	ReviewApprovalID string
}

// ProcessIngress inspects a prompt and evaluates ingress rules.
// declared may be nil if the agent didn't send _lobstertrap headers.
func (p *Pipeline) ProcessIngress(promptText string, declared *metadata.RequestHeaders) *PipelineResult {
	return p.ProcessIngressRequest(IngressRequest{Prompt: promptText, Declared: declared})
}

// evaluateRules runs identity binding, the ingress table, review approvals, and the
// network/filesystem policies, in that order.
func (p *Pipeline) evaluateRules(req IngressRequest, meta *inspector.PromptMetadata, reqID string) (policy.RuleResult, string, bool) {
	if denied := p.checkAgentIdentity(req); denied != nil {
		return *denied, "", true
	}

	result := p.ingressTable.Evaluate(meta)
	approval := ""
	if result.Action == policy.ActionHumanReview {
		result, approval = p.resolveHumanReview(req, reqID, result)
	}

	// Enforce network and filesystem policies for requests that passed rule evaluation.
	// The YAML `network` and `filesystem` sections are separate from ingress_rules and
	// must be checked explicitly — they are not part of the match-action table.
	if result.Action == policy.ActionAllow || result.Action == policy.ActionLog {
		if len(meta.TargetDomains) > 0 {
			if blocked, msg := policy.CheckNetworkPolicy(&p.pol.Network, meta.TargetDomains); blocked {
				result = policy.RuleResult{Matched: true, RuleName: "network_policy", Action: policy.ActionDeny, DenyMessage: msg}
			}
		}
		if result.Action != policy.ActionDeny && len(meta.TargetPaths) > 0 {
			if blocked, msg := policy.CheckFilesystemPolicy(&p.pol.Filesystem, meta.TargetPaths); blocked {
				result = policy.RuleResult{Matched: true, RuleName: "filesystem_policy", Action: policy.ActionDeny, DenyMessage: msg}
			}
		}
	}
	return result, approval, false
}

// resolveHumanReview either releases a human-approved replay (once) or records this
// request as pending review. Returns the result and an audit note on the approval.
func (p *Pipeline) resolveHumanReview(req IngressRequest, reqID string, result policy.RuleResult) (policy.RuleResult, string) {
	agentID := ""
	if req.Declared != nil {
		agentID = req.Declared.AgentID
	}
	fingerprint := requestFingerprint(req)
	if req.ReviewApprovalID != "" && !validApprovalID(req.ReviewApprovalID) {
		p.reviews.record(reqID, agentID, fingerprint)
		return result, "malformed"
	}
	if req.ReviewApprovalID != "" && p.approvals != nil &&
		p.reviews.consume(req.ReviewApprovalID, agentID, fingerprint, p.approvals) {
		return policy.RuleResult{Matched: true, RuleName: ruleHumanReviewApproved, Action: policy.ActionAllow}, "accepted"
	}
	p.reviews.record(reqID, agentID, fingerprint)
	if req.ReviewApprovalID != "" {
		return result, "rejected"
	}
	return result, ""
}

// inspectAndEvaluate runs DPI and the ingress rules. A locked-out caller is denied
// before DPI runs (decided once here, so an expiring lockout can never let rules
// evaluate against empty metadata), so a lockout also sheds the DPI CPU cost.
func (p *Pipeline) inspectAndEvaluate(req IngressRequest, reqID string) (*inspector.PromptMetadata, policy.RuleResult, string, bool) {
	if p.lockedOut(req) {
		return &inspector.PromptMetadata{}, *authRateLimitedDeny(), "", true
	}
	meta := p.inspector.Inspect(req.Prompt)
	// Enrich metadata with declared headers before policy evaluation so rules
	// can match on has_mismatch and declared_intent.
	if declared := req.Declared; declared != nil {
		meta.DeclaredIntent = declared.DeclaredIntent
		meta.HasMismatch = declared.DeclaredIntent != "" &&
			declared.DeclaredIntent != meta.IntentCategory
	}
	result, approval, identityDenied := p.evaluateRules(req, meta, reqID)
	return meta, result, approval, identityDenied
}

// ProcessIngressRequest inspects a prompt and evaluates all ingress enforcement.
func (p *Pipeline) ProcessIngressRequest(req IngressRequest) *PipelineResult {
	reqID := fmt.Sprintf("req-%s-%d", bootNonce, requestCounter.Add(1))
	declared := req.Declared

	meta, result, approval, identityDenied := p.inspectAndEvaluate(req, reqID)

	// Detect mismatches between declared and detected metadata
	mismatches := metadata.DetectMismatches(declared, meta)

	pr := &PipelineResult{
		RequestID:       reqID,
		IngressMetadata: meta,
		IngressResult:   &result,
		DeclaredHeaders: declared,
		Mismatches:      mismatches,
	}

	if result.Action == policy.ActionDeny || result.Action == policy.ActionQuarantine {
		pr.Blocked = true
		pr.BlockedAt = "ingress"
		pr.DenyMessage = result.DenyMessage
	}

	// Extract agent ID for audit logging. Claims that failed identity checks are
	// attacker-controlled: log a truncated agent ID and drop the declared headers.
	var agentID string
	auditDeclared := declared
	if declared != nil {
		agentID = declared.AgentID
	}
	if identityDenied {
		agentID = truncateAgentID(agentID)
		auditDeclared = nil
	}

	// Audit log
	p.auditLogger.Log(audit.Entry{
		RequestID:       reqID,
		Direction:       "ingress",
		Action:          string(result.Action),
		RuleName:        result.RuleName,
		DenyMessage:     result.DenyMessage,
		Metadata:        meta,
		RiskScore:       meta.RiskScore,
		TokenCount:      meta.TokenCount,
		DeclaredHeaders: auditDeclared,
		Mismatches:      mismatches,
		AgentID:         agentID,
		ReviewApproval:  reviewApprovalNote(approval, req.ReviewApprovalID),
	})

	// Notify observers
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "ingress",
		RequestID: reqID,
		Action:    result.Action,
		RuleName:  result.RuleName,
		Metadata:  meta,
		Blocked:   pr.Blocked,
		DenyMsg:   result.DenyMessage,
	})

	return pr
}

func reviewApprovalNote(outcome, approvalID string) string {
	switch outcome {
	case "":
		return ""
	case "malformed":
		return "rejected:malformed"
	}
	return outcome + ":" + approvalID
}

const egressReviewMsg = "[SENTINEL] Output blocked: held for review at egress (egress review cannot be approved)."

// ProcessEgress inspects model output and evaluates egress rules.
// Updates the existing PipelineResult with egress information.
func (p *Pipeline) ProcessEgress(pr *PipelineResult, responseText string) {
	meta := p.inspector.Inspect(responseText)
	result := p.egressTable.Evaluate(meta)

	pr.EgressMetadata = meta
	pr.EgressResult = &result

	if result.Action == policy.ActionDeny || result.Action == policy.ActionQuarantine {
		pr.Blocked = true
		pr.BlockedAt = "egress"
		pr.DenyMessage = result.DenyMessage
	}
	// Only ingress holds can be approved and replayed, so an egress hold must not
	// deliver the output it is holding.
	if result.Action == policy.ActionHumanReview {
		pr.Blocked = true
		pr.BlockedAt = "egress"
		pr.DenyMessage = egressReviewMsg
	}

	// Audit log
	p.auditLogger.Log(audit.Entry{
		RequestID:   pr.RequestID,
		Direction:   "egress",
		Action:      string(result.Action),
		RuleName:    result.RuleName,
		DenyMessage: result.DenyMessage,
		Metadata:    meta,
		RiskScore:   meta.RiskScore,
		TokenCount:  meta.TokenCount,
	})

	// Notify observers
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "egress",
		RequestID: pr.RequestID,
		Action:    result.Action,
		RuleName:  result.RuleName,
		Metadata:  meta,
		Blocked:   pr.Blocked && pr.BlockedAt == "egress",
		DenyMsg:   result.DenyMessage,
	})
}

// AddObserver registers a callback that will be invoked for every pipeline event.
func (p *Pipeline) AddObserver(fn EventObserver) {
	p.observerMu.Lock()
	defer p.observerMu.Unlock()
	p.observers = append(p.observers, fn)
}

// notify sends an event to all registered observers.
func (p *Pipeline) notify(event PipelineEvent) {
	p.observerMu.RLock()
	observers := p.observers
	p.observerMu.RUnlock()

	for _, fn := range observers {
		fn(event)
	}
}

// LogStreamingBlock records a DENY audit entry for a request that was blocked
// because it requested streaming after passing ingress DPI. ProcessIngress already
// wrote an ALLOW/LOG entry for this request_id; this appends the final DENY so the
// dashboard counts it as a blocked event. It also marks pr as blocked so that
// BuildResponseHeaders returns a DENY verdict with full metadata.
func (p *Pipeline) LogStreamingBlock(pr *PipelineResult) {
	const denyMsg = "[SENTINEL] Blocked: streaming requests are not permitted."

	// Mark the result as blocked so BuildResponseHeaders produces a consistent DENY
	// verdict. Overwrite IngressResult so ingress.action and ingress.rule_name in the
	// _lobstertrap response object match the top-level verdict (not the original ALLOW).
	pr.Blocked = true
	pr.BlockedAt = "ingress"
	pr.DenyMessage = denyMsg
	pr.IngressResult = &policy.RuleResult{
		Matched:     true,
		Action:      policy.ActionDeny,
		RuleName:    "streaming_blocked",
		DenyMessage: denyMsg,
	}

	var agentID string
	if pr.DeclaredHeaders != nil {
		agentID = pr.DeclaredHeaders.AgentID
	}

	var riskScore float64
	var tokenCount int
	if pr.IngressMetadata != nil {
		riskScore = pr.IngressMetadata.RiskScore
		tokenCount = pr.IngressMetadata.TokenCount
	}

	p.auditLogger.Log(audit.Entry{ //nolint:errcheck
		RequestID:       pr.RequestID,
		Direction:       "ingress",
		Action:          string(policy.ActionDeny),
		RuleName:        "streaming_blocked",
		DenyMessage:     denyMsg,
		Metadata:        pr.IngressMetadata,
		RiskScore:       riskScore,
		TokenCount:      tokenCount,
		DeclaredHeaders: pr.DeclaredHeaders,
		Mismatches:      pr.Mismatches,
		AgentID:         agentID,
	})
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "ingress",
		RequestID: pr.RequestID,
		Action:    policy.ActionDeny,
		RuleName:  "streaming_blocked",
		Metadata:  pr.IngressMetadata,
		Blocked:   true,
		DenyMsg:   denyMsg,
	})
}

// LogEgressBlock records an egress DENY for a response that was blocked outside
// the egress rule table (e.g. it could not be decoded for inspection).
func (p *Pipeline) LogEgressBlock(pr *PipelineResult, ruleName, denyMsg string) {
	pr.Blocked = true
	pr.BlockedAt = "egress"
	pr.DenyMessage = denyMsg
	pr.EgressResult = &policy.RuleResult{Matched: true, Action: policy.ActionDeny, RuleName: ruleName, DenyMessage: denyMsg}

	p.auditLogger.Log(audit.Entry{ //nolint:errcheck
		RequestID:   pr.RequestID,
		Direction:   "egress",
		Action:      string(policy.ActionDeny),
		RuleName:    ruleName,
		DenyMessage: denyMsg,
	})
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "egress",
		RequestID: pr.RequestID,
		Action:    policy.ActionDeny,
		RuleName:  ruleName,
		Blocked:   true,
		DenyMsg:   denyMsg,
	})
}

// InspectOnly runs DPI without policy evaluation (for the `inspect` command).
func (p *Pipeline) InspectOnly(text string) *inspector.PromptMetadata {
	return p.inspector.Inspect(text)
}
