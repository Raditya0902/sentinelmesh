package pipeline

import (
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

// EventObserver is a callback function that receives pipeline events.
// direction is "ingress" or "egress".
type EventObserver func(event PipelineEvent)

// PipelineEvent represents a single pipeline event for observers.
type PipelineEvent struct {
	Timestamp time.Time                `json:"timestamp"`
	Direction string                   `json:"direction"`
	RequestID string                   `json:"request_id"`
	Action    policy.Action            `json:"action"`
	RuleName  string                   `json:"rule_name,omitempty"`
	Metadata  *inspector.PromptMetadata `json:"metadata"`
	Blocked   bool                     `json:"blocked"`
	DenyMsg   string                   `json:"deny_message,omitempty"`
}

// Pipeline runs the ingress → inference → egress inspection flow.
type Pipeline struct {
	inspector    *inspector.Inspector
	ingressTable *policy.MatchActionTable
	egressTable  *policy.MatchActionTable
	pol          *policy.Policy
	auditLogger  *audit.Logger

	observerMu sync.RWMutex
	observers  []EventObserver
}

// New creates a new Pipeline from a loaded policy.
func New(pol *policy.Policy, auditLogger *audit.Logger) *Pipeline {
	ingress, egress := policy.BuildTables(pol)
	return &Pipeline{
		inspector:    inspector.New(),
		ingressTable: ingress,
		egressTable:  egress,
		pol:          pol,
		auditLogger:  auditLogger,
	}
}

// ProcessIngress inspects a prompt and evaluates ingress rules.
// declared may be nil if the agent didn't send _lobstertrap headers.
func (p *Pipeline) ProcessIngress(promptText string, declared *metadata.RequestHeaders) *PipelineResult {
	reqID := fmt.Sprintf("req-%d", requestCounter.Add(1))

	meta := p.inspector.Inspect(promptText)

	// Enrich metadata with declared headers before policy evaluation so rules
	// can match on has_mismatch and declared_intent.
	if declared != nil {
		meta.DeclaredIntent = declared.DeclaredIntent
		meta.HasMismatch = declared.DeclaredIntent != "" &&
			declared.DeclaredIntent != meta.IntentCategory
	}

	result := p.ingressTable.Evaluate(meta)

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

	// Extract agent ID for audit logging
	var agentID string
	if declared != nil {
		agentID = declared.AgentID
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
		DeclaredHeaders: declared,
		Mismatches:      mismatches,
		AgentID:         agentID,
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

// InspectOnly runs DPI without policy evaluation (for the `inspect` command).
func (p *Pipeline) InspectOnly(text string) *inspector.PromptMetadata {
	return p.inspector.Inspect(text)
}
