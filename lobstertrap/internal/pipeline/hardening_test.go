package pipeline

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coal/lobstertrap/internal/audit"
	"github.com/coal/lobstertrap/internal/policy"
)

func TestRequestIDsAreUniqueAcrossPipelines(t *testing.T) {
	a := newIdentityPipeline(t).ProcessIngress("hello", nil)
	b := newIdentityPipeline(t).ProcessIngress("hello", nil)
	if !regexp.MustCompile(`^req-[0-9a-f]{8}-\d+$`).MatchString(a.RequestID) {
		t.Fatalf("request ID %q should carry a per-boot nonce", a.RequestID)
	}
	if a.RequestID == b.RequestID {
		t.Fatal("request IDs must not collide")
	}
}

func TestIdentity_UnknownAgentAndBadKeyLookIdentical(t *testing.T) {
	pipe := newIdentityPipeline(t)
	unknown := pipe.ProcessIngressRequest(ingress("rogue-agent", "general", "k-0000000000000000", "hi"))
	badKey := pipe.ProcessIngressRequest(ingress("critic-agent-v1", "general", "k-0000000000000000", "hi"))
	if unknown.IngressResult.RuleName != badKey.IngressResult.RuleName ||
		unknown.DenyMessage != badKey.DenyMessage {
		t.Fatalf("unknown agent and bad key must be indistinguishable to callers: %q/%q vs %q/%q",
			unknown.IngressResult.RuleName, unknown.DenyMessage, badKey.IngressResult.RuleName, badKey.DenyMessage)
	}
}

func TestValidateAgentKeys_RejectsDuplicateKeys(t *testing.T) {
	pol := loadInlinePolicy(t, identityPolicyYAML)
	dup := map[string]string{
		"extraction-agent-v1": "same-secret-0123456789",
		"critic-agent-v1":     "same-secret-0123456789",
	}
	if err := ValidateAgentKeys(pol, dup); err == nil {
		t.Fatal("two agents sharing a key must be rejected")
	}
}

func TestReview_ApprovalBoundToFullRequestBody(t *testing.T) {
	approvals := fakeApprovals{}
	pipe := newReviewPipeline(t, approvals)
	req := criticRequest(reviewPrompt, "")
	req.Body = []byte(`{"model":"small","messages":[]}`)
	first := pipe.ProcessIngressRequest(req)
	approvals[first.RequestID] = true

	replay := criticRequest(reviewPrompt, first.RequestID)
	replay.Body = []byte(`{"model":"small","messages":[],"tools":[{"type":"function"}]}`)
	if !pipe.ProcessIngressRequest(replay).NeedsHumanReview() {
		t.Fatal("an approval must not transfer to a request with different non-message fields")
	}
}

func TestReview_MalformedApprovalHeaderIgnored(t *testing.T) {
	pipe := newReviewPipeline(t, fakeApprovals{})
	res := pipe.ProcessIngressRequest(criticRequest(reviewPrompt, strings.Repeat("A", 500)))
	if !res.NeedsHumanReview() {
		t.Fatal("malformed approval reference must not release anything")
	}
}

func TestEgressHumanReviewBlocks(t *testing.T) {
	pol := loadInlinePolicy(t, `
version: "1.0"
policy_name: "egress-hr"
default_action: ALLOW
ingress_rules:
  - name: allow_all
    priority: 1
    action: ALLOW
    conditions:
      - field: risk_score
        match_type: threshold
        value: 0.0
egress_rules:
  - name: review_urls
    priority: 10
    action: HUMAN_REVIEW
    conditions:
      - field: contains_urls
        match_type: boolean
        value: true
`)
	pipe := New(pol, audit.NopLogger())
	res := pipe.ProcessIngress("hello", nil)
	pipe.ProcessEgress(res, "See https://example.com/data")
	if !res.Blocked || res.BlockedAt != "egress" || !strings.HasPrefix(res.DenyMessage, "[SENTINEL]") {
		t.Fatalf("egress HUMAN_REVIEW cannot be approved, so it must block: blocked=%v at=%s msg=%q",
			res.Blocked, res.BlockedAt, res.DenyMessage)
	}
	if res.EgressResult.Action != policy.ActionHumanReview {
		t.Errorf("audit should still record the HUMAN_REVIEW action, got %s", res.EgressResult.Action)
	}
}

func TestFileReviewApprovals_FirstDecisionWins(t *testing.T) {
	since := time.Now().Add(-time.Minute).UTC()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	path := writeDecisions(t,
		`{"request_id":"req-1","decision":"reject","decided_at":"`+ts+`"}`,
		`{"request_id":"req-1","decision":"approve","decided_at":"`+ts+`"}`,
	)
	if (FileReviewApprovals{Path: path}).IsApproved("req-1", since) {
		t.Fatal("decisions are write-once: a later approve must not flip an earlier reject")
	}
}

func TestFileReviewApprovals_ApprovalExpires(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour).UTC()
	path := writeDecisions(t,
		`{"request_id":"req-1","decision":"approve","decided_at":"`+old.Add(time.Minute).Format(time.RFC3339Nano)+`"}`)
	approvals := FileReviewApprovals{Path: path, MaxAge: 15 * time.Minute}
	if approvals.IsApproved("req-1", old) {
		t.Fatal("an approval older than MaxAge must not release the request")
	}
}
