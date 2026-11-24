package pipeline

import (
	"testing"

	"github.com/coal/lobstertrap/internal/audit"
	"github.com/coal/lobstertrap/internal/metadata"
	"github.com/coal/lobstertrap/internal/policy"
)

const identityPolicyYAML = `
version: "1.0"
policy_name: "identity-test"
default_action: ALLOW
ingress_rules:
  - name: block_prompt_injection
    priority: 100
    action: DENY
    deny_message: "[SENTINEL] Blocked: prompt injection detected."
    conditions:
      - field: contains_injection_patterns
        match_type: boolean
        value: true
  - name: review_urls
    priority: 50
    action: HUMAN_REVIEW
    conditions:
      - field: contains_urls
        match_type: boolean
        value: true
agents:
  extraction-agent-v1:
    allowed_intents: [data_access]
  critic-agent-v1:
    allowed_intents: [general]
`

var testAgentKeys = map[string]string{
	"extraction-agent-v1": "extraction-secret-0123456789",
	"critic-agent-v1":     "critic-secret-0123456789abc",
}

func loadInlinePolicy(t *testing.T, src string) *policy.Policy {
	t.Helper()
	pol, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse inline policy: %v", err)
	}
	return pol
}

func newIdentityPipeline(t *testing.T) *Pipeline {
	t.Helper()
	return New(loadInlinePolicy(t, identityPolicyYAML), audit.NopLogger(), WithAgentIdentity(testAgentKeys))
}

func ingress(agentID, intent, key, prompt string) IngressRequest {
	return IngressRequest{
		Prompt:   prompt,
		Declared: &metadata.RequestHeaders{AgentID: agentID, DeclaredIntent: intent},
		AgentKey: key,
	}
}

func assertDeny(t *testing.T, res *PipelineResult, rule string) {
	t.Helper()
	if !res.Blocked || res.IngressResult.Action != policy.ActionDeny {
		t.Fatalf("expected DENY, got %s (blocked=%v)", res.IngressResult.Action, res.Blocked)
	}
	if res.IngressResult.RuleName != rule {
		t.Errorf("expected rule %s, got %s", rule, res.IngressResult.RuleName)
	}
	if res.DenyMessage == "" || res.DenyMessage[:10] != "[SENTINEL]" {
		t.Errorf("deny message must carry [SENTINEL] prefix, got %q", res.DenyMessage)
	}
}

func TestIdentity_ValidKeyAndIntentAllowed(t *testing.T) {
	pipe := newIdentityPipeline(t)
	res := pipe.ProcessIngressRequest(ingress("critic-agent-v1", "general", testAgentKeys["critic-agent-v1"], "Review this summary."))
	if res.Blocked || res.IngressResult.Action != policy.ActionAllow {
		t.Fatalf("expected ALLOW, got %s rule=%s", res.IngressResult.Action, res.IngressResult.RuleName)
	}
}

func TestIdentity_MissingDeclaredHeadersDenied(t *testing.T) {
	pipe := newIdentityPipeline(t)
	res := pipe.ProcessIngressRequest(IngressRequest{Prompt: "hello"})
	assertDeny(t, res, "agent_identity_missing")
}

func TestIdentity_UnknownAgentDenied(t *testing.T) {
	pipe := newIdentityPipeline(t)
	res := pipe.ProcessIngressRequest(ingress("rogue-agent", "general", "whatever-key-0123456789", "hello"))
	assertDeny(t, res, "agent_auth_failed")
}

func TestIdentity_MismatchedKeyDenied(t *testing.T) {
	pipe := newIdentityPipeline(t)
	// The critic's key presented while claiming to be the extraction agent.
	res := pipe.ProcessIngressRequest(ingress("extraction-agent-v1", "data_access", testAgentKeys["critic-agent-v1"], "Extract fields."))
	assertDeny(t, res, "agent_auth_failed")
}

func TestIdentity_MissingKeyDenied(t *testing.T) {
	pipe := newIdentityPipeline(t)
	res := pipe.ProcessIngressRequest(ingress("extraction-agent-v1", "data_access", "", "Extract fields."))
	assertDeny(t, res, "agent_auth_failed")
}

func TestIdentity_SpoofedIntentDenied(t *testing.T) {
	pipe := newIdentityPipeline(t)
	// Valid critic credentials, but the critic is only registered for "general".
	res := pipe.ProcessIngressRequest(ingress("critic-agent-v1", "data_access", testAgentKeys["critic-agent-v1"], "Review this."))
	assertDeny(t, res, "agent_intent_spoofed")
}

func TestIdentity_RecordsAgentInAuditEvenWhenDenied(t *testing.T) {
	pipe := newIdentityPipeline(t)
	res := pipe.ProcessIngressRequest(ingress("critic-agent-v1", "data_access", "bad-key-000000000000", "Review."))
	if res.IngressMetadata == nil {
		t.Fatal("DPI metadata must still be populated for denied identity checks")
	}
}

func TestIdentity_NotEnforcedWithoutOption(t *testing.T) {
	pipe := New(loadInlinePolicy(t, identityPolicyYAML), audit.NopLogger())
	res := pipe.ProcessIngress("hello there", nil)
	if res.Blocked {
		t.Fatalf("identity must not be enforced when WithAgentIdentity is not set, got rule %s", res.IngressResult.RuleName)
	}
}

func TestValidateAgentKeys(t *testing.T) {
	pol := loadInlinePolicy(t, identityPolicyYAML)
	if err := ValidateAgentKeys(pol, testAgentKeys); err != nil {
		t.Fatalf("expected full key set to validate: %v", err)
	}
	if err := ValidateAgentKeys(pol, map[string]string{"critic-agent-v1": testAgentKeys["critic-agent-v1"]}); err == nil {
		t.Fatal("expected error when a registered agent has no key")
	}
	short := map[string]string{"extraction-agent-v1": "short", "critic-agent-v1": testAgentKeys["critic-agent-v1"]}
	if err := ValidateAgentKeys(pol, short); err == nil {
		t.Fatal("expected error for a key shorter than the minimum length")
	}
}
