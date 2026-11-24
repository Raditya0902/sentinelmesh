package cmd

import (
	"testing"

	"github.com/coal/lobstertrap/internal/policy"
)

func registryPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	pol, err := policy.Parse([]byte(`
version: "1.0"
policy_name: "serve-test"
ingress_rules:
  - name: allow_all
    priority: 1
    action: ALLOW
    conditions:
      - field: risk_score
        match_type: threshold
        value: 0.0
agents:
  critic-agent-v1:
    allowed_intents: [general]
`))
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestPipelineOptions_FailsClosedWithoutKeys(t *testing.T) {
	if _, err := pipelineOptions(registryPolicy(t), "", ""); err == nil {
		t.Fatal("expected startup error when registered agents have no keys")
	}
}

func TestPipelineOptions_RejectsMalformedKeys(t *testing.T) {
	if _, err := pipelineOptions(registryPolicy(t), "not-json", ""); err == nil {
		t.Fatal("expected error for malformed LT_AGENT_KEYS")
	}
}

func TestPipelineOptions_AcceptsFullKeySet(t *testing.T) {
	opts, err := pipelineOptions(registryPolicy(t), `{"critic-agent-v1":"critic-secret-0123456789"}`, "/tmp/decisions.jsonl")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("expected identity + approvals options, got %d", len(opts))
	}
}

func TestDefaultDecisionsPath(t *testing.T) {
	if got := defaultDecisionsPath("/app/logs/audit.jsonl"); got != "/app/logs/review_decisions.jsonl" {
		t.Errorf("got %s", got)
	}
	if got := defaultDecisionsPath(""); got != "" {
		t.Errorf("expected empty path without an audit log, got %s", got)
	}
}
