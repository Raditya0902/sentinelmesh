package policy

import (
	"strings"
	"testing"
)

const agentsPolicyYAML = `
version: "1.0"
policy_name: "agents-test"
ingress_rules:
  - name: allow_all
    priority: 1
    action: ALLOW
    conditions:
      - field: risk_score
        match_type: threshold
        value: 0.0
agents:
  extraction-agent-v1:
    allowed_intents: [data_access]
  critic-agent-v1:
    allowed_intents: [general]
`

func TestParse_AgentsSection(t *testing.T) {
	pol, err := Parse([]byte(agentsPolicyYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	spec, ok := pol.Agents["extraction-agent-v1"]
	if !ok {
		t.Fatal("expected extraction-agent-v1 in agents registry")
	}
	if !spec.AllowsIntent("data_access") {
		t.Error("expected data_access to be allowed for extraction agent")
	}
	if spec.AllowsIntent("code_execution") {
		t.Error("expected code_execution to be rejected for extraction agent")
	}
}

func TestParse_AgentWithoutIntentsRejected(t *testing.T) {
	bad := strings.Replace(agentsPolicyYAML, "allowed_intents: [general]", "allowed_intents: []", 1)
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected validation error for agent with no allowed_intents")
	}
}

func TestSentinelMeshPolicyRegistersAllAgents(t *testing.T) {
	pol, err := LoadFromFile("../../../proxy/policy.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := map[string]string{
		"extraction-agent-v1": "data_access",
		"analysis-agent-v1":   "summarize",
		"critic-agent-v1":     "general",
		"action-agent-v1":     "code_execution",
	}
	for agent, intent := range want {
		spec, ok := pol.Agents[agent]
		if !ok {
			t.Errorf("agent %s missing from proxy/policy.yaml agents section", agent)
			continue
		}
		if !spec.AllowsIntent(intent) {
			t.Errorf("agent %s should be allowed intent %s", agent, intent)
		}
	}
}
