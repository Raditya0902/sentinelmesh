package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func policyWithAction(direction, action string) string {
	return `
version: "1.0"
policy_name: "loader-test"
` + direction + `:
  - name: r1
    priority: 1
    action: ` + action + `
    conditions:
      - field: risk_score
        match_type: threshold
        value: 0.5
`
}

func TestParse_RejectsUnimplementedActions(t *testing.T) {
	for _, action := range []string{"RATE_LIMIT", "MODIFY", "REDIRECT"} {
		for _, dir := range []string{"ingress_rules", "egress_rules"} {
			_, err := Parse([]byte(policyWithAction(dir, action)))
			if err == nil {
				t.Fatalf("%s in %s: expected an error, got nil", action, dir)
			}
			if !strings.Contains(err.Error(), "not implemented") || !strings.Contains(err.Error(), action) {
				t.Errorf("%s in %s: error should name the action and say it is not implemented, got %q", action, dir, err)
			}
		}
	}
}

func TestParse_AcceptsImplementedActions(t *testing.T) {
	for _, action := range []string{"ALLOW", "DENY", "LOG", "QUARANTINE", "HUMAN_REVIEW"} {
		if _, err := Parse([]byte(policyWithAction("ingress_rules", action))); err != nil {
			t.Errorf("%s: unexpected error %v", action, err)
		}
	}
}

func TestParse_RejectsUnknownAction(t *testing.T) {
	_, err := Parse([]byte(policyWithAction("ingress_rules", "EXPLODE")))
	if err == nil || !strings.Contains(err.Error(), "invalid action") {
		t.Fatalf("expected invalid action error, got %v", err)
	}
}

func TestParse_RejectsUnimplementedDefaultAction(t *testing.T) {
	yaml := "version: \"1.0\"\npolicy_name: p\ndefault_action: REDIRECT\n"
	if _, err := Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("expected default_action REDIRECT to be rejected, got %v", err)
	}
}

func TestParse_DefaultActionIsAllow(t *testing.T) {
	pol, err := Parse([]byte("version: \"1.0\"\npolicy_name: p\n"))
	if err != nil {
		t.Fatal(err)
	}
	if pol.DefaultAction != ActionAllow {
		t.Errorf("default action = %q, want ALLOW", pol.DefaultAction)
	}
}

func TestParse_StructuralErrors(t *testing.T) {
	cases := map[string]string{
		"missing version":      "policy_name: p\n",
		"missing policy_name":  "version: \"1.0\"\n",
		"bad yaml":             "version: [unterminated\n",
		"rule without name":    "version: \"1.0\"\npolicy_name: p\ningress_rules:\n  - action: DENY\n    conditions: [{field: risk_score, match_type: threshold, value: 1}]\n",
		"rule without cond":    "version: \"1.0\"\npolicy_name: p\ningress_rules:\n  - name: r\n    action: DENY\n",
		"egress without name":  "version: \"1.0\"\npolicy_name: p\negress_rules:\n  - action: DENY\n    conditions: [{field: risk_score, match_type: threshold, value: 1}]\n",
		"egress without cond":  "version: \"1.0\"\npolicy_name: p\negress_rules:\n  - name: r\n    action: DENY\n",
		"egress bad action":    "version: \"1.0\"\npolicy_name: p\negress_rules:\n  - name: r\n    action: NOPE\n    conditions: [{field: risk_score, match_type: threshold, value: 1}]\n",
		"agent without intent": "version: \"1.0\"\npolicy_name: p\nagents:\n  a1:\n    allowed_intents: []\n",
	}
	for name, yaml := range cases {
		if _, err := Parse([]byte(yaml)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte(policyWithAction("ingress_rules", "DENY")), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.IngressRules) != 1 {
		t.Errorf("rules = %d, want 1", len(pol.IngressRules))
	}
	if _, err := LoadFromFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestBuildTables(t *testing.T) {
	pol, err := Parse([]byte(policyWithAction("egress_rules", "DENY")))
	if err != nil {
		t.Fatal(err)
	}
	ingress, egress := BuildTables(pol)
	if len(ingress.Rules) != 0 || len(egress.Rules) != 1 {
		t.Errorf("ingress=%d egress=%d, want 0/1", len(ingress.Rules), len(egress.Rules))
	}
}

func TestParse_RejectsUnenforcedRateLimitsSection(t *testing.T) {
	yaml := "version: \"1.0\"\npolicy_name: p\nrate_limits:\n  requests_per_minute: 120\n"
	_, err := Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "rate_limits") || !strings.Contains(err.Error(), "not enforced") {
		t.Fatalf("expected a clear rate_limits error, got %v", err)
	}
}

func TestParse_RejectsUnknownTopLevelKey(t *testing.T) {
	// A typo used to drop the whole rule table silently.
	yaml := "version: \"1.0\"\npolicy_name: p\ningres_rules: []\n"
	if _, err := Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "ingres_rules") {
		t.Fatalf("expected unknown-key error naming ingres_rules, got %v", err)
	}
}
