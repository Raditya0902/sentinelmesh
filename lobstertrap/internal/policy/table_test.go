package policy

import (
	"strings"
	"testing"

	"github.com/coal/lobstertrap/internal/inspector"
)

func cond(field string, mt MatchType, value any) MatchCondition {
	return MatchCondition{Field: field, MatchType: mt, Value: value}
}

func TestEvaluateCondition_MatchTypes(t *testing.T) {
	meta := &inspector.PromptMetadata{
		IntentCategory: "data_access",
		RiskScore:      0.42,
		TokenCount:     120,
		TargetPaths:    []string{"/home/u/.ssh/id_rsa", "/tmp/x"},
		TargetDomains:  []string{"pastebin.com"},
		DeclaredIntent: "summarize",
	}
	cases := []struct {
		name string
		c    MatchCondition
		want bool
	}{
		{"prefix hit", cond("intent_category", MatchPrefix, "data"), true},
		{"prefix miss", cond("intent_category", MatchPrefix, "code"), false},
		{"contains slice", cond("target_paths", MatchContains, ".ssh"), true},
		{"contains slice miss", cond("target_paths", MatchContains, ".gnupg"), false},
		{"contains string", cond("declared_intent", MatchContains, "summ"), true},
		{"regex slice", cond("target_domains", MatchRegex, `^paste`), true},
		{"regex string miss", cond("intent_category", MatchRegex, `^code_`), false},
		{"range hit", cond("risk_score", MatchRange, "0.4-0.5"), true},
		{"range miss", cond("risk_score", MatchRange, "0.5-0.9"), false},
		{"range malformed", cond("risk_score", MatchRange, "high"), false},
		{"range int field", cond("token_count", MatchRange, "100-200"), true},
		{"glob doublestar", cond("target_paths", MatchGlob, "**/.ssh/**"), true},
		{"glob string", cond("intent_category", MatchGlob, "data_*"), true},
		{"threshold string value", cond("risk_score", MatchThreshold, "0.4"), true},
		{"boolean string value", cond("has_mismatch", MatchBoolean, "false"), true},
		{"negated exact", MatchCondition{Field: "intent_category", MatchType: MatchExact, Value: "general", Negate: true}, true},
	}
	for _, tc := range cases {
		table := NewMatchActionTable([]GuardRule{{Name: "r", Action: ActionDeny, Conditions: []MatchCondition{tc.c}}}, ActionAllow)
		got := table.Evaluate(meta).Action == ActionDeny
		if got != tc.want {
			t.Errorf("%s: matched=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestToBoolAndFloatCoercions(t *testing.T) {
	if !toBool(1) || toBool(0.0) || !toBool("TRUE") || toBool(struct{}{}) {
		t.Error("toBool coercions wrong")
	}
	if toFloat64(float32(0.5)) != 0.5 || toFloat64(int64(3)) != 3 || toFloat64(nil) != 0 {
		t.Error("toFloat64 coercions wrong")
	}
}

func TestCheckNetworkPolicy(t *testing.T) {
	pol := &NetworkPolicy{
		EgressPolicy:   "allowlist",
		AllowedDomains: []string{"api.groq.com", "*.example.com"},
		DeniedDomains:  []string{"pastebin.com", "*.onion"},
	}
	cases := map[string]bool{"pastebin.com": true, "abc.onion": true, "evil.io": true, "api.groq.com": false, "docs.example.com": false}
	for domain, wantDeny := range cases {
		denied, msg := CheckNetworkPolicy(pol, []string{domain})
		if denied != wantDeny {
			t.Errorf("%s: denied=%v want %v", domain, denied, wantDeny)
		}
		if denied && !strings.HasPrefix(msg, "[SENTINEL]") {
			t.Errorf("%s: message must carry [SENTINEL] prefix: %q", domain, msg)
		}
	}
	if denied, _ := CheckNetworkPolicy(&NetworkPolicy{}, []string{"anything.io"}); denied {
		t.Error("empty network policy must not deny")
	}
}

func TestCheckFilesystemPolicy(t *testing.T) {
	pol := &FilesystemPolicy{DeniedPaths: []string{"/etc/**", "**/.ssh/**"}}
	for path, wantDeny := range map[string]bool{"/etc/passwd": true, "/home/u/.ssh/id_rsa": true, "/tmp/agent/out.txt": false} {
		if denied, _ := CheckFilesystemPolicy(pol, []string{path}); denied != wantDeny {
			t.Errorf("%s: denied=%v want %v", path, denied, wantDeny)
		}
	}
}

func ruleYAML(field, matchType, value string) string {
	return "version: \"1.0\"\npolicy_name: p\ningress_rules:\n  - name: r\n    action: DENY\n    conditions:\n" +
		"      - field: " + field + "\n        match_type: " + matchType + "\n        value: " + value + "\n"
}

// A condition that can never evaluate (unknown field/match type, bad regex) used to
// make its rule silently never match — a DENY rule that quietly does nothing.
func TestParse_RejectsConditionsThatCanNeverMatch(t *testing.T) {
	cases := map[string]string{
		"unknown match_type": ruleYAML("risk_score", "fuzzy", "0.5"),
		"unknown field":      ruleYAML("risk_scroe", "threshold", "0.5"),
		"invalid regex":      ruleYAML("intent_category", "regex", "'(unclosed'"),
	}
	for name, yaml := range cases {
		if _, err := Parse([]byte(yaml)); err == nil {
			t.Errorf("%s: expected a load error", name)
		}
	}
	if _, err := Parse([]byte(ruleYAML("intent_category", "regex", "'^data_'"))); err != nil {
		t.Errorf("valid regex rejected: %v", err)
	}
}

func TestParse_RejectsBadGlobsAndNumbers(t *testing.T) {
	base := "version: \"1.0\"\npolicy_name: p\n"
	cases := map[string]string{
		"bad denied domain":     base + "network:\n  denied_domains: [\"[evil\"]\n",
		"bad allowed domain":    base + "network:\n  allowed_domains: [\"[x\"]\n",
		"bad denied path":       base + "filesystem:\n  denied_paths: [\"/etc/[\"]\n",
		"bad glob condition":    ruleYAML("target_paths", "glob", "'/etc/['"),
		"non-numeric threshold": ruleYAML("risk_score", "threshold", "high"),
		"malformed range":       ruleYAML("risk_score", "range", "low-high"),
		"inverted range":        ruleYAML("risk_score", "range", "'0.9-0.1'"),
		"non-boolean boolean":   ruleYAML("contains_pii", "boolean", "maybe"),
	}
	for name, yaml := range cases {
		if _, err := Parse([]byte(yaml)); err == nil {
			t.Errorf("%s: expected a load error", name)
		}
	}
	for _, ok := range []string{
		ruleYAML("risk_score", "threshold", "0.8"),
		ruleYAML("risk_score", "range", "'0.3-0.7'"),
		ruleYAML("contains_pii", "boolean", "true"),
		ruleYAML("target_paths", "glob", "'/etc/**'"),
	} {
		if _, err := Parse([]byte(ok)); err != nil {
			t.Errorf("valid condition rejected: %v", err)
		}
	}
}
