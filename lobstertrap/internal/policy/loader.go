package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/coal/lobstertrap/internal/inspector"
)

// LoadFromFile loads a policy from a YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return Parse(data)
}

// Parse parses YAML bytes into a Policy.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Unknown keys are errors: a typo (e.g. "ingres_rules") used to drop a whole
	// rule table silently.
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		if strings.Contains(err.Error(), "field rate_limits not found") {
			return nil, fmt.Errorf("parsing policy YAML: rate_limits is not enforced by the proxy; remove it " +
				"(callers are rate limited per API key in the SentinelMesh API, failed agent auth per IP here)")
		}
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if err := validate(&p); err != nil {
		return nil, fmt.Errorf("validating policy: %w", err)
	}
	return &p, nil
}

// implementedActions have runtime behaviour in the pipeline. Anything else is
// rejected at load time so a policy can never silently degrade to ALLOW.
var implementedActions = map[Action]bool{
	ActionAllow: true, ActionDeny: true, ActionLog: true,
	ActionQuarantine: true, ActionHumanReview: true,
}

// unimplementedActions are names from the original design that never got runtime
// behaviour; they get a specific error so the policy author knows why.
var unimplementedActions = map[Action]bool{
	"RATE_LIMIT": true, "MODIFY": true, "REDIRECT": true,
}

func checkAction(a Action) error {
	if implementedActions[a] {
		return nil
	}
	if unimplementedActions[a] {
		return fmt.Errorf("action %q is not implemented (use one of ALLOW, DENY, LOG, QUARANTINE, HUMAN_REVIEW)", a)
	}
	return fmt.Errorf("invalid action %q", a)
}

var knownMatchTypes = map[MatchType]bool{
	MatchExact: true, MatchPrefix: true, MatchGlob: true, MatchRegex: true,
	MatchRange: true, MatchContains: true, MatchBoolean: true, MatchThreshold: true,
}

// checkConditions rejects conditions that could never evaluate. They used to make
// their rule silently never match, so a misspelled DENY rule did nothing.
func checkConditions(conds []MatchCondition) error {
	probe := &inspector.PromptMetadata{}
	for _, c := range conds {
		if getFieldValue(c.Field, probe) == nil {
			return fmt.Errorf("unknown field %q", c.Field)
		}
		if !knownMatchTypes[c.MatchType] {
			return fmt.Errorf("field %q: unknown match_type %q", c.Field, c.MatchType)
		}
		if err := checkValue(c); err != nil {
			return fmt.Errorf("field %q: %w", c.Field, err)
		}
	}
	return nil
}

// checkValue rejects values a match type would silently mis-evaluate: a bad regex or
// glob never matches, a non-numeric threshold becomes 0 (always matches), and a
// malformed range never matches.
func checkValue(c MatchCondition) error {
	raw := fmt.Sprintf("%v", c.Value)
	switch c.MatchType {
	case MatchRegex:
		if _, err := regexp.Compile(raw); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	case MatchGlob:
		return checkGlob(raw)
	case MatchThreshold:
		if _, err := strconv.ParseFloat(raw, 64); err != nil {
			return fmt.Errorf("threshold value %q is not a number", raw)
		}
	case MatchRange:
		return checkRange(raw)
	case MatchBoolean:
		if _, err := strconv.ParseBool(raw); err != nil {
			return fmt.Errorf("boolean value %q is not true/false", raw)
		}
	}
	return nil
}

func checkRange(raw string) error {
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("range %q must be \"min-max\"", raw)
	}
	lo, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	hi, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err1 != nil || err2 != nil || lo > hi {
		return fmt.Errorf("range %q must be \"min-max\" with numeric min <= max", raw)
	}
	return nil
}

// checkGlob validates each path segment the way matchParts / filepath.Match use it.
func checkGlob(pattern string) error {
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "**" {
			continue
		}
		if _, err := filepath.Match(segment, ""); err != nil {
			return fmt.Errorf("invalid glob %q: %w", pattern, err)
		}
	}
	return nil
}

func checkGlobs(section string, patterns []string) error {
	for _, p := range patterns {
		if err := checkGlob(p); err != nil {
			return fmt.Errorf("%s: %w", section, err)
		}
	}
	return nil
}

func checkRules(direction string, rules []GuardRule) error {
	for i, rule := range rules {
		if rule.Name == "" {
			return fmt.Errorf("%s rule %d: name is required", direction, i)
		}
		if err := checkAction(rule.Action); err != nil {
			return fmt.Errorf("%s rule %q: %w", direction, rule.Name, err)
		}
		if len(rule.Conditions) == 0 {
			return fmt.Errorf("%s rule %q: at least one condition is required", direction, rule.Name)
		}
		if err := checkConditions(rule.Conditions); err != nil {
			return fmt.Errorf("%s rule %q: %w", direction, rule.Name, err)
		}
	}
	return nil
}

// validate checks policy integrity.
func validate(p *Policy) error {
	if p.Version == "" {
		return fmt.Errorf("policy version is required")
	}
	if p.PolicyName == "" {
		return fmt.Errorf("policy_name is required")
	}
	if p.DefaultAction == "" {
		p.DefaultAction = ActionAllow
	}
	if err := checkAction(p.DefaultAction); err != nil {
		return fmt.Errorf("default_action: %w", err)
	}

	if err := checkRules("ingress", p.IngressRules); err != nil {
		return err
	}
	if err := checkRules("egress", p.EgressRules); err != nil {
		return err
	}
	for section, patterns := range map[string][]string{
		"network.denied_domains":  p.Network.DeniedDomains,
		"network.allowed_domains": p.Network.AllowedDomains,
		"filesystem.denied_paths": p.Filesystem.DeniedPaths,
	} {
		if err := checkGlobs(section, patterns); err != nil {
			return err
		}
	}

	for agentID, spec := range p.Agents {
		if agentID == "" {
			return fmt.Errorf("agents: agent_id must not be empty")
		}
		if len(spec.AllowedIntents) == 0 {
			return fmt.Errorf("agent %q: at least one allowed_intent is required", agentID)
		}
	}

	return nil
}

// BuildTables creates ingress and egress MatchActionTables from the policy.
func BuildTables(p *Policy) (ingress *MatchActionTable, egress *MatchActionTable) {
	ingress = NewMatchActionTable(p.IngressRules, p.DefaultAction)
	egress = NewMatchActionTable(p.EgressRules, p.DefaultAction)
	return
}
