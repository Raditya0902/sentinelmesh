package pipeline

import (
	"crypto/subtle"
	"fmt"
	"sort"

	"github.com/coal/lobstertrap/internal/policy"
)

// MinAgentKeyLength is the shortest agent key accepted at startup.
const MinAgentKeyLength = 16

const (
	ruleAgentIdentityMissing = "agent_identity_missing"
	// One rule and message for unknown agent_id and wrong key, so callers cannot
	// enumerate which agent IDs are registered.
	ruleAgentAuthFailed    = "agent_auth_failed"
	ruleAgentIntentSpoofed = "agent_intent_spoofed"
	maxAuditedAgentIDChars = 64
)

// ValidateAgentKeys checks that every agent registered in the policy has a key of
// adequate length. `serve` refuses to start when this fails (fail closed).
func ValidateAgentKeys(pol *policy.Policy, keys map[string]string) error {
	ids := make([]string, 0, len(pol.Agents))
	for id := range pol.Agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	owners := make(map[string]string, len(keys))
	for _, id := range ids {
		key, ok := keys[id]
		if !ok {
			return fmt.Errorf("no agent key configured for registered agent %q", id)
		}
		if len(key) < MinAgentKeyLength {
			return fmt.Errorf("agent key for %q must be at least %d characters", id, MinAgentKeyLength)
		}
		if other, dup := owners[key]; dup {
			return fmt.Errorf("agents %q and %q share a key; each agent needs its own", other, id)
		}
		owners[key] = id
	}
	return nil
}

func identityDeny(rule, msg string) *policy.RuleResult {
	return &policy.RuleResult{
		Matched:     true,
		RuleName:    rule,
		Action:      policy.ActionDeny,
		DenyMessage: "[SENTINEL] Blocked: " + msg,
	}
}

// truncateAgentID bounds attacker-controlled agent IDs before they reach the audit log.
func truncateAgentID(id string) string {
	if len(id) > maxAuditedAgentIDChars {
		return id[:maxAuditedAgentIDChars]
	}
	return id
}

// keysEqual compares in constant time with respect to the key contents.
func keysEqual(presented, expected string) bool {
	if presented == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

// checkAgentIdentity returns a DENY result when the caller's identity claim cannot
// be trusted, or nil when the agent is authenticated and its declared intent is one
// it is registered for. It is a no-op when identity binding is disabled.
func (p *Pipeline) checkAgentIdentity(req IngressRequest) *policy.RuleResult {
	if p.agentKeys == nil {
		return nil
	}
	if p.lockedOut(req) {
		return authRateLimitedDeny()
	}
	declared := req.Declared
	if declared == nil || declared.AgentID == "" {
		return identityDeny(ruleAgentIdentityMissing, "agent identity missing.")
	}
	spec, registered := p.pol.Agents[declared.AgentID]
	if !registered || !keysEqual(req.AgentKey, p.agentKeys[declared.AgentID]) {
		p.authFailures.recordFailure(p.lockoutKey(req))
		return identityDeny(ruleAgentAuthFailed, "agent authentication failed.")
	}
	if !spec.AllowsIntent(declared.DeclaredIntent) {
		return identityDeny(ruleAgentIntentSpoofed, "declared intent is not permitted for this agent.")
	}
	return nil
}
