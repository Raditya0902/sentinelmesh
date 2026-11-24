package inspector

import (
	"strings"
	"sync"
)

// PromptMetadata holds all extracted metadata from a prompt or response text.
type PromptMetadata struct {
	IntentCategory            string   `json:"intent_category"`
	IntentConfidence          float64  `json:"intent_confidence"`
	RiskScore                 float64  `json:"risk_score"`
	DeclaredIntent            string   `json:"declared_intent,omitempty"`
	HasMismatch               bool     `json:"has_mismatch"`
	ContainsCode              bool     `json:"contains_code"`
	ContainsCredentials       bool     `json:"contains_credentials"`
	ContainsPII               bool     `json:"contains_pii"`
	ContainsPIIRequest        bool     `json:"contains_pii_request"`
	ContainsSystemCommands    bool     `json:"contains_system_commands"`
	ContainsMalwareRequest    bool     `json:"contains_malware_request"`
	ContainsPhishingPatterns  bool     `json:"contains_phishing_patterns"`
	ContainsRoleImpersonation bool     `json:"contains_role_impersonation"`
	ContainsExfiltration      bool     `json:"contains_exfiltration"`
	ContainsHarmPatterns      bool     `json:"contains_harm_patterns"`
	ContainsObfuscation       bool     `json:"contains_obfuscation"`
	ContainsInjectionPatterns bool     `json:"contains_injection_patterns"`
	ContainsFilePaths         bool     `json:"contains_file_paths"`
	ContainsSensitivePaths    bool     `json:"contains_sensitive_paths"`
	ContainsURLs              bool     `json:"contains_urls"`
	TargetPaths               []string `json:"target_paths"`
	TargetDomains             []string `json:"target_domains"`
	TargetCommands            []string `json:"target_commands"`
	TokenCount                int      `json:"token_count"`
}

// Inspector is the DPI engine. It extracts structured metadata from text
// using compiled regex patterns — no LLM call involved.
type Inspector struct{}

// New creates a new Inspector.
func New() *Inspector {
	return &Inspector{}
}

// scan runs one regex job per goroutine and waits for all of them. Each job writes
// only its own variable, so no locking is needed. The pattern sets are independent
// full-text scans (Go's regexp is linear in input length), so running them
// concurrently cuts wall-clock latency roughly by the number of cores; total CPU
// per request is unchanged.
//
// A panic in a job is re-raised on the caller's goroutine once all jobs finish, so
// net/http's per-request recovery still applies (the request fails, nothing is
// forwarded) instead of the whole proxy crashing.
func scan(jobs ...func()) {
	var (
		wg       sync.WaitGroup
		once     sync.Once
		panicked any
	)
	wg.Add(len(jobs))
	for _, job := range jobs {
		go func(job func()) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					once.Do(func() { panicked = r })
				}
			}()
			job()
		}(job)
	}
	wg.Wait()
	if panicked != nil {
		panic(panicked)
	}
}

// Inspect extracts metadata from the given text.
func (ins *Inspector) Inspect(text string) *PromptMetadata {
	meta := &PromptMetadata{}
	var (
		hasSensitivePaths bool
		classification    ClassificationResult
	)
	matchInto := func(dst *bool, ps *PatternSet) func() {
		return func() { *dst = ps.MatchAny(text) }
	}

	scan(
		matchInto(&meta.ContainsCredentials, &CredentialPatterns),
		matchInto(&meta.ContainsPII, &PIIPatterns),
		matchInto(&meta.ContainsPIIRequest, &PIIRequestPatterns),
		matchInto(&meta.ContainsMalwareRequest, &MalwareRequestPatterns),
		matchInto(&meta.ContainsPhishingPatterns, &PhishingPatterns),
		matchInto(&meta.ContainsRoleImpersonation, &RoleImpersonationPatterns),
		matchInto(&meta.ContainsExfiltration, &ExfiltrationPatterns),
		matchInto(&meta.ContainsHarmPatterns, &HarmPatterns),
		matchInto(&meta.ContainsObfuscation, &ObfuscationPatterns),
		matchInto(&meta.ContainsInjectionPatterns, &InjectionPatterns),
		matchInto(&meta.ContainsSystemCommands, &ShellCommandPatterns),
		matchInto(&meta.ContainsCode, &CodePatterns),
		matchInto(&meta.ContainsURLs, &URLPatterns),
		matchInto(&hasSensitivePaths, &SensitivePathPatterns),
		func() { meta.TargetPaths = FilePathPatterns.FindAll(text) },
		func() { meta.TargetCommands = CommandExtractPatterns.FindAll(text) },
		func() { classification = Classify(text) },
	)

	meta.ContainsFilePaths = len(meta.TargetPaths) > 0
	meta.ContainsSensitivePaths = hasSensitivePaths

	// Extract domains from URLs
	if matches := DomainExtractPattern.FindAllStringSubmatch(text, -1); len(matches) > 0 {
		seen := make(map[string]struct{})
		for _, m := range matches {
			if len(m) > 1 {
				domain := strings.ToLower(m[1])
				if _, ok := seen[domain]; !ok {
					seen[domain] = struct{}{}
					meta.TargetDomains = append(meta.TargetDomains, domain)
				}
			}
		}
	}

	meta.IntentCategory = string(classification.Category)
	meta.IntentConfidence = classification.Confidence

	// Compute risk score
	meta.RiskScore = ComputeRisk(RiskSignals{
		ContainsCredentials:       meta.ContainsCredentials,
		ContainsPII:               meta.ContainsPII,
		ContainsPIIRequest:        meta.ContainsPIIRequest,
		ContainsMalwareRequest:    meta.ContainsMalwareRequest,
		ContainsPhishingPatterns:  meta.ContainsPhishingPatterns,
		ContainsRoleImpersonation: meta.ContainsRoleImpersonation,
		ContainsExfiltration:      meta.ContainsExfiltration,
		ContainsHarmPatterns:      meta.ContainsHarmPatterns,
		ContainsObfuscation:       meta.ContainsObfuscation,
		ContainsInjectionPatterns: meta.ContainsInjectionPatterns,
		ContainsSystemCommands:    meta.ContainsSystemCommands,
		ContainsFilePaths:         meta.ContainsFilePaths,
		ContainsURLs:              meta.ContainsURLs,
		ContainsCode:              meta.ContainsCode,
		HasSensitivePaths:         hasSensitivePaths,
		Intent:                    classification.Category,
		IntentConfidence:          classification.Confidence,
	})

	// Rough token estimate (~4 chars per token)
	meta.TokenCount = estimateTokens(text)

	return meta
}

// estimateTokens gives a rough token count (~4 chars per token for English).
func estimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	// Rough heuristic: ~4 characters per token
	tokens := len(text) / 4
	if tokens == 0 {
		tokens = 1
	}
	return tokens
}
