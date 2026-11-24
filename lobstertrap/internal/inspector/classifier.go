package inspector

import (
	"regexp"
	"strings"
)

// IntentCategory represents a classified prompt intent.
type IntentCategory string

const (
	IntentCodeExecution    IntentCategory = "code_execution"
	IntentFileIO           IntentCategory = "file_io"
	IntentNetwork          IntentCategory = "network"
	IntentSystem           IntentCategory = "system"
	IntentCommunication    IntentCategory = "communication"
	IntentCredentialAccess IntentCategory = "credential_access"
	IntentDataAccess       IntentCategory = "data_access"
	IntentGeneral          IntentCategory = "general"
)

// ClassificationResult holds intent classification output.
type ClassificationResult struct {
	Category   IntentCategory
	Confidence float64
}

// intentRule maps keyword patterns to an intent category with a weight.
type intentRule struct {
	pattern  *regexp.Regexp
	category IntentCategory
	weight   float64
}

// Patterns run against lower-cased text (see Classify), so they carry no (?i) flag.
// Generic English words ("run", "make", "text", "message", "alert", "key", "request",
// "update", "select", "insert", and the pipeline's own "extract"/"parse"/"collect")
// only count in their security-relevant forms; as bare
// words they made ordinary LLM summaries look like a non-general intent and tripped
// human_review_mismatch.
var intentRules = []intentRule{
	// Code execution signals
	{regexp.MustCompile(`\b(execute|compile|eval|exec|invoke|spawn|subprocess|shell)\b`), IntentCodeExecution, 0.8},
	{regexp.MustCompile(`\brun\s+(\w+\s+){0,3}(scripts?|commands?|code|programs?|binar(y|ies)|files?)\b`), IntentCodeExecution, 0.8},
	{regexp.MustCompile(`\b(python|node|bash|ruby|perl|java|go\s+run|gcc|npm|pip|makefile|make\s+(install|build|all|clean|test))\b`), IntentCodeExecution, 0.7},
	{regexp.MustCompile("```(python|bash|sh|javascript|go|ruby)"), IntentCodeExecution, 0.6},

	// File I/O signals
	{regexp.MustCompile(`\b(read|write|open|create|delete|remove|copy|move|rename|mkdir|touch|cat|ls|dir)\b.*\b(file|directory|folder|path)\b`), IntentFileIO, 0.8},
	{regexp.MustCompile(`\b(read|write|open|save|load|dump|append)\s+(to|from|the)\s+(file|disk|directory)`), IntentFileIO, 0.9},
	{regexp.MustCompile(`\b(cat|head|tail|less|more|nano|vim|vi|emacs)\s+\S`), IntentFileIO, 0.7},

	// Network signals
	{regexp.MustCompile(`\b(curl|wget|fetch|http|https|download|upload|api\s+call|endpoints?|post\s+(\w+\s+){0,2}to|get\s+from|(http|api|web|network)\s+requests?)\b`), IntentNetwork, 0.8},
	{regexp.MustCompile(`\b(connect|socket|tcp|udp|dns|ping|traceroute|ssh|ftp|telnet)\b`), IntentNetwork, 0.7},
	{regexp.MustCompile(`\b(send|transmit|upload|exfiltrate|forward)\b.*\b(data|files?|info|results?)\b`), IntentNetwork, 0.7},

	// System signals
	{regexp.MustCompile(`\b(sudo|su\s|chmod|chown|mount|umount|systemctl|service|cron|kill|pkill|reboot|shutdown)\b`), IntentSystem, 0.9},
	{regexp.MustCompile(`\b(process|daemon|kernel|boot|init|grub|partition|disk)\b`), IntentSystem, 0.5},

	// Communication signals
	{regexp.MustCompile(`\b(email|e-mail|send\s+mail|smtp|notify|slack|webhook|sms|send\s+(an?\s+|the\s+)?(text|message|alert)s?)\b`), IntentCommunication, 0.8},

	// Credential access signals
	{regexp.MustCompile(`\b(password|credential|secret|token|auth|login|decrypt|crack|hash|brute|(api|secret|private|access|ssh|encryption)[\s_-]?keys?|(give|send|show|share|reveal|hand)\s+(me\s+|us\s+)?(the|your|all)\s+keys?)\b`), IntentCredentialAccess, 0.7},
	{regexp.MustCompile(`\b(\.env|passwd|shadow|keychain|vault|keyring)\b`), IntentCredentialAccess, 0.8},

	// Data access signals
	{regexp.MustCompile(`\b(database|sql|query|delete\s+from|drop\s+table|mongodb|redis|postgres|select\s+.+\s+from|insert\s+into|update\s+\w+\s+set)\b`), IntentDataAccess, 0.8},
	{regexp.MustCompile(`\b(scrape|crawl|harvest|spider)\b.*\b(data|info|pages?|sites?)\b`), IntentDataAccess, 0.6},
}

// tieBreakOrder resolves equal scores deterministically, preferring the more
// sensitive category (fail safe). Map iteration order used to decide ties randomly.
var tieBreakOrder = []IntentCategory{
	IntentCredentialAccess, IntentSystem, IntentCodeExecution, IntentNetwork,
	IntentFileIO, IntentDataAccess, IntentCommunication,
}

// Classify determines the most likely intent category for the given text.
func Classify(text string) ClassificationResult {
	lower := strings.ToLower(text)
	scores := make(map[IntentCategory]float64)

	for _, rule := range intentRules {
		if rule.pattern.MatchString(lower) {
			scores[rule.category] += rule.weight
		}
	}

	if len(scores) == 0 {
		return ClassificationResult{
			Category:   IntentGeneral,
			Confidence: 0.5,
		}
	}

	// Highest score wins; ties go to the earlier category in tieBreakOrder.
	var bestCategory IntentCategory
	var bestScore float64
	for _, cat := range tieBreakOrder {
		if score := scores[cat]; score > bestScore {
			bestScore = score
			bestCategory = cat
		}
	}

	// Normalize confidence: base on score relative to max possible
	confidence := bestScore / (bestScore + 1.0) // sigmoid-like normalization
	if confidence > 1.0 {
		confidence = 1.0
	}

	return ClassificationResult{
		Category:   bestCategory,
		Confidence: confidence,
	}
}
