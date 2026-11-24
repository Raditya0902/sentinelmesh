package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

// agentKeysEnv holds a JSON object mapping agent_id → secret key.
const agentKeysEnv = "LT_AGENT_KEYS"

// approvalMaxAge bounds how long after an admin's decision the replay may use it.
const approvalMaxAge = 15 * time.Minute

// parseAgentKeys parses the LT_AGENT_KEYS JSON object. Empty input yields no keys.
func parseAgentKeys(raw string) (map[string]string, error) {
	if raw == "" {
		return map[string]string{}, nil
	}
	var keys map[string]string
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, fmt.Errorf("%s must be a JSON object of {\"<agent_id>\": \"<key>\"}: %w", agentKeysEnv, err)
	}
	return keys, nil
}

// pipelineOptions builds the enforcement options for `serve`. When the policy
// registers agents, every one of them must have a key or startup fails (fail closed).
func pipelineOptions(pol *policy.Policy, rawAgentKeys, decisionsPath string) ([]pipeline.Option, error) {
	var opts []pipeline.Option
	if len(pol.Agents) > 0 {
		keys, err := parseAgentKeys(rawAgentKeys)
		if err != nil {
			return nil, err
		}
		if err := pipeline.ValidateAgentKeys(pol, keys); err != nil {
			return nil, fmt.Errorf("%w (set %s; `make keys` generates a full set)", err, agentKeysEnv)
		}
		opts = append(opts, pipeline.WithAgentIdentity(keys))
	}
	if decisionsPath != "" {
		opts = append(opts, pipeline.WithReviewApprovals(pipeline.FileReviewApprovals{Path: decisionsPath, MaxAge: approvalMaxAge}))
	}
	return opts, nil
}

// defaultDecisionsPath puts review_decisions.jsonl next to the audit log, which is
// where the SentinelMesh API writes it.
func defaultDecisionsPath(auditPath string) string {
	if auditPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(auditPath), "review_decisions.jsonl")
}

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 60 * time.Second
	// The response waits on the LLM backend; keep this well above model latency.
	writeTimeout = 5 * time.Minute
	idleTimeout  = 2 * time.Minute
)

// newHTTPServer bounds how long a client may take to send a request, so slow or
// stalled connections (slowloris) cannot pin proxy goroutines indefinitely.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}
