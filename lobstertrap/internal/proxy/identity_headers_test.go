package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/coal/lobstertrap/internal/audit"
	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

const proxyIdentityPolicy = `
version: "1.0"
policy_name: "proxy-identity-test"
default_action: ALLOW
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
`

const criticKey = "critic-secret-0123456789abc"

func newIdentityProxy(t *testing.T, backend *httptest.Server) *GuardProxy {
	t.Helper()
	pol, err := policy.Parse([]byte(proxyIdentityPolicy))
	if err != nil {
		t.Fatal(err)
	}
	pipe := pipeline.New(pol, audit.NopLogger(),
		pipeline.WithAgentIdentity(map[string]string{"critic-agent-v1": criticKey}))
	gp, err := New(pipe, backend.URL, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	return gp
}

func chatBody(t *testing.T, intent string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":    "test",
		"messages": []map[string]string{{"role": "user", "content": "Review this summary."}},
		"_lobstertrap": map[string]string{
			"agent_id":        "critic-agent-v1",
			"declared_intent": intent,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

const backendReply = `{"id":"x","model":"test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`

func TestProxy_StripsAgentSecretsBeforeForwarding(t *testing.T) {
	var seen http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		io.WriteString(w, backendReply)
	}))
	defer backend.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, "general")))
	req.Header.Set(AgentKeyHeader, criticKey)
	req.Header.Set(ReviewApprovalHeader, "req-1")
	rec := httptest.NewRecorder()
	newIdentityProxy(t, backend).ServeHTTP(rec, req)

	if seen == nil {
		t.Fatalf("expected request to be forwarded; got body %s", rec.Body.String())
	}
	if seen.Get(AgentKeyHeader) != "" || seen.Get(ReviewApprovalHeader) != "" {
		t.Fatalf("agent key / review approval headers leaked to backend: %v", seen)
	}
}

func TestProxy_DeniesWrongAgentKeyWithoutForwarding(t *testing.T) {
	forwarded := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		io.WriteString(w, backendReply)
	}))
	defer backend.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, "general")))
	req.Header.Set(AgentKeyHeader, "wrong-key-000000000000")
	rec := httptest.NewRecorder()
	newIdentityProxy(t, backend).ServeHTTP(rec, req)

	if forwarded {
		t.Fatal("request with a forged agent key must not reach the backend")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("[SENTINEL] Blocked: agent authentication failed")) {
		t.Fatalf("expected [SENTINEL] agent key deny message, got %s", rec.Body.String())
	}
}
