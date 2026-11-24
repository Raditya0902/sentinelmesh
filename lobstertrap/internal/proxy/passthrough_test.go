package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxy_NonChatPostIsDenied(t *testing.T) {
	forwarded := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
	}))
	defer backend.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/completions", strings.NewReader(`{"prompt":"x"}`))
	rec := httptest.NewRecorder()
	newIdentityProxy(t, backend).ServeHTTP(rec, req)

	if forwarded || rec.Code != http.StatusForbidden {
		t.Fatalf("uninspected POST endpoints must be denied (code=%d forwarded=%v)", rec.Code, forwarded)
	}
}

func TestProxy_PassthroughStripsAgentHeaders(t *testing.T) {
	var seen http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		io.WriteString(w, `{"data":[]}`)
	}))
	defer backend.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set(AgentKeyHeader, criticKey)
	req.Header.Set(ReviewApprovalHeader, "req-1")
	rec := httptest.NewRecorder()
	newIdentityProxy(t, backend).ServeHTTP(rec, req)

	if seen == nil || seen.Get(AgentKeyHeader) != "" || seen.Get(ReviewApprovalHeader) != "" {
		t.Fatalf("GET passthrough must be forwarded with agent headers stripped: %v", seen)
	}
}

func TestProxy_UnparseableEgressFailsClosed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// content as an array of parts does not match the parser's string field
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":[{"type":"text","text":"SSN 123-45-6789"}]}}]}`)
	}))
	defer backend.Close()

	rec := postChat(t, newEgressProxy(t, backend))

	if !strings.Contains(rec.Body.String(), "[SENTINEL]") || bytes.Contains(rec.Body.Bytes(), []byte("123-45-6789")) {
		t.Fatalf("an unparseable backend response must be denied, got %q", rec.Body.String())
	}
}
