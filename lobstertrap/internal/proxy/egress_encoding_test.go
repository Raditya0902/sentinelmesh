package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/coal/lobstertrap/internal/audit"
	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

const egressPolicy = `
version: "1.0"
policy_name: "egress-encoding-test"
default_action: ALLOW
ingress_rules:
  - name: allow_all
    priority: 1
    action: ALLOW
    conditions:
      - field: risk_score
        match_type: threshold
        value: 0.0
egress_rules:
  - name: block_pii_exfiltration
    priority: 100
    action: DENY
    deny_message: "[SENTINEL] Output blocked: contains PII."
    conditions:
      - field: contains_pii
        match_type: boolean
        value: true
`

const piiReply = `{"id":"x","model":"test","choices":[{"index":0,"message":{"role":"assistant","content":"The SSN is 123-45-6789."}}]}`

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	io.WriteString(zw, s)
	zw.Close()
	return buf.Bytes()
}

func newEgressProxy(t *testing.T, backend *httptest.Server) *GuardProxy {
	t.Helper()
	pol, err := policy.Parse([]byte(egressPolicy))
	if err != nil {
		t.Fatal(err)
	}
	gp, err := New(pipeline.New(pol, audit.NopLogger()), backend.URL, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	return gp
}

func postChat(t *testing.T, gp *GuardProxy) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"test","messages":[{"role":"user","content":"What is on file?"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Accept-Encoding", "gzip, deflate") // what httpx/OpenAI SDK send
	rec := httptest.NewRecorder()
	gp.ServeHTTP(rec, req)
	return rec
}

// A backend that gzips whenever the client advertises gzip (as Groq does).
func TestProxy_EgressDPIInspectsGzippedBackendResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(gzipBytes(t, piiReply))
			return
		}
		io.WriteString(w, piiReply)
	}))
	defer backend.Close()

	rec := postChat(t, newEgressProxy(t, backend))

	if !strings.Contains(rec.Body.String(), "[SENTINEL] Output blocked: contains PII.") {
		t.Fatalf("egress DPI was bypassed by a gzip-encoded response; got %q", rec.Body.String())
	}
}

// A backend that encodes even when not asked must not slip past egress DPI.
func TestProxy_FailsClosedOnUninspectableEncodedResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Write([]byte{0x1f, 0x8b, 0x00, 0x01})
	}))
	defer backend.Close()

	rec := postChat(t, newEgressProxy(t, backend))

	if !strings.Contains(rec.Body.String(), "[SENTINEL]") || bytes.Contains(rec.Body.Bytes(), []byte{0x1f, 0x8b}) {
		t.Fatalf("expected a [SENTINEL] deny for an uninspectable response, got %q", rec.Body.String())
	}
}
