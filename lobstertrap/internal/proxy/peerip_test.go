package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestPeerIP_IgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "172.18.0.5:51234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := peerIP(r); got != "172.18.0.5" {
		t.Errorf("peerIP = %q, want 172.18.0.5", got)
	}
}

func TestPeerIP_FallsBackToRawAddr(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.RemoteAddr = "not-a-host-port"
	if got := peerIP(r); got != "not-a-host-port" {
		t.Errorf("peerIP = %q", got)
	}
}
