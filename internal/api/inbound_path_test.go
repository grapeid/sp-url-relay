package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grapeid/sp-url-relay/internal/store"
)

// A real AID-shaped segment, since the path allowlist requires one.
const testAID = "EAbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"

func seedAllocation(t *testing.T, s *Server, st store.Store, token string) {
	t.Helper()
	if err := st.SaveAllocation(store.Allocation{
		AllocationToken: "tok-" + token,
		RAID:            testAID,
		PublicHostname:  s.publicID(token),
		EnrollmentAID:   "EEnrollmentAID",
		CreatedAt:       "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
}

// The allocation token is read from the first path segment, and everything
// after it is what the agent is asked for — the agent must not see the token.
func TestInboundStripsTokenBeforeForwarding(t *testing.T) {
	s, st := testServer(t)
	seedAllocation(t, s, st, "k7f2pq9rxy")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/k7f2pq9rxy/"+testAID+"/did.json", nil)
	req.Host = "relay.test"
	s.Handler().ServeHTTP(rec, req)

	// No tunnel session is registered, so a correctly-routed request stops at
	// the tunnel gap. That 503 is the proof it got past allocation lookup and
	// the path allowlist — a mis-parsed token or path would 404 instead.
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 tunnel gap, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("tunnel gap should set Retry-After")
	}
}

func TestInboundRejectsUnknownAndMalformedTokens(t *testing.T) {
	s, st := testServer(t)
	seedAllocation(t, s, st, "k7f2pq9rxy")

	cases := []struct {
		name string
		path string
	}{
		{"unallocated token", "/zzzzzzzzzz/" + testAID + "/did.json"},
		{"too short", "/abc/" + testAID + "/did.json"},
		{"non-base58 (contains 0 and O)", "/0OOOOOOOOO/" + testAID + "/did.json"},
		{"path not on allowlist", "/k7f2pq9rxy/" + testAID + "/secrets"},
		{"token alone", "/k7f2pq9rxy"},
		{"old subdomain-style request", "/" + testAID + "/did.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Host = "relay.test"
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("want 404, got %d", rec.Code)
			}
		})
	}
}

// The token now lives in the path, so the Host header is no longer a routing
// input. Requests must resolve identically whichever hostname they arrive on.
func TestInboundIgnoresHost(t *testing.T) {
	s, st := testServer(t)
	seedAllocation(t, s, st, "k7f2pq9rxy")

	for _, host := range []string{"relay.test", "grapeid-url-relay.fly.dev", "k7f2pq9rxy.relay.test"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/k7f2pq9rxy/"+testAID+"/did.json", nil)
		req.Host = host
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("host %s: want 503, got %d", host, rec.Code)
		}
	}
}

func TestRootStillServesBanner(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "relay.test"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}
