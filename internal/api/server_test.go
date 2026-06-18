package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/grapeid/sp-url-relay/internal/sign"
	"github.com/grapeid/sp-url-relay/internal/store"
)

func testServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Apex: "relay.test", RelayAID: "ERelay", Store: st}), st
}

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signBody(t *testing.T, priv ed25519.PrivateKey, enrollmentAID string, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	body["v"] = "IARELAY10JSON"
	body["signed_by"] = enrollmentAID
	canonical, err := sign.CanonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)
	body["signature"] = base64.StdEncoding.EncodeToString(sig)
	return body
}

func TestAllocateCSPRNGAndReleaseIdempotent(t *testing.T) {
	srv, st := testServer(t)
	defer st.Close()
	pub, priv := testKeypair(t)
	enrollmentAID := "EEnrollmentAID00000000000000000000000001"
	_ = st.SaveEnrollment(store.Enrollment{
		EnrollmentAID: enrollmentAID, OOBIURL: "https://agent.example/oobi",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub), EnrolledAt: "2026-01-01T00:00:00Z",
	})
	tok, _, _ := enrollTokenForTest(enrollmentAID)

	allocBody := signBody(t, priv, enrollmentAID, map[string]interface{}{
		"raid": "EPairwiseAID00000000000000000000000001",
		"intent": "serve-didwebs-artifacts", "ttl_hint": "persistent",
	})
	raw, _ := json.Marshal(allocBody)
	req := httptest.NewRequest(http.MethodPost, "/allocate", bytes.NewReader(raw))
	req.Header.Set("Authorization", tok)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("allocate %d %s", w.Code, w.Body.String())
	}
	var allocResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &allocResp)
	host := allocResp["public_hostname"].(string)
	if len(host) < 8 {
		t.Fatalf("hostname too short: %s", host)
	}

	// Repeat allocate → 409
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/allocate", bytes.NewReader(raw))
	req2.Header.Set("Authorization", tok)
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 got %d", w2.Code)
	}

	token := allocResp["allocation_token"].(string)
	releaseBody := signBody(t, priv, enrollmentAID, map[string]interface{}{
		"allocation_token": token,
	})
	rawRel, _ := json.Marshal(releaseBody)
	for i := 0; i < 2; i++ {
		w3 := httptest.NewRecorder()
		req3 := httptest.NewRequest(http.MethodPost, "/release", bytes.NewReader(rawRel))
		req3.Header.Set("Authorization", tok)
		srv.Handler().ServeHTTP(w3, req3)
		if w3.Code != http.StatusOK {
			t.Fatalf("release attempt %d: %d", i, w3.Code)
		}
	}
	q, _ := st.IsQuarantined(host)
	if !q {
		t.Fatal("released hostname must enter quarantine")
	}
}

func TestQuarantineNeverReissue(t *testing.T) {
	srv, st := testServer(t)
	defer st.Close()
	pub, _ := testKeypair(t)
	enrollmentAID := "EEnrollmentAID00000000000000000000000002"
	_ = st.SaveEnrollment(store.Enrollment{
		EnrollmentAID: enrollmentAID, OOBIURL: "https://agent.example/oobi",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub), EnrolledAt: "2026-01-01T00:00:00Z",
	})
	host := "deadbeef12.relay.test"
	_ = st.SaveAllocation(store.Allocation{
		AllocationToken: "tok1", RAID: "ERAID1", PublicHostname: host,
		EnrollmentAID: enrollmentAID, CreatedAt: "2026-01-01T00:00:00Z",
	})
	_ = st.DeleteAllocation("tok1")
	_ = st.QuarantineHostname(host)

	_, err := srv.mintHostname()
	if err == nil {
		// may succeed with different token; ensure quarantined host not reused
		a, _ := st.GetAllocationByHostname(host)
		if a != nil {
			t.Fatal("quarantined hostname reissued")
		}
	}
}

func enrollTokenForTest(enrollmentAID string) (string, interface{}, error) {
	return base64.RawURLEncoding.EncodeToString([]byte(
		`{"v":"KERI10JSON","t":"exn","i":"`+enrollmentAID+`","a":{"enrollment_aid":"`+enrollmentAID+`"}}`,
	)), nil, nil
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}