package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/grapeid/sp-url-relay/internal/allowlist"
	"github.com/grapeid/sp-url-relay/internal/enroll"
	"github.com/grapeid/sp-url-relay/internal/enrollverify"
	"github.com/grapeid/sp-url-relay/internal/hostname"
	"github.com/grapeid/sp-common/oobi"
	"github.com/grapeid/sp-url-relay/internal/protocol"
	"github.com/grapeid/sp-common/sign"
	"github.com/grapeid/sp-url-relay/internal/store"
	tunnelpkg "github.com/grapeid/sp-url-relay/internal/tunnel"
)

// decodeKEL accepts the CESR stream in any of the base64 spellings the agent
// side might reasonably produce.
//
// An absent log is not an error here. Whether a log is required is the
// verifier's question, and answering it in two places invites them to disagree.
func decodeKEL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("kel_cesr_b64 is not valid base64")
}

type Config struct {
	Apex       string
	RelayAID   string
	ListenAddr string
	Store      store.Store
	Logger     *slog.Logger
	// Verifier binds an enrolling key to its AID. Nil or disabled means
	// enrollment is open, which is a choice that has to be made explicitly.
	Verifier enrollverify.Verifier
}

type Server struct {
	cfg      Config
	hub      *tunnelpkg.Hub
	upgrader websocket.Upgrader
	inbound  sync.Map // hostname -> simple token bucket
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Apex == "" {
		cfg.Apex = "relay.grapeid.org"
	}
	if cfg.RelayAID == "" {
		cfg.RelayAID = "ERelayAID000000000000000000000000000000"
	}
	return &Server{
		cfg: cfg,
		hub: tunnelpkg.NewHub(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/url-relay-service.json", s.handleDescriptor)
	mux.HandleFunc("/enroll", s.handleEnroll)
	mux.HandleFunc("/allocate", s.handleAllocate)
	mux.HandleFunc("/release", s.handleRelease)
	mux.HandleFunc("/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/tunnel", s.handleTunnelWS)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.handleInbound)
	return mux
}

func (s *Server) handleDescriptor(w http.ResponseWriter, r *http.Request) {
	base := s.baseURL(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"v":                      protocol.JSONVersion,
		"protocol_version":       protocol.Version,
		"didwebs_spec_version":   protocol.DidWebsSpecVersion,
		"relay_aid":              s.cfg.RelayAID,
		"apex":                   s.cfg.Apex,
		"tunnel_endpoint":        base + "/tunnel",
		"allocate_endpoint":      base + "/allocate",
		"release_endpoint":       base + "/release",
		"heartbeat_endpoint":     base + "/heartbeat",
		"heartbeat_interval_sec": protocol.HeartbeatInterval,
		"url_form":               protocol.URLForm,
		"token_alphabet":         "base58",
		"token_min_len":          protocol.MinHostnameLen,
		// Whether this relay binds an enrolling key to its AID, and how to
		// satisfy it. Published so an agent can tell before it tries.
		"enrollment_verified": s.cfg.Verifier != nil && s.cfg.Verifier.Enabled(),
		"enrollment_kel_field": "kel_cesr_b64",
		"enrollment_kel_format": "cesr",
		"path_allowlist":         protocol.PathAllowlist,
		"rate_limits": map[string]int{
			"allocate_per_min":             protocol.AllocatePerMin,
			"inbound_per_hostname_per_min": protocol.InboundPerHostMin,
		},
		"pricing_tier": "free",
	})
}

type enrollBody struct {
	V                 string `json:"v"`
	EnrollmentAID     string `json:"enrollment_aid"`
	OOBI              string `json:"oobi"`
	RootAIDEnrollment bool   `json:"root_aid_enrollment"`
	PublicKeyB64      string `json:"public_key_b64"`
	// KELCESRB64 is the enrolling identity's key event log, as a CESR stream,
	// base64-encoded for transport. The relay validates it in process; it is
	// not fetched, because at enrollment the agent has no tunnel yet and may
	// not be reachable at all. A log is self-verifying, so who carries it
	// does not matter.
	//
	// omitempty is load-bearing: the signature covers the canonical body, so a
	// field that serialised as "" would change the canonical form and break
	// every signature produced before this field existed. Omitted when absent,
	// the old canonicalisation is preserved exactly; sent, it is signed like
	// everything else.
	KELCESRB64 string `json:"kel_cesr_b64,omitempty"`
	// Signature covers the canonical body, made by the key being presented.
	//
	// Enrollment used to take none. That mattered more here than it looks:
	// allocation and release ARE signed, against the key recorded at
	// enrollment — so whoever enrolls an AID controls every signed operation
	// for it afterwards. Registering an unproven key was therefore a full
	// takeover of somebody's relay presence, not merely a squat on a name.
	Signature string `json:"signature"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}
	var body enrollBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if body.EnrollmentAID == "" || body.OOBI == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "enrollment_aid and oobi required")
		return
	}
	if err := oobi.Validate(body.OOBI); err != nil {
		writeError(w, http.StatusBadRequest, "oobi_blocked", err.Error())
		return
	}
	exists, _ := s.cfg.Store.HasEnrollment(body.EnrollmentAID)
	if exists {
		writeError(w, http.StatusConflict, "already_enrolled", body.EnrollmentAID)
		return
	}
	pubKey := body.PublicKeyB64
	if pubKey == "" || body.Signature == "" {
		writeError(w, http.StatusBadRequest, "missing_fields",
			"public_key_b64 and signature are required")
		return
	}

	// Two separate questions, and enrollment needs both answered.
	//
	// First: does the caller HOLD this key? A signature over the request
	// says yes. Second: does the key BELONG to this AID? Only the
	// identity's key event log says that, and it has to be asked — the key
	// is public, so presenting the right one proves nothing on its own.
	//
	// Either check alone is useless. Possession without binding lets
	// anybody enroll any AID with a key they invented. Binding without
	// possession lets anybody enroll any AID using its real published key,
	// which they can simply look up.
	canonical, cerr := sign.CanonicalBody(body)
	if cerr != nil {
		writeError(w, http.StatusBadRequest, "canonicalisation_failed", cerr.Error())
		return
	}
	if err := sign.VerifyEd25519(pubKey, body.Signature, canonical); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
		return
	}
	if s.cfg.Verifier != nil && s.cfg.Verifier.Enabled() {
		kel, derr := decodeKEL(body.KELCESRB64)
		if derr != nil {
			writeError(w, http.StatusBadRequest, "invalid_kel", derr.Error())
			return
		}
		if result := s.cfg.Verifier.Verify(body.EnrollmentAID, pubKey, kel); !result.Verified {
			writeError(w, http.StatusForbidden, "key_not_bound_to_aid", result.Reason)
			return
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.cfg.Store.SaveEnrollment(store.Enrollment{
		EnrollmentAID: body.EnrollmentAID, OOBIURL: body.OOBI,
		PublicKeyB64: pubKey, RootAIDEnrollment: body.RootAIDEnrollment, EnrolledAt: now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	tokenStr, _, err := enroll.IssueToken(s.cfg.RelayAID, body.EnrollmentAID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enrolled": true, "enrollment_aid": body.EnrollmentAID,
		"enrollment_token": tokenStr, "tunnel_endpoint": s.baseURL(r) + "/tunnel",
		"enrolled_at": now,
	})
}

type signedBody struct {
	V         string `json:"v"`
	SignedBy  string `json:"signed_by"`
	Signature string `json:"signature"`
}

type allocateBody struct {
	signedBody
	RAID    string `json:"raid"`
	Intent  string `json:"intent"`
	TTLHint string `json:"ttl_hint"`
}

func (s *Server) handleAllocate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}
	enrollmentAID, err := s.authEnrollment(r)
	if err != nil {
		writeError(w, http.StatusForbidden, "enrollment_token_invalid", err.Error())
		return
	}
	var body allocateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if err := s.verifySigned(enrollmentAID, body.signedBody, body); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
		return
	}
	if body.RAID == "" || body.Intent != "serve-didwebs-artifacts" {
		writeError(w, http.StatusBadRequest, "invalid_raid", "raid and intent required")
		return
	}
	if existing, _ := s.cfg.Store.GetAllocationByRAID(body.RAID); existing != nil {
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error": "already_allocated", "raid": body.RAID,
			"public_hostname": existing.PublicHostname,
			"public_url":      "https://" + existing.PublicHostname,
		})
		return
	}
	token, err := s.cfg.Store.MintAllocationToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error", err.Error())
		return
	}
	hostToken, err := s.mintHostname()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hostname_error", err.Error())
		return
	}
	publicHost := s.publicID(hostToken)
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.cfg.Store.SaveAllocation(store.Allocation{
		AllocationToken: token, RAID: body.RAID, PublicHostname: publicHost,
		EnrollmentAID: enrollmentAID, CreatedAt: now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"public_url": "https://" + publicHost, "public_hostname": publicHost,
		"allocation_token": token, "valid_until": nil,
		"tunnel_endpoint": s.baseURL(r) + "/tunnel",
	})
}

type releaseBody struct {
	signedBody
	AllocationToken string `json:"allocation_token"`
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}
	enrollmentAID, err := s.authEnrollment(r)
	if err != nil {
		writeError(w, http.StatusForbidden, "enrollment_token_invalid", err.Error())
		return
	}
	var body releaseBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if err := s.verifySigned(enrollmentAID, body.signedBody, body); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
		return
	}
	// Idempotent: unknown/already-released token → 200 treat-as-done (SEAM-16 OQ-3).
	alloc, _ := s.cfg.Store.GetAllocationByToken(body.AllocationToken)
	releasedHost := ""
	if alloc != nil {
		if alloc.EnrollmentAID != enrollmentAID {
			writeError(w, http.StatusForbidden, "forbidden", "allocation not owned by enrollment aid")
			return
		}
		releasedHost = alloc.PublicHostname
		_ = s.cfg.Store.DeleteAllocation(body.AllocationToken)
		_ = s.cfg.Store.QuarantineHostname(alloc.PublicHostname)
	}
	if releasedHost == "" {
		releasedHost = "unknown"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"released": true, "public_hostname": releasedHost,
		"released_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}
	enrollmentAID, err := s.authEnrollment(r)
	if err != nil {
		writeError(w, http.StatusForbidden, "enrollment_token_invalid", err.Error())
		return
	}
	var body signedBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if err := s.verifySigned(enrollmentAID, body, body); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
		return
	}
	next := time.Now().UTC().Add(time.Duration(protocol.HeartbeatInterval) * time.Second)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "next_heartbeat_before": next.Format(time.RFC3339),
	})
}

func (s *Server) handleTunnelWS(w http.ResponseWriter, r *http.Request) {
	enrollmentAID, err := s.authEnrollment(r)
	if err != nil {
		http.Error(w, "enrollment_token_invalid", http.StatusForbidden)
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.hub.Register(enrollmentAID, conn)
}

// handleInbound routes a public request to the agent that owns it.
//
// The allocation token is the FIRST PATH SEGMENT, not a subdomain:
//
//	https://relay.grapeid.org/k7f2pq9r/E.../did.json
//	                          ^token^  ^--- forwarded to the agent ---^
//
// Keeping the token in the path instead of in the hostname keeps it inside
// TLS. A subdomain would publish it in every DNS query and in the cleartext
// TLS SNI field, handing the pairwise identifier to the DNS operator and to
// any passive network observer — the exact leak Decision 6 set out to avoid.
// It also means one certificate and no wildcard DNS.
//
// Everything after the token is forwarded verbatim, so agents serve exactly
// the paths they served under the subdomain scheme.
func (s *Server) handleInbound(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(r.URL.Path, "/")
	if trimmed == "" {
		w.Write([]byte("url-relay M35 (SEAM-16)"))
		return
	}
	parts := strings.SplitN(trimmed, "/", 2)
	token := parts[0]
	rest := "/"
	if len(parts) == 2 {
		rest = "/" + parts[1]
	}
	if !hostname.Valid(token) {
		http.NotFound(w, r)
		return
	}
	if !s.allowInbound(token) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "")
		return
	}
	quarantined, _ := s.cfg.Store.IsQuarantined(s.publicID(token))
	if quarantined {
		http.NotFound(w, r)
		return
	}
	alloc, _ := s.cfg.Store.GetAllocationByHostname(s.publicID(token))
	if alloc == nil {
		http.NotFound(w, r)
		return
	}
	if !allowlist.Allowed(r.Method, rest) {
		http.NotFound(w, r)
		return
	}
	sess, ok := s.hub.SessionForEnrollment(alloc.EnrollmentAID)
	if !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(protocol.TunnelGapRetry.Seconds())))
		http.Error(w, "tunnel gap", http.StatusServiceUnavailable)
		return
	}
	streamID := randomStreamID()
	headers := map[string]string{}
	for k, vals := range r.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}
	req := tunnelpkg.RequestFrame{
		T: "req", StreamID: streamID, RAID: alloc.RAID,
		Method: r.Method, Path: rest, Headers: headers,
	}
	res, err := sess.Forward(req, 30*time.Second)
	if err != nil {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(protocol.TunnelGapRetry.Seconds())))
		http.Error(w, "tunnel gap", http.StatusServiceUnavailable)
		return
	}
	for k, v := range res.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(res.Status)
	if res.BodyB64 != "" {
		raw, _ := base64.RawURLEncoding.DecodeString(res.BodyB64)
		_, _ = w.Write(raw)
	}
}

func (s *Server) authEnrollment(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("missing authorization")
	}
	tok, err := enroll.ParseAuthorization(auth)
	if err != nil {
		return "", err
	}
	enrollmentAID := tok.I
	if enrollmentAID == "" {
		if v, ok := tok.A["enrollment_aid"].(string); ok {
			enrollmentAID = v
		}
	}
	if enrollmentAID == "" {
		return "", fmt.Errorf("token missing enrollment aid")
	}
	exists, err := s.cfg.Store.HasEnrollment(enrollmentAID)
	if err != nil || !exists {
		return "", fmt.Errorf("unknown enrollment")
	}
	return enrollmentAID, nil
}

func (s *Server) verifySigned(enrollmentAID string, signed signedBody, full interface{}) error {
	if signed.SignedBy != enrollmentAID {
		return fmt.Errorf("signed_by mismatch")
	}
	e, err := s.cfg.Store.GetEnrollment(enrollmentAID)
	if err != nil || e == nil {
		return fmt.Errorf("enrollment not found")
	}
	canonical, err := sign.CanonicalBody(full)
	if err != nil {
		return err
	}
	return sign.VerifyEd25519(e.PublicKeyB64, signed.Signature, canonical)
}

// publicID is the stored, canonical public identity of an allocation:
// "relay.grapeid.org/k7f2pq9r". Prefixing "https://" yields the public URL,
// and the did:web form is did:web:relay.grapeid.org:k7f2pq9r.
func (s *Server) publicID(token string) string {
	return s.cfg.Apex + "/" + token
}

func (s *Server) mintHostname() (string, error) {
	for i := 0; i < 20; i++ {
		token, err := hostname.Mint(10)
		if err != nil {
			return "", err
		}
		full := s.publicID(token)
		q, _ := s.cfg.Store.IsQuarantined(full)
		if q {
			continue
		}
		if existing, _ := s.cfg.Store.GetAllocationByHostname(full); existing == nil {
			return token, nil
		}
	}
	return "", fmt.Errorf("hostname pool exhausted")
}

func (s *Server) allowInbound(sub string) bool {
	// Simple per-hostname rate limit (R-16).
	type bucket struct {
		count int
		reset time.Time
	}
	now := time.Now()
	v, _ := s.inbound.LoadOrStore(sub, &bucket{reset: now.Add(time.Minute)})
	b := v.(*bucket)
	if now.After(b.reset) {
		b.count = 0
		b.reset = now.Add(time.Minute)
	}
	b.count++
	return b.count <= protocol.InboundPerHostMin
}

func (s *Server) baseURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Host
	if host == "" {
		host = "localhost" + s.cfg.ListenAddr
	}
	return proto + "://" + host
}

func randomStreamID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]string{"error": code, "detail": detail})
}

// DrainBody is a test helper.
func DrainBody(r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }
