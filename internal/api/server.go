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
        "github.com/grapeid/sp-url-relay/internal/hostname"
        "github.com/grapeid/sp-url-relay/internal/oobi"
        "github.com/grapeid/sp-url-relay/internal/protocol"
        "github.com/grapeid/sp-url-relay/internal/sign"
        "github.com/grapeid/sp-url-relay/internal/store"
        tunnelpkg "github.com/grapeid/sp-url-relay/internal/tunnel"
)

type Config struct {
        Apex       string
        RelayAID   string
        ListenAddr string
        Store      store.Store
        Logger     *slog.Logger
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
                "v":                    protocol.JSONVersion,
                "protocol_version":     protocol.Version,
                "didwebs_spec_version": protocol.DidWebsSpecVersion,
                "relay_aid":            s.cfg.RelayAID,
                "apex":                 s.cfg.Apex,
                "tunnel_endpoint":      base + "/tunnel",
                "allocate_endpoint":    base + "/allocate",
                "release_endpoint":     base + "/release",
                "heartbeat_endpoint":   base + "/heartbeat",
                "heartbeat_interval_sec": protocol.HeartbeatInterval,
                "subdomain_alphabet":   "base58",
                "subdomain_min_len":    protocol.MinHostnameLen,
                "path_allowlist":       protocol.PathAllowlist,
                "rate_limits": map[string]int{
                        "allocate_per_min":               protocol.AllocatePerMin,
                        "inbound_per_hostname_per_min":   protocol.InboundPerHostMin,
                },
                "pricing_tier": "free",
        })
}

type enrollBody struct {
        V                 string `json:"v"`
        EnrollmentAID     string `json:"enrollment_aid"`
        OOBI              string `json:"oobi"`
        RootAIDEnrollment bool   `json:"root_aid_enrollment"`
        PublicKeyB64      string `json:"public_key_b64,omitempty"` // dev bootstrap when OOBI fetch blocked
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
        if err := oobi.ValidateOOBIURL(body.OOBI); err != nil {
                writeError(w, http.StatusBadRequest, "oobi_blocked", err.Error())
                return
        }
        exists, _ := s.cfg.Store.HasEnrollment(body.EnrollmentAID)
        if exists {
                writeError(w, http.StatusConflict, "already_enrolled", body.EnrollmentAID)
                return
        }
        pubKey := body.PublicKeyB64
        if pubKey == "" {
                // BLOCKED: full OOBI KEL resolve — production fetches keystate from OOBI.
                writeError(w, http.StatusUnauthorized, "oobi_unresolvable", "OOBI resolve not wired; supply public_key_b64 in dev")
                return
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
        publicHost := hostToken + "." + s.cfg.Apex
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

func (s *Server) handleInbound(w http.ResponseWriter, r *http.Request) {
        host := r.Host
        if idx := strings.Index(host, ":"); idx != -1 {
                host = host[:idx]
        }
        sub := strings.TrimSuffix(host, "."+s.cfg.Apex)
        if sub == host || sub == "" || sub == s.cfg.Apex {
                if r.URL.Path == "/" {
                        w.Write([]byte("url-relay M35 (SEAM-16)"))
                        return
                }
                http.NotFound(w, r)
                return
        }
        if !s.allowInbound(sub) {
                writeError(w, http.StatusTooManyRequests, "rate_limited", "")
                return
        }
        quarantined, _ := s.cfg.Store.IsQuarantined(sub + "." + s.cfg.Apex)
        if quarantined {
                http.NotFound(w, r)
                return
        }
        alloc, _ := s.cfg.Store.GetAllocationByHostname(host)
        if alloc == nil {
                http.NotFound(w, r)
                return
        }
        if !allowlist.Allowed(r.Method, r.URL.Path) {
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
                Method: r.Method, Path: r.URL.Path, Headers: headers,
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

func (s *Server) mintHostname() (string, error) {
        for i := 0; i < 20; i++ {
                token, err := hostname.Mint(10)
                if err != nil {
                        return "", err
                }
                full := token + "." + s.cfg.Apex
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