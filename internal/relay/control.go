package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"github.com/grapeid/sp-url-relay/internal/store"
)

var b64 = base64.RawURLEncoding

// A control request is a JSON object of strings signed by an identifier's
// current key, as ADR-048 §8 keeps ADR-024's allocate and release requests. It
// is signed the way the relay protocol signs an admission statement: Ed25519
// over the object's canonical JSON (every field but "signature", keys sorted,
// no whitespace, no HTML escaping), base64url without padding. Every field is
// printable ASCII, so the signed bytes have one spelling. Every request
// carries:
//
//	op         which request this is, so a signature for one cannot be used
//	           as another
//	relay      this relay's host name, so it cannot be used at another relay
//	signed_by  the identifier
//	t          RFC 3339, within two minutes of the relay's clock
//	nonce      16 to 64 characters, never accepted twice
//	signature
//
// The identifier must hold a live session: enrolment is the first admission
// (ADR-048 §8), and the key a request is checked against is the one the
// session's key event log names now.
type controlRequest struct {
	fields map[string]any
	aid    string
}

func (c controlRequest) str(k string) string {
	v, _ := c.fields[k].(string)
	return v
}

type controlHandler struct {
	op string
	fn func(w http.ResponseWriter, r *http.Request, c controlRequest)
}

func (s *Server) controlRoutes() map[string]controlHandler {
	if s.cfg.Mode == relayproto.ModePrivate {
		return map[string]controlHandler{
			"/allocate": {"allocate", s.handleAllocate},
			"/bind":     {"bind", s.handleBind},
			"/release":  {"release", s.handleRelease},
		}
	}
	return map[string]controlHandler{
		"/names/claim":     {"claim-name", s.handleClaimName},
		"/names/release":   {"release-name", s.handleReleaseName},
		"/domains/request": {"request-domain", s.handleRequestDomain},
		"/domains/verify":  {"verify-domain", s.handleVerifyDomain},
		"/domains/release": {"release-domain", s.handleReleaseDomain},
	}
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request, h controlHandler) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	// A request body has a few seconds to arrive, not as long as it likes.
	http.NewResponseController(w).SetReadDeadline(s.cfg.Now().Add(controlReadTimeout))
	ip := s.clientIP(r)
	if !s.controlIP.Allow(ip) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	c, status, err := s.verifyControl(r, h.op)
	if err != nil {
		s.cfg.Logger.Info("control request refused", "op", h.op, "ip", ip, "reason", err.Error())
		writeError(w, status, "refused", err.Error())
		return
	}
	if !s.controlID.Allow(c.aid) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this identity")
		return
	}
	if s.cfg.Mode == relayproto.ModePrivate {
		// Which identity asked for which private address is exactly what this
		// relay does not keep, in its database or its logs.
		s.cfg.Logger.Info("control request", "op", h.op)
	} else {
		s.cfg.Logger.Info("control request", "op", h.op, "aid", c.aid)
	}
	h.fn(w, r, c)
}

// verifyControl reads and checks a signed control request.
func (s *Server) verifyControl(r *http.Request, op string) (controlRequest, int, error) {
	var c controlRequest
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxControlBody+1))
	if err != nil {
		return c, http.StatusBadRequest, fmt.Errorf("could not read the request")
	}
	if len(raw) > maxControlBody {
		return c, http.StatusRequestEntityTooLarge, fmt.Errorf("the request is larger than %d bytes", maxControlBody)
	}
	if err := json.Unmarshal(raw, &c.fields); err != nil || c.fields == nil {
		return c, http.StatusBadRequest, fmt.Errorf("the request is not a JSON object")
	}
	for k, v := range c.fields {
		str, ok := v.(string)
		if !ok || !printableASCII(str) || !printableASCII(k) {
			return c, http.StatusBadRequest, fmt.Errorf("every field is a string of printable ASCII; %q is not", k)
		}
	}
	c.aid = c.str("signed_by")
	switch {
	case c.str("op") != op:
		return c, http.StatusBadRequest, fmt.Errorf("this endpoint takes op %q", op)
	case c.str("relay") != s.cfg.ConnectHost:
		return c, http.StatusBadRequest, fmt.Errorf("the request names relay %q; this is %q", c.str("relay"), s.cfg.ConnectHost)
	case c.aid == "":
		return c, http.StatusBadRequest, fmt.Errorf("signed_by is required")
	}
	at, err := time.Parse(time.RFC3339, c.str("t"))
	if err != nil {
		return c, http.StatusBadRequest, fmt.Errorf("t must be RFC 3339")
	}
	now := s.cfg.Now()
	if d := now.Sub(at); d > relayproto.ClockSkew || d < -relayproto.ClockSkew {
		return c, http.StatusBadRequest, fmt.Errorf("the request is not fresh")
	}
	nonce := c.str("nonce")
	if len(nonce) < 16 || len(nonce) > 64 {
		return c, http.StatusBadRequest, fmt.Errorf("nonce must be 16 to 64 characters")
	}
	session, ok := s.registry.Get(c.aid)
	if !ok {
		return c, http.StatusForbidden, fmt.Errorf("connect to this relay before asking it for anything")
	}
	key, err := currentKey(session.KEL(), c.aid)
	if err != nil {
		return c, http.StatusForbidden, err
	}
	sig, err := b64.DecodeString(c.str("signature"))
	if err != nil {
		return c, http.StatusBadRequest, fmt.Errorf("the signature is not base64url")
	}
	body, err := canonicalControl(c.fields)
	if err != nil {
		return c, http.StatusBadRequest, err
	}
	if err := keri.VerifySignature(key, body, sig); err != nil {
		return c, http.StatusUnauthorized, fmt.Errorf("the request is not signed by the key %q's log names now", c.aid)
	}
	// Recorded only once it has verified, so nobody can burn somebody else's
	// nonce with a forgery.
	digest := sha256.Sum256([]byte(c.aid + " " + nonce))
	fresh, err := s.cfg.Store.UseNonce(hex.EncodeToString(digest[:]), at.Add(relayproto.ClockSkew))
	if err != nil {
		return c, http.StatusInternalServerError, fmt.Errorf("could not record the request")
	}
	if !fresh {
		return c, http.StatusConflict, fmt.Errorf("this request has been seen before")
	}
	return c, 0, nil
}

// currentKey is the one signing key an identifier's key event log names now.
// The log is the session's, which admission already verified; it is checked
// again because a control request is authorised by it.
func currentKey(kel []byte, aid string) (string, error) {
	messages, err := keri.ParseKELStream(kel)
	if err != nil {
		return "", fmt.Errorf("the key event log held for %q is not readable", aid)
	}
	st, err := keri.ValidateSignedKEL(messages)
	if err != nil || st.Identifier != aid || len(st.Keys) != 1 {
		return "", fmt.Errorf("the key event log held for %q does not establish one signing key", aid)
	}
	return st.Keys[0], nil
}

// canonicalControl is the byte string a control request is signed over: the
// one form every service-provider request is signed in (the Identity Agent's
// ADR-049), implemented once, by relayproto.CanonicalBody. This relay keeps no
// copy of its own.
func canonicalControl(fields map[string]any) ([]byte, error) {
	return relayproto.CanonicalBody(fields)
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// --- private mode ---------------------------------------------------------

// commitmentOf is the stored commitment to an allocation's secret.
func commitmentOf(secret []byte) string {
	sum := sha256.Sum256(secret)
	return b64.EncodeToString(sum[:])
}

// handleAllocate makes a private allocation. The Identity Agent sends a
// commitment to a secret it keeps (base64url SHA-256 of 32 or more random
// bytes). The relay stores the label and the commitment, never the
// identifier: after a restart, the secret is what proves whose the label is.
func (s *Server) handleAllocate(w http.ResponseWriter, _ *http.Request, c controlRequest) {
	commitment := c.str("commitment")
	if raw, err := b64.DecodeString(commitment); err != nil || len(raw) != sha256.Size {
		writeError(w, http.StatusBadRequest, "invalid_commitment", "commitment is base64url SHA-256 of the allocation's secret")
		return
	}
	s.boundMu.RLock()
	held := s.boundCount[c.aid]
	s.boundMu.RUnlock()
	if held >= s.cfg.PrivatePerSession {
		writeError(w, http.StatusForbidden, "quota", fmt.Sprintf("an identity may hold %d addresses here at once", s.cfg.PrivatePerSession))
		return
	}
	label := relayproto.NewAllocationToken()
	if err := s.cfg.Store.CreateAllocation(label, commitment); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", "could not record the allocation")
		return
	}
	s.bind(label, c.aid)
	writeJSON(w, http.StatusOK, map[string]any{
		"allocation": label,
		"public_url": "https://" + s.cfg.Apex + "/" + label,
		"mode":       relayproto.ModePrivate,
	})
}

// checkSecret proves the caller made the allocation.
func (s *Server) checkSecret(label, secretB64 string) (int, error) {
	if !validLabel(label) {
		return http.StatusNotFound, fmt.Errorf("no such allocation")
	}
	commitment, err := s.cfg.Store.Allocation(label)
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound, fmt.Errorf("no such allocation")
	}
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("could not read the allocation")
	}
	secret, err := b64.DecodeString(secretB64)
	if err != nil || len(secret) < 32 {
		return http.StatusForbidden, fmt.Errorf("the secret does not match this allocation")
	}
	if subtle.ConstantTimeCompare([]byte(commitmentOf(secret)), []byte(commitment)) != 1 {
		return http.StatusForbidden, fmt.Errorf("the secret does not match this allocation")
	}
	return 0, nil
}

// handleBind attaches an existing allocation to the caller's session, as an
// Identity Agent does for each of its allocations after it connects: the
// relay keeps that link only in memory, so a restarted relay learns it again
// this way.
func (s *Server) handleBind(w http.ResponseWriter, _ *http.Request, c controlRequest) {
	label := c.str("allocation")
	if status, err := s.checkSecret(label, c.str("secret")); err != nil {
		writeError(w, status, "refused", err.Error())
		return
	}
	s.boundMu.RLock()
	held, already := s.boundCount[c.aid], s.bound[label] == c.aid
	s.boundMu.RUnlock()
	if !already && held >= s.cfg.PrivatePerSession {
		writeError(w, http.StatusForbidden, "quota", fmt.Sprintf("an identity may hold %d addresses here at once", s.cfg.PrivatePerSession))
		return
	}
	s.bind(label, c.aid)
	writeJSON(w, http.StatusOK, map[string]any{"allocation": label, "public_url": "https://" + s.cfg.Apex + "/" + label})
}

// handleRelease ends an allocation for good.
func (s *Server) handleRelease(w http.ResponseWriter, _ *http.Request, c controlRequest) {
	label := c.str("allocation")
	if status, err := s.checkSecret(label, c.str("secret")); err != nil {
		writeError(w, status, "refused", err.Error())
		return
	}
	if err := s.cfg.Store.DeleteAllocation(label); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", "could not release the allocation")
		return
	}
	s.unbind(label)
	writeJSON(w, http.StatusOK, map[string]any{"allocation": label, "released": true})
}

func (s *Server) bind(label, aid string) {
	s.boundMu.Lock()
	defer s.boundMu.Unlock()
	if prev, ok := s.bound[label]; ok {
		if prev == aid {
			return
		}
		s.boundCount[prev]--
	}
	s.bound[label] = aid
	s.boundCount[aid]++
}

func (s *Server) unbind(label string) {
	s.boundMu.Lock()
	defer s.boundMu.Unlock()
	if prev, ok := s.bound[label]; ok {
		delete(s.bound, label)
		if s.boundCount[prev]--; s.boundCount[prev] <= 0 {
			delete(s.boundCount, prev)
		}
	}
}

// --- public mode ----------------------------------------------------------

func (s *Server) handleClaimName(w http.ResponseWriter, r *http.Request, c controlRequest) {
	if !s.claimIP.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many name claims from this address")
		return
	}
	name := c.str("name")
	switch {
	case !validName(name):
		writeError(w, http.StatusBadRequest, "invalid_name", "a name is 3 to 32 lowercase letters, digits and single inner hyphens")
		return
	case s.reserved[name]:
		writeError(w, http.StatusForbidden, "reserved", "that name is reserved")
		return
	}
	switch err := s.cfg.Store.ClaimName(name, c.aid, s.cfg.PerIdentity, NameHoldBack); {
	case errors.Is(err, store.ErrTaken):
		writeError(w, http.StatusConflict, "taken", "that name is held by another identity")
		return
	case errors.Is(err, store.ErrQuota):
		writeError(w, http.StatusForbidden, "quota", fmt.Sprintf("an identity may hold %d names here", s.cfg.PerIdentity))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "store_error", "could not record the name")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "public_url": "https://" + name + "." + s.cfg.Apex + "/", "mode": relayproto.ModePublic,
	})
}

func (s *Server) handleReleaseName(w http.ResponseWriter, _ *http.Request, c controlRequest) {
	name := c.str("name")
	switch err := s.cfg.Store.ReleaseName(name, c.aid); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "nobody holds that name")
	case errors.Is(err, store.ErrNotYours):
		writeError(w, http.StatusForbidden, "not_yours", "only the identity holding a name may release it")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "store_error", "could not release the name")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "released": true})
	}
}

// txtName and txtValue are the DNS record that proves a domain is an
// identity's: TXT _iarelay.<domain> = "iarelay-aid=<identifier>".
func txtName(domain string) string { return "_iarelay." + domain }
func txtValue(aid string) string   { return "iarelay-aid=" + aid }

func (s *Server) handleRequestDomain(w http.ResponseWriter, _ *http.Request, c controlRequest) {
	domain := strings.ToLower(c.str("domain"))
	if !validDomain(domain, s.cfg.Apex) {
		writeError(w, http.StatusBadRequest, "invalid_domain", "not a domain this relay can serve")
		return
	}
	switch err := s.cfg.Store.RequestDomain(domain, c.aid, s.cfg.PerIdentity, DomainPendingFor); {
	case errors.Is(err, store.ErrTaken):
		writeError(w, http.StatusConflict, "taken", "another identity holds that domain; if it is yours, publish the TXT record below and send verify-domain")
		return
	case errors.Is(err, store.ErrQuota):
		writeError(w, http.StatusForbidden, "quota", fmt.Sprintf("an identity may hold %d domains here", s.cfg.PerIdentity))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "store_error", "could not record the domain")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domain": domain, "verified": false,
		"txt_name": txtName(domain), "txt_value": txtValue(c.aid),
		"then": "point the domain at this relay, publish the TXT record, and send verify-domain",
	})
}

// handleVerifyDomain activates a custom domain once its DNS carries the TXT
// record binding it to the identity. Only then is it served, and only then may
// the relay request a certificate for it (HostAllowed). The proof decides who
// holds a domain, not who asked first: it takes over another identity's
// unproved request, and a proof that no longer holds loses to one that does.
func (s *Server) handleVerifyDomain(w http.ResponseWriter, r *http.Request, c controlRequest) {
	domain := strings.ToLower(c.str("domain"))
	if !validDomain(domain, s.cfg.Apex) {
		writeError(w, http.StatusBadRequest, "invalid_domain", "not a domain this relay can serve")
		return
	}
	if !s.domainCheckID.Allow(c.aid) || !s.domainCheck.Allow("relay") {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many domain checks; try again in a minute")
		return
	}
	if !s.proves(r.Context(), domain, c.aid) {
		writeError(w, http.StatusForbidden, "unproven",
			fmt.Sprintf("TXT %s does not carry %q yet", txtName(domain), txtValue(c.aid)))
		return
	}
	err := s.cfg.Store.VerifyDomainFor(domain, c.aid, s.cfg.PerIdentity)
	if errors.Is(err, store.ErrTaken) {
		// Proved by another identity before. Its proof is gone if this one
		// now holds; check, and let the current proof win.
		if d, derr := s.cfg.Store.Domain(domain); derr == nil && !s.proves(r.Context(), domain, d.AID) {
			if err = s.cfg.Store.UnverifyDomain(domain); err == nil {
				err = s.cfg.Store.VerifyDomainFor(domain, c.aid, s.cfg.PerIdentity)
			}
		}
	}
	switch {
	case errors.Is(err, store.ErrTaken):
		writeError(w, http.StatusConflict, "taken", "another identity has proved that domain")
		return
	case errors.Is(err, store.ErrQuota):
		writeError(w, http.StatusForbidden, "quota", fmt.Sprintf("an identity may hold %d domains here", s.cfg.PerIdentity))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "store_error", "could not record the proof")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "verified": true, "public_url": "https://" + domain + "/"})
}

func (s *Server) handleReleaseDomain(w http.ResponseWriter, _ *http.Request, c controlRequest) {
	domain := strings.ToLower(c.str("domain"))
	switch err := s.cfg.Store.ReleaseDomain(domain, c.aid); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "nobody holds that domain")
	case errors.Is(err, store.ErrNotYours):
		writeError(w, http.StatusForbidden, "not_yours", "only the identity holding a domain may release it")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "store_error", "could not release the domain")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "released": true})
	}
}

// --- descriptor -----------------------------------------------------------

// handleDescriptor publishes what an Identity Agent needs to use this relay
// (ADR-048 §8).
func (s *Server) handleDescriptor(w http.ResponseWriter, _ *http.Request) {
	base := "https://" + s.cfg.ConnectHost
	endpoints := map[string]string{}
	for path, h := range s.controlRoutes() {
		endpoints[h.op] = base + path
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":        relayproto.ProtocolVersion,
		"subprotocol":     relayproto.Subprotocol,
		"service":         s.cfg.ConnectHost,
		"connect_host":    s.cfg.ConnectHost,
		"caller_host":     s.cfg.Apex,
		"mode":            s.cfg.Mode,
		"tunnel_endpoint": "wss://" + s.cfg.ConnectHost + "/tunnel",
		"endpoints":       endpoints,
		"address_form":    map[relayproto.Mode]string{relayproto.ModePrivate: "https://" + s.cfg.Apex + "/<label>/", relayproto.ModePublic: "https://<name>." + s.cfg.Apex + "/"}[s.cfg.Mode],
		"control_signing": map[string]any{
			"fields":    []string{"op", "relay", "signed_by", "t", "nonce", "signature"},
			"canonical": "JSON of string fields, signature removed, keys sorted, no whitespace, no HTML escaping",
			"signature": "Ed25519 by the key the identifier's key event log names now, base64url without padding",
		},
		"limits": map[string]any{
			"names_per_identity":   s.cfg.PerIdentity,
			"domains_per_identity": s.cfg.PerIdentity,
			"control_per_minute":   controlPerIdentity,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}
