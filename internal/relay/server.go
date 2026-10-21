// Package relay is a relay server for Identity Agents, speaking the relay
// protocol in identity-bot's ADR-048 through the shared relayproto module.
//
// One process serves one mode, fixed when it starts:
//
//   - private: one unlinkable address per relationship, at
//     https://<apex>/<label>/..., passing only identity artifacts, messages and
//     key registration;
//   - public: one stable address anybody may find, at a claimed name
//     (https://<apex>/<name>/...) or at the identity's own domain, passing
//     every request to the Identity Agent's own gate.
//
// An operator runs the two as separate deployments, each with its own domain,
// database and certificate, so that neither one's records join an identity's
// public name to its relationships.
package relay

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"github.com/grapeid/sp-url-relay/internal/store"
)

// Resolver looks up DNS TXT records. net.DefaultResolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Config is everything a relay is started with.
type Config struct {
	// Mode is public or private, for the life of the process.
	Mode relayproto.Mode
	// Apex is the relay's host name: the address it serves at, and its name in
	// every admission challenge, which an Identity Agent checks against the
	// host it dialled.
	Apex  string
	Store *store.Store
	// Resolver checks custom-domain proofs. Nil means the system resolver.
	Resolver Resolver
	// ReservedNames are names nobody may claim, on top of the built-in list:
	// brand names, say.
	ReservedNames []string
	// PerIdentity is how many names, and separately how many custom domains,
	// one identity may hold. Zero means DefaultPerIdentity.
	PerIdentity int
	// MaxSessions bounds how many Identity Agents are connected at once; zero
	// means the protocol's default.
	MaxSessions int
	Logger      *slog.Logger
	// Now is the relay's clock; nil means time.Now.
	Now func() time.Time
}

const (
	// DefaultPerIdentity is how many names, and how many domains, one
	// identity may hold unless the operator says otherwise.
	DefaultPerIdentity = 3
	// NameHoldBack is how long a released name stays unclaimable by anybody
	// but the identity that released it, so that a name somebody gave up
	// cannot be picked up at once and used to impersonate them.
	NameHoldBack = 90 * 24 * time.Hour
	// ControlRequestsPerMinute bounds signed control requests from one
	// address, so the expensive part (checking a key event log) cannot be
	// driven at will.
	ControlRequestsPerMinute = 60
	// maxControlBody bounds a signed control request.
	maxControlBody = 16 << 10
)

// Server is one relay.
type Server struct {
	cfg      Config
	registry *relayproto.Registry
	service  *relayproto.ServiceConfig
	reserved map[string]bool

	// kelMu orders writes of key event logs, so the record is always the log
	// of the identifier's current session (see recordKEL).
	kelMu sync.Mutex

	// bound maps a private label to the identifier serving it, while that
	// identifier is known to this process. It is never written to disk: a
	// copy of the relay's data must not say whose relationships these are.
	boundMu sync.RWMutex
	bound   map[string]string

	nonces  *nonceCache
	control *relayproto.AllocationLimiter
}

// New makes a relay. It refuses a configuration it cannot serve safely.
func New(cfg Config) (*Server, error) {
	if cfg.Mode != relayproto.ModePublic && cfg.Mode != relayproto.ModePrivate {
		return nil, fmt.Errorf("mode must be %q or %q, not %q", relayproto.ModePublic, relayproto.ModePrivate, cfg.Mode)
	}
	cfg.Apex = strings.ToLower(strings.TrimSpace(cfg.Apex))
	if cfg.Apex == "" {
		return nil, fmt.Errorf("the relay needs its host name (apex)")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("the relay needs a store")
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.PerIdentity <= 0 {
		cfg.PerIdentity = DefaultPerIdentity
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		cfg:      cfg,
		registry: relayproto.NewRegistry(),
		reserved: reservedNames(cfg.ReservedNames),
		bound:    map[string]string{},
		nonces:   newNonceCache(),
		control:  relayproto.NewAllocationLimiter(ControlRequestsPerMinute),
	}
	s.service = &relayproto.ServiceConfig{
		Verifier: &relayproto.Verifier{
			Service: cfg.Apex,
			Enrolled: func(aid string) ([]byte, bool) {
				kel, ok, err := cfg.Store.KEL(aid)
				if err != nil {
					cfg.Logger.Error("read key event log", "aid", aid, "error", err)
					return nil, false
				}
				return kel, ok
			},
		},
		Registry:    s.registry,
		OnAdmit:     s.recordKEL,
		OnRenew:     s.recordKEL,
		MaxSessions: cfg.MaxSessions,
		Logf: func(format string, args ...any) {
			cfg.Logger.Info(fmt.Sprintf(format, args...))
		},
	}
	return s, nil
}

// Mode is the mode this relay serves.
func (s *Server) Mode() relayproto.Mode { return s.cfg.Mode }

// recordKEL stores the key event log of an admission or renewal, but only if
// the session that carries it is still the identifier's own.
//
// The session registry admits a session only if its log extends the one it
// replaces, and calls this only once that session is in place. Two admissions
// for one identifier can still race to this point; writing only the current
// session's log, under one lock, means the older of the two never lands last.
// So the stored log only ever moves forward, as ADR-048 §3.5 requires.
func (s *Server) recordKEL(v *relayproto.Verified) error {
	s.kelMu.Lock()
	defer s.kelMu.Unlock()
	cur, ok := s.registry.Get(v.AID)
	if !ok || !bytes.Equal(cur.KEL(), v.KEL) {
		return nil
	}
	return s.cfg.Store.PutKEL(v.AID, v.KEL)
}

// HostAllowed reports whether the relay may hold a certificate for host: its
// apex, and in public mode a custom domain whose DNS has proved it.
func (s *Server) HostAllowed(host string) bool {
	host = strings.ToLower(host)
	if host == s.cfg.Apex {
		return true
	}
	if s.cfg.Mode != relayproto.ModePublic {
		return false
	}
	d, err := s.cfg.Store.Domain(host)
	return err == nil && d.Verified
}

// ServeHTTP routes one request: to the relay's own endpoints, or to the
// Identity Agent behind the address the request names.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if host != s.cfg.Apex {
		if s.cfg.Mode == relayproto.ModePublic {
			s.forwardDomain(w, r, host)
			return
		}
		http.Error(w, "this relay does not serve that host", http.StatusMisdirectedRequest)
		return
	}
	switch r.URL.Path {
	case "/health":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","mode":%q,"sessions":%d}`, s.cfg.Mode, s.registry.Len())
		return
	case "/.well-known/url-relay-service.json":
		s.handleDescriptor(w, r)
		return
	case "/tunnel":
		// Accept logs and answers every outcome itself.
		relayproto.Accept(w, r, s.service)
		return
	}
	if h, ok := s.controlRoutes()[r.URL.Path]; ok {
		s.handleControl(w, r, h)
		return
	}
	s.forwardPath(w, r)
}

// forwardPath carries a request at https://<apex>/<allocation>/... to the
// Identity Agent holding that allocation, with the allocation segment removed.
func (s *Server) forwardPath(w http.ResponseWriter, r *http.Request) {
	escaped := r.URL.EscapedPath()
	rest := strings.TrimPrefix(escaped, "/")
	seg, tail, _ := strings.Cut(rest, "/")
	tail = "/" + tail
	if seg == "" {
		http.NotFound(w, r)
		return
	}

	var aid string
	switch s.cfg.Mode {
	case relayproto.ModePrivate:
		if !validLabel(seg) {
			http.NotFound(w, r)
			return
		}
		s.boundMu.RLock()
		aid = s.bound[seg]
		s.boundMu.RUnlock()
		if aid == "" {
			if _, err := s.cfg.Store.Allocation(seg); err != nil {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "the Identity Agent at this address is not connected", http.StatusBadGateway)
			return
		}
	case relayproto.ModePublic:
		if !validName(seg) {
			http.NotFound(w, r)
			return
		}
		holder, err := s.cfg.Store.Name(seg)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		aid = holder
		if rest == seg {
			// https://<apex>/<name> serves the same page as .../<name>/, and
			// relative links on it only resolve under the slash.
			http.Redirect(w, r, "/"+seg+"/", http.StatusPermanentRedirect)
			return
		}
	}

	session, ok := s.registry.Get(aid)
	if !ok {
		http.Error(w, "the Identity Agent at this address is not connected", http.StatusBadGateway)
		return
	}
	out := r.Clone(r.Context())
	unescaped, err := url.PathUnescape(tail)
	if err != nil {
		http.Error(w, "malformed path", http.StatusBadRequest)
		return
	}
	out.URL.Path = unescaped
	out.URL.RawPath = ""
	if unescaped != tail {
		out.URL.RawPath = tail
	}
	out.RequestURI = ""
	out.Header.Set("X-Forwarded-Prefix", "/"+seg)
	session.Forward(w, out, relayproto.Preamble{Allocation: seg, Mode: s.cfg.Mode, Host: s.cfg.Apex})
}

// forwardDomain carries a request for a verified custom domain to the
// identity whose domain it is, unchanged.
func (s *Server) forwardDomain(w http.ResponseWriter, r *http.Request, host string) {
	d, err := s.cfg.Store.Domain(host)
	if err != nil || !d.Verified {
		http.Error(w, "this relay does not serve that host", http.StatusMisdirectedRequest)
		return
	}
	session, ok := s.registry.Get(d.AID)
	if !ok {
		http.Error(w, "the Identity Agent at this address is not connected", http.StatusBadGateway)
		return
	}
	r.Header.Del("X-Forwarded-Prefix")
	session.Forward(w, r, relayproto.Preamble{Allocation: host, Mode: relayproto.ModePublic, Host: host})
}

// hostOnly is a request's Host without its port, lower case.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
