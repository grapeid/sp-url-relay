// Package relay is a relay server for Identity Agents, speaking the relay
// protocol in identity-bot's ADR-048 through the shared relayproto module.
//
// One process serves one mode, fixed when it starts:
//
//   - private: one unlinkable address per relationship, at
//     https://<apex>/<label>/..., passing only identity artifacts, messages and
//     key registration;
//   - public: one stable address anybody may find, at a claimed name
//     (https://<name>.<apex>/) or at the identity's own domain, passing every
//     request to the Identity Agent's own gate. Each name is its own host, so
//     each is its own browser origin: one name's pages can never read another
//     name's, or set its cookies.
//
// An operator runs the two as separate deployments, each with its own domain,
// database and certificate, so that neither one's records join an identity's
// public name to its relationships.
package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/metrics"
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
	Apex string
	// ConnectHost is the host Identity Agents dial to be admitted, and send
	// control requests to. Empty means Apex. A relay whose caller-facing
	// hosts sit behind a TLS-terminating CDN gives Identity Agents a separate,
	// directly reached host here, because an admission is bound to the TLS
	// connection the Identity Agent itself opened (ADR-048 §10). It must not
	// be a name a caller could claim.
	ConnectHost string
	// OriginPullCAs, when set, requires every connection to a caller-facing
	// host (the apex and public names, never the connect host or a custom
	// domain) to present a client certificate from one of these authorities:
	// the CDN's authenticated origin pulls. Nobody can then bypass the CDN by
	// connecting to the relay's address directly.
	OriginPullCAs *x509.CertPool
	// TrustedProxies are the networks whose connections may say who the
	// client is, in CF-Connecting-IP. A request from anywhere else is taken
	// to come from its TCP peer.
	TrustedProxies []*net.IPNet
	Store          *store.Store
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
	// SessionsPerIP bounds how many Identity Agents one source address may
	// hold connected at once. Zero means DefaultSessionsPerIP.
	SessionsPerIP int
	// MaxStreams bounds the requests in flight through the whole relay. Zero
	// means DefaultMaxStreams.
	MaxStreams int
	// MemoryLimit, when set, is the heap size in bytes past which the relay
	// admits no new session.
	MemoryLimit uint64
	// PrivatePerSession bounds the private allocations one connected identity
	// may hold attached. Zero means DefaultPrivatePerSession.
	PrivatePerSession int
	Logger            *slog.Logger
	// Now is the relay's clock; nil means time.Now.
	Now func() time.Time
}

const (
	// DefaultPerIdentity is how many names, and how many domains, one
	// identity may hold unless the operator says otherwise.
	DefaultPerIdentity = 3
	// DefaultSessionsPerIP is how many Identity Agents one address may keep
	// connected. Generous, for a household or office behind one NAT.
	DefaultSessionsPerIP = 50
	// DefaultMaxStreams is the relay-wide ceiling on requests in flight.
	DefaultMaxStreams = 20000
	// DefaultPrivatePerSession is how many private addresses one connected
	// identity may hold: one per relationship.
	DefaultPrivatePerSession = 2000
	// NameHoldBack is how long a released name stays unclaimable by anybody
	// but the identity that released it, so that a name somebody gave up
	// cannot be picked up at once and used to impersonate them. It counts
	// against the releaser's quota meanwhile.
	NameHoldBack = 90 * 24 * time.Hour
	// DomainPendingFor is how long a custom domain may stay requested but
	// unproved before the request lapses.
	DomainPendingFor = 7 * 24 * time.Hour
	// DomainRecheckEvery is how often proved domains are proved again, and
	// DomainRecheckFailures how many failed checks in a row un-prove one.
	DomainRecheckEvery    = 6 * time.Hour
	DomainRecheckFailures = 3
	// maxControlBody bounds a signed control request.
	maxControlBody = 16 << 10
)

// controlReadTimeout is how long a control request's body may take to
// arrive. A variable so a test can shorten it.
var controlReadTimeout = 10 * time.Second

// Rate limits, per minute.
const (
	// controlPerIP is a loose bound on control requests from one address
	// before anything is verified, so that checking signatures cannot be
	// driven at will.
	controlPerIP = 600
	// controlPerIdentity bounds verified control requests per identity.
	controlPerIdentity = 60
	// claimsPerIP bounds name claims from one address.
	claimsPerIP = 10
	// domainChecksPerIdentity and domainChecksPerRelay bound the DNS lookups
	// verify-domain makes.
	domainChecksPerIdentity = 5
	domainChecksPerRelay    = 120
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
	// identifier is known to this process, and boundCount counts each
	// identifier's labels. Never written to disk: a copy of the relay's data
	// must not say whose relationships these are.
	boundMu    sync.RWMutex
	bound      map[string]string
	boundCount map[string]int

	// perIP counts the sessions each source address holds, or is being
	// admitted for.
	ipMu  sync.Mutex
	perIP map[string]int

	// streams is the relay-wide ceiling on requests in flight.
	streams chan struct{}

	// domainFailures counts consecutive failed re-checks per proved domain.
	domainFailures map[string]int

	controlIP     *relayproto.AllocationLimiter
	controlID     *relayproto.AllocationLimiter
	claimIP       *relayproto.AllocationLimiter
	domainCheckID *relayproto.AllocationLimiter
	domainCheck   *relayproto.AllocationLimiter
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
	cfg.ConnectHost = strings.ToLower(strings.TrimSpace(cfg.ConnectHost))
	if cfg.ConnectHost == "" {
		cfg.ConnectHost = cfg.Apex
	}
	if cfg.OriginPullCAs != nil && cfg.ConnectHost == cfg.Apex {
		return nil, fmt.Errorf("origin pulls need a separate connect host: Identity Agents cannot present the CDN's client certificate")
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.PerIdentity <= 0 {
		cfg.PerIdentity = DefaultPerIdentity
	}
	if cfg.SessionsPerIP <= 0 {
		cfg.SessionsPerIP = DefaultSessionsPerIP
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = DefaultMaxStreams
	}
	if cfg.PrivatePerSession <= 0 {
		cfg.PrivatePerSession = DefaultPrivatePerSession
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		cfg:            cfg,
		registry:       relayproto.NewRegistry(),
		reserved:       reservedNames(append(cfg.ReservedNames, strings.TrimSuffix(cfg.ConnectHost, "."+cfg.Apex))),
		bound:          map[string]string{},
		boundCount:     map[string]int{},
		perIP:          map[string]int{},
		streams:        make(chan struct{}, cfg.MaxStreams),
		domainFailures: map[string]int{},
		controlIP:      relayproto.NewAllocationLimiter(controlPerIP),
		controlID:      relayproto.NewAllocationLimiter(controlPerIdentity),
		claimIP:        relayproto.NewAllocationLimiter(claimsPerIP),
		domainCheckID:  relayproto.NewAllocationLimiter(domainChecksPerIdentity),
		domainCheck:    relayproto.NewAllocationLimiter(domainChecksPerRelay),
	}
	s.service = &relayproto.ServiceConfig{
		Verifier: &relayproto.Verifier{
			Service: cfg.ConnectHost,
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
		Budget:      s.memoryBudget,
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

var heapSample = []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
var heapMu sync.Mutex

// memoryBudget refuses a new session once the heap is past the relay's
// memory limit. Every session may hold up to MaxStreamsPerSession ×
// StreamWindowBytes in flight, so the count of sessions alone is not a memory
// bound.
func (s *Server) memoryBudget() error {
	if s.cfg.MemoryLimit == 0 {
		return nil
	}
	heapMu.Lock()
	metrics.Read(heapSample)
	used := heapSample[0].Value.Uint64()
	heapMu.Unlock()
	if used > s.cfg.MemoryLimit {
		return fmt.Errorf("the relay is at its memory limit")
	}
	return nil
}

// nameOf returns the name a host serves, when host is <name>.<apex> on a
// public relay.
func (s *Server) nameOf(host string) string {
	if s.cfg.Mode != relayproto.ModePublic {
		return ""
	}
	name, ok := strings.CutSuffix(host, "."+s.cfg.Apex)
	if !ok || !relayproto.ValidName(name) {
		return ""
	}
	return name
}

func (s *Server) verifiedDomain(host string) bool {
	d, err := s.cfg.Store.Domain(host)
	return err == nil && d.Verified
}

// HostAllowed reports whether the relay serves host: its apex, and on a
// public relay any <name>.<apex> and every proved custom domain.
func (s *Server) HostAllowed(host string) bool {
	host = strings.ToLower(host)
	if host == s.cfg.Apex || host == s.cfg.ConnectHost {
		return true
	}
	if s.cfg.Mode != relayproto.ModePublic {
		return false
	}
	return s.nameOf(host) != "" || s.verifiedDomain(host)
}

// RedirectToHTTPS answers a plain-HTTP request with the HTTPS address of the
// same resource, on a host this relay serves, never a host the caller chose.
func (s *Server) RedirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if !s.HostAllowed(host) {
		host = s.cfg.Apex
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
}

// ServeHTTP routes one request by the host it names:
//
//   - the connect host serves Identity Agents: admission, control requests
//     and the descriptor;
//   - caller-facing hosts (the apex and public names) carry callers'
//     requests to Identity Agents, and nothing else;
//   - a proved custom domain is caller-facing too, but reached directly.
//
// When the connect host is the apex, the apex serves both.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if host == s.cfg.ConnectHost && s.serveConnect(w, r) {
		return
	}
	if host != s.cfg.Apex && s.nameOf(host) == "" {
		if host != s.cfg.ConnectHost && s.cfg.Mode == relayproto.ModePublic {
			s.forwardDomain(w, r, host)
			return
		}
		if host != s.cfg.ConnectHost {
			http.Error(w, "this relay does not serve that host", http.StatusMisdirectedRequest)
			return
		}
		http.NotFound(w, r)
		return
	}
	// A caller-facing host. Behind a CDN, only the CDN may reach it.
	if !s.originPulled(r) {
		http.Error(w, "this host is reached only through its CDN", http.StatusForbidden)
		return
	}
	if name := s.nameOf(host); name != "" {
		s.forwardName(w, r, name, host)
		return
	}
	switch r.URL.Path {
	case "/health":
		s.handleHealth(w)
		return
	case "/.well-known/url-relay-service.json":
		s.handleDescriptor(w, r)
		return
	}
	if s.cfg.Mode == relayproto.ModePrivate {
		s.forwardLabel(w, r)
		return
	}
	http.NotFound(w, r)
}

// serveConnect answers what the connect host serves, reporting whether it
// did.
func (s *Server) serveConnect(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/health":
		s.handleHealth(w)
	case "/.well-known/url-relay-service.json":
		s.handleDescriptor(w, r)
	case "/tunnel":
		s.handleTunnel(w, r)
	default:
		h, ok := s.controlRoutes()[r.URL.Path]
		if !ok {
			return false
		}
		s.handleControl(w, r, h)
	}
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","mode":%q}`, s.cfg.Mode)
}

// callerFacing reports whether host is one callers reach through the CDN:
// the apex, when it is not also the connect host, and every public name.
func (s *Server) callerFacing(host string) bool {
	if host == s.cfg.ConnectHost {
		return false
	}
	return host == s.cfg.Apex || s.nameOf(host) != ""
}

// originPulled reports whether a request to a caller-facing host came through
// the CDN: always true when origin pulls are off.
func (s *Server) originPulled(r *http.Request) bool {
	if s.cfg.OriginPullCAs == nil || !s.callerFacing(hostOnly(r.Host)) {
		return true
	}
	return r.TLS != nil && len(r.TLS.VerifiedChains) > 0
}

// handleTunnel admits an Identity Agent, holding to the per-address cap.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	s.ipMu.Lock()
	if s.perIP[ip] >= s.cfg.SessionsPerIP {
		s.ipMu.Unlock()
		s.cfg.Logger.Info("relay admission refused", "ip", ip, "reason", "too many sessions from this address")
		http.Error(w, "too many Identity Agents connected from this address", http.StatusTooManyRequests)
		return
	}
	s.perIP[ip]++
	s.ipMu.Unlock()
	release := func() {
		s.ipMu.Lock()
		if s.perIP[ip]--; s.perIP[ip] <= 0 {
			delete(s.perIP, ip)
		}
		s.ipMu.Unlock()
	}
	// Accept logs and answers every outcome itself.
	session, err := relayproto.Accept(w, r, s.service)
	if err != nil {
		release()
		return
	}
	go func() {
		<-session.Done()
		release()
	}()
}

// forwardLabel carries a request at https://<apex>/<label>/... on a private
// relay to the Identity Agent holding that label, with the label removed.
func (s *Server) forwardLabel(w http.ResponseWriter, r *http.Request) {
	escaped := r.URL.EscapedPath()
	seg, tail, _ := strings.Cut(strings.TrimPrefix(escaped, "/"), "/")
	tail = "/" + tail
	if !validLabel(seg) {
		http.NotFound(w, r)
		return
	}
	s.boundMu.RLock()
	aid := s.bound[seg]
	s.boundMu.RUnlock()
	if aid == "" {
		if _, err := s.cfg.Store.Allocation(seg); err != nil {
			http.NotFound(w, r)
			return
		}
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
	// A private address serves artifacts, messages and key registration, none
	// of which use cookies or credentials. Never pass a caller's: a browser
	// sends cookies for the whole site, and until each name under a shared
	// parent domain is its own site, one set elsewhere could reach here.
	for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization"} {
		out.Header.Del(h)
	}
	out.Header.Set("X-Forwarded-Prefix", "/"+seg)
	s.forward(w, out, aid, relayproto.Preamble{Allocation: seg, Mode: relayproto.ModePrivate, Host: s.cfg.Apex})
}

// forwardName carries a request for https://<name>.<apex>/ to the identity
// holding the name, unchanged.
func (s *Server) forwardName(w http.ResponseWriter, r *http.Request, name, host string) {
	aid, err := s.cfg.Store.Name(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	r.Header.Del("X-Forwarded-Prefix")
	s.forward(w, r, aid, relayproto.Preamble{Allocation: name, Mode: relayproto.ModePublic, Host: host})
}

// forwardDomain carries a request for a proved custom domain to the identity
// whose domain it is, unchanged.
func (s *Server) forwardDomain(w http.ResponseWriter, r *http.Request, host string) {
	d, err := s.cfg.Store.Domain(host)
	if err != nil || !d.Verified {
		http.Error(w, "this relay does not serve that host", http.StatusMisdirectedRequest)
		return
	}
	r.Header.Del("X-Forwarded-Prefix")
	s.forward(w, r, d.AID, relayproto.Preamble{Allocation: host, Mode: relayproto.ModePublic, Host: host})
}

// forward hands one request to the identifier's session, within the
// relay-wide ceiling on requests in flight, and filters what comes back.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, aid string, p relayproto.Preamble) {
	session, ok := s.registry.Get(aid)
	if !ok {
		http.Error(w, "the Identity Agent at this address is not connected", http.StatusBadGateway)
		return
	}
	select {
	case s.streams <- struct{}{}:
		defer func() { <-s.streams }()
	default:
		http.Error(w, "the relay is busy", http.StatusServiceUnavailable)
		return
	}
	session.Forward(&responseFilter{ResponseWriter: w}, r, p)
}

// clientIP is the address a request came from. With PROXY protocol enabled
// the listener has already replaced the platform proxy's address with the
// client's. A request from a trusted proxy (the CDN in front of caller-facing
// hosts) names its client in CF-Connecting-IP; from anywhere else that header
// is ignored, since anybody can send it.
func (s *Server) clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	ip := net.ParseIP(peer)
	if ip == nil || len(s.cfg.TrustedProxies) == 0 {
		return peer
	}
	for _, n := range s.cfg.TrustedProxies {
		if n.Contains(ip) {
			if c := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); c != nil {
				return c.String()
			}
			return peer
		}
	}
	return peer
}

// clientIP without a server: the TCP peer.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// hostOnly is a request's Host without its port, lower case.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// RecheckDomains proves every proved domain again, and un-proves one whose
// proof has failed DomainRecheckFailures times in a row: a domain that has
// changed hands stops reaching its old holder.
func (s *Server) RecheckDomains(ctx context.Context) {
	domains, err := s.cfg.Store.VerifiedDomains()
	if err != nil {
		s.cfg.Logger.Error("list proved domains", "error", err)
		return
	}
	for _, d := range domains {
		if s.proves(ctx, d.Domain, d.AID) {
			delete(s.domainFailures, d.Domain)
			continue
		}
		s.domainFailures[d.Domain]++
		if s.domainFailures[d.Domain] < DomainRecheckFailures {
			continue
		}
		delete(s.domainFailures, d.Domain)
		if err := s.cfg.Store.UnverifyDomain(d.Domain); err != nil {
			s.cfg.Logger.Error("un-prove a domain", "domain", d.Domain, "error", err)
			continue
		}
		s.cfg.Logger.Info("domain no longer proved; stopped serving it", "domain", d.Domain, "aid", d.AID)
	}
}

// KeepDomainsProved re-checks proved domains until ctx ends.
func (s *Server) KeepDomainsProved(ctx context.Context) {
	if s.cfg.Mode != relayproto.ModePublic {
		return
	}
	t := time.NewTicker(DomainRecheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RecheckDomains(ctx)
		}
	}
}

// proves reports whether the domain's DNS currently binds it to aid.
func (s *Server) proves(ctx context.Context, domain, aid string) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	records, err := s.cfg.Resolver.LookupTXT(ctx, txtName(domain))
	if err != nil {
		return false
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == txtValue(aid) {
			return true
		}
	}
	return false
}

// responseFilter removes what a relayed response could use to reach beyond
// its own address: a cookie scoped to a parent domain, and a service worker
// allowed a wider scope than its own path. Each public name is already its
// own origin; this is defence in depth.
type responseFilter struct {
	http.ResponseWriter
	done bool
}

func (f *responseFilter) filter() {
	if f.done {
		return
	}
	f.done = true
	h := f.ResponseWriter.Header()
	h.Del("Service-Worker-Allowed")
	if cookies := h.Values("Set-Cookie"); len(cookies) > 0 {
		h.Del("Set-Cookie")
		for _, c := range cookies {
			parsed, err := http.ParseSetCookie(c)
			if err != nil || parsed.Domain != "" {
				continue
			}
			h.Add("Set-Cookie", c)
		}
	}
}

func (f *responseFilter) WriteHeader(code int) {
	f.filter()
	f.ResponseWriter.WriteHeader(code)
}

func (f *responseFilter) Write(b []byte) (int, error) {
	f.filter()
	return f.ResponseWriter.Write(b)
}

// Hijack is how a websocket upgrade takes the connection; the upgrade
// response's headers are written from the same header map after it.
func (f *responseFilter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.filter()
	h, ok := f.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking is not supported")
	}
	return h.Hijack()
}

func (f *responseFilter) Flush() {
	f.filter()
	http.NewResponseController(f.ResponseWriter).Flush()
}

func (f *responseFilter) Unwrap() http.ResponseWriter { return f.ResponseWriter }
