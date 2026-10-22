package relay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/grapeid/sp-url-relay/internal/proxylisten"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// --- one origin per name --------------------------------------------------

func TestARelayedResponseCannotReachBeyondItsOwnAddress(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Service-Worker-Allowed", "/")
		w.Header().Add("Set-Cookie", "session=mine; Path=/; Secure")
		w.Header().Add("Set-Cookie", "spread=everyone; Domain="+apex+"; Path=/")
		w.Header().Add("Set-Cookie", "spaced=everyone; domain = ."+apex)
		w.Write([]byte("ok"))
	}))
	h.control(id, "/names/claim", "claim-name", map[string]any{"name": "acme"})

	resp, _ := h.do("GET", "/", "acme."+apex, nil)
	if resp.Header.Get("Service-Worker-Allowed") != "" {
		t.Fatal("a service worker was allowed a wider scope")
	}
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 0 {
		t.Fatalf("cookies passed: %q; the protocol uses none, so none may pass", cookies)
	}
}

// --- the protocol, never a page (ADR-048 §12) -------------------------------

// A browser loading a page at a name gets this relay's visitor page, with the
// operator's link, and the Identity Agent behind the name is never asked; an
// Identity Agent that answers a script with a page has it refused.
func TestANameShowsABrowserTheRelaysPageNeverTheIdentityAgents(t *testing.T) {
	h := newHarnessWith(t, relayproto.ModePublic, func(c *Config) { c.VisitorLink = "https://operator.test/get" })
	id := newIdentity(t)
	var reached atomic.Int32
	h.connect(id, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<form>password</form>"))
	}))
	h.control(id, "/names/claim", "claim-name", map[string]any{"name": "acme"})

	get := func(headers map[string]string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", h.ts.URL+"/", nil)
		req.Host = "acme." + apex
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	resp, body := get(map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `href="https://operator.test/get"`) ||
		strings.Contains(body, "password") || reached.Load() != 0 {
		t.Fatalf("a page load at a name: %d, reached %d, %s", resp.StatusCode, reached.Load(), body)
	}
	resp, body = get(map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"})
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "password") || reached.Load() != 1 {
		t.Fatalf("an Identity Agent's page passed: %d, reached %d, %s", resp.StatusCode, reached.Load(), body)
	}
}

// --- control-request limits -----------------------------------------------

func TestUnsignedRequestsDoNotSpendAnIdentitysAllowance(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	for i := 0; i < controlPerIdentity+5; i++ {
		h.post("/names/claim", []byte("{}"))
	}
	if status, m := h.control(id, "/names/claim", "claim-name", map[string]any{"name": "realname"}); status != 200 {
		t.Fatalf("a signed request after unsigned noise from the same address: %d %v", status, m)
	}
}

func TestAnIdentityIsLimitedOnceVerified(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	limited := false
	for i := 0; i < controlPerIdentity+1; i++ {
		status, _ := h.control(id, "/names/release", "release-name", map[string]any{"name": "nothing-here"})
		if status == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("an identity sent more verified control requests than its allowance")
	}
}

func TestNameClaimsAreLimitedPerAddress(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	limited := false
	for i := 0; i < claimsPerIP+1; i++ {
		if status, _ := h.control(id, "/names/claim", "claim-name", map[string]any{"name": "login"}); status == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("one address made more name claims than allowed")
	}
}

func TestAReleasedNameStillCountsAgainstItsReleaser(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	for _, n := range []string{"brand-a", "brand-b"} {
		h.control(id, "/names/claim", "claim-name", map[string]any{"name": n})
		h.control(id, "/names/release", "release-name", map[string]any{"name": n})
	}
	if status, _ := h.control(id, "/names/claim", "claim-name", map[string]any{"name": "brand-c"}); status != http.StatusForbidden {
		t.Fatalf("claim and release locked up more names than the quota: %d, want 403", status)
	}
}

func TestAControlRequestBodyCannotArriveSlowly(t *testing.T) {
	old := controlReadTimeout
	controlReadTimeout = 300 * time.Millisecond
	defer func() { controlReadTimeout = old }()
	h := newHarness(t, relayproto.ModePublic)
	cfg := h.tlsConfig().Clone()
	cfg.NextProtos = []string{"http/1.1"}
	c, err := tls.Dial("tcp", strings.TrimPrefix(h.ts.URL, "https://"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST /names/claim HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\n{", apex)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 100)); err != nil && strings.Contains(err.Error(), "timeout") {
		t.Fatal("the relay was still waiting for a slow body after three seconds")
	}
}

func TestAReplayedRequestIsRefusedAfterARestart(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	body := signedBody(t, id, "claim-name", map[string]any{"name": "acme"})
	if status, _ := h.post("/names/claim", body); status != 200 {
		t.Fatalf("first: %d", status)
	}
	h.restart()
	h.connect(id, http.HandlerFunc(echo))
	if status, _ := h.post("/names/claim", body); status != http.StatusConflict {
		t.Fatalf("replayed after a restart: %d, want 409", status)
	}
}

func TestTheSignedBytesAreTheRelayProtocolsCanonicalForm(t *testing.T) {
	got, err := canonicalControl(map[string]any{"op": "claim-name", "name": "a<b>&c", "signature": "x", "nonce": "n"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"name":"a<b>&c","nonce":"n","op":"claim-name"}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// --- sessions and streams -------------------------------------------------

func TestOneAddressCannotHoldEverySession(t *testing.T) {
	h := newHarnessWith(t, relayproto.ModePrivate, func(c *Config) { c.SessionsPerIP = 2 })
	h.connect(newIdentity(t), http.HandlerFunc(echo))
	second := h.connect(newIdentity(t), http.HandlerFunc(echo))
	if _, err := relayproto.Dial(context.Background(), h.agentConfig(newIdentity(t))); err == nil {
		t.Fatal("a third session from one address was admitted")
	}
	second.Close()
	h.waitFor(func() bool { h.srv.ipMu.Lock(); defer h.srv.ipMu.Unlock(); return h.srv.perIP["127.0.0.1"] == 1 })
	h.connect(newIdentity(t), http.HandlerFunc(echo))
}

func TestARelayAtItsMemoryLimitAdmitsNobody(t *testing.T) {
	h := newHarnessWith(t, relayproto.ModePrivate, func(c *Config) { c.MemoryLimit = 1 })
	if _, err := relayproto.Dial(context.Background(), h.agentConfig(newIdentity(t))); err == nil {
		t.Fatal("a relay past its memory limit admitted a session")
	}
}

func TestTheRelayHasOneCeilingOnRequestsInFlight(t *testing.T) {
	h := newHarnessWith(t, relayproto.ModePublic, func(c *Config) { c.MaxStreams = 1 })
	id := newIdentity(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h.connect(id, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
	}))
	h.control(id, "/names/claim", "claim-name", map[string]any{"name": "acme"})
	go h.do("GET", "/slow", "acme."+apex, nil)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first request never reached the Identity Agent")
	}
	resp, _ := h.do("GET", "/second", "acme."+apex, nil)
	close(release)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a request past the relay's ceiling: %d, want 503", resp.StatusCode)
	}
}

func TestPrivateAddressesAreLimitedPerIdentity(t *testing.T) {
	h := newHarnessWith(t, relayproto.ModePrivate, func(c *Config) { c.PrivatePerSession = 2 })
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	h.allocate(id)
	h.allocate(id)
	sum := sha256.Sum256([]byte("x"))
	if status, _ := h.control(id, "/allocate", "allocate", map[string]any{"commitment": b64.EncodeToString(sum[:])}); status != http.StatusForbidden {
		t.Fatalf("a third address past the limit: %d, want 403", status)
	}
}

func TestPROXYProtocolGivesTheClientsAddressAndIsRequired(t *testing.T) {
	ln, err := proxylisten.Listen("127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 2)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- clientIP(r) })}
	go srv.Serve(ln)
	defer srv.Close()

	c, _ := net.Dial("tcp", ln.Addr().String())
	hdr := &proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.TCPv4,
		SourceAddr:      &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000},
		DestinationAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}}
	hdr.WriteTo(c)
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := <-seen; got != "203.0.113.9" {
		t.Fatalf("client address %q, want the one the proxy announced", got)
	}
	c.Close()

	direct, _ := net.Dial("tcp", ln.Addr().String())
	defer direct.Close()
	fmt.Fprintf(direct, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	direct.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadAll(direct)
	select {
	case got := <-seen:
		t.Fatalf("a connection without the header was served, as %q", got)
	default:
	}
}

// --- custom domains -------------------------------------------------------

func TestTheProofDecidesWhoHoldsADomain(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	squatter, owner := newIdentity(t), newIdentity(t)
	h.connect(squatter, http.HandlerFunc(echo))
	h.connect(owner, http.HandlerFunc(echo))
	const d = "owner.example.org"
	h.control(squatter, "/domains/request", "request-domain", map[string]any{"domain": d})
	h.resolver.set("_iarelay."+d, "iarelay-aid="+owner.aid)
	if status, m := h.control(owner, "/domains/verify", "verify-domain", map[string]any{"domain": d}); status != 200 {
		t.Fatalf("its real owner, with the proof, was refused: %d %v", status, m)
	}
	if _, m := h.do("GET", "/", d, nil); m["allocation"] != d {
		t.Fatalf("the domain does not reach its owner: %v", m)
	}
	got, _ := h.st.Domain(d)
	if got.AID != owner.aid {
		t.Fatal("the squatter still holds the domain")
	}
}

func TestADomainThatChangesHandsStopsBeingServed(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	const d = "sold.example.org"
	h.resolver.set("_iarelay."+d, "iarelay-aid="+id.aid)
	h.control(id, "/domains/verify", "verify-domain", map[string]any{"domain": d})
	if !h.srv.HostAllowed(d) {
		t.Fatal("setup: not proved")
	}
	h.resolver.mu.Lock()
	delete(h.resolver.records, "_iarelay."+d)
	h.resolver.mu.Unlock()
	for i := 0; i < DomainRecheckFailures; i++ {
		if !h.srv.HostAllowed(d) {
			t.Fatalf("un-proved after %d failed checks; one DNS hiccup should not cut a domain off", i)
		}
		h.srv.RecheckDomains(context.Background())
	}
	if h.srv.HostAllowed(d) {
		t.Fatal("a domain whose proof is gone is still served")
	}
}

func TestDomainChecksAreLimited(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	limited := false
	for i := 0; i < domainChecksPerIdentity+1; i++ {
		if status, _ := h.control(id, "/domains/verify", "verify-domain", map[string]any{"domain": "x.example.org"}); status == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("one identity made unlimited DNS lookups")
	}
}

// --- what a private relay keeps -------------------------------------------

func TestAPrivateRelayLogsNoIdentityBesideItsAddresses(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	a := h.allocate(id)
	h.control(id, "/bind", "bind", map[string]any{"allocation": a.label, "secret": a.secret})
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, "control request") && strings.Contains(line, id.aid) {
			t.Fatalf("a control log line names the identity: %s", line)
		}
	}
	rows := dumpTables(t, h.dbPath)
	for _, cell := range rows["private_allocations"] {
		if _, err := time.Parse(time.RFC3339, cell); err == nil {
			t.Fatalf("an allocation records an exact time: %s", cell)
		}
	}
}

// --- small things ---------------------------------------------------------

func TestRedirectsGoOnlyToHostsTheRelayServes(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	for host, want := range map[string]string{
		"evil.example.net": "https://" + apex + "/path?q=1",
		"acme." + apex:     "https://acme." + apex + "/path?q=1",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://"+host+"/path?q=1", nil)
		h.srv.RedirectToHTTPS(rec, req)
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("from %s: %q, want %q", host, got, want)
		}
	}
}

func TestHealthSaysNothingAboutWhoIsConnected(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	h.connect(newIdentity(t), http.HandlerFunc(echo))
	_, m := h.do("GET", "/health", "", nil)
	if _, ok := m["sessions"]; ok || m["status"] != "ok" {
		t.Fatalf("health: %v", m)
	}
}

func TestTheEarlierSchemasRowsDoNotSurviveInTheFile(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	h.st.Close()
	// Write a schema-1 database in its place, then open it as the relay does.
	os.Remove(h.dbPath)
	os.Remove(h.dbPath + "-wal")
	writeV1(t, h.dbPath)
	h.start()
	for _, f := range []string{h.dbPath, h.dbPath + "-wal"} {
		raw, _ := os.ReadFile(f)
		if strings.Contains(string(raw), "EAIDLINKEDTOALLOCATIONS") {
			t.Fatalf("%s still holds the earlier schema's link between identities and allocations", f)
		}
	}
}

func writeV1(t *testing.T, path string) {
	t.Helper()
	db := openRaw(t, path)
	defer db.Close()
	db.Exec(`CREATE TABLE allocations (token TEXT, enrollment_aid TEXT, pad TEXT)`)
	for i := 0; i < 50; i++ {
		db.Exec(`INSERT INTO allocations VALUES (?, ?, ?)`, fmt.Sprintf("label%03d", i),
			"EAIDLINKEDTOALLOCATIONS", strings.Repeat("x", 200))
	}
	db.Exec(`PRAGMA user_version = 1`)
}

func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestAPrivateAddressPassesNoCookiesOrCredentials(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"cookie":%q,"authorization":%q,"proxy":%q}`,
			r.Header.Get("Cookie"), r.Header.Get("Authorization"), r.Header.Get("Proxy-Authorization"))
	}))
	a := h.allocate(id)
	req, _ := http.NewRequest("POST", h.ts.URL+"/"+a.label+"/didcomm", strings.NewReader("sealed"))
	req.Header.Set("Cookie", "session=from-another-site")
	req.Header.Set("Authorization", "Bearer someone-elses")
	req.Header.Set("Proxy-Authorization", "Basic x")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"cookie":"","authorization":"","proxy":""}` {
		t.Fatalf("the Identity Agent received %s", body)
	}
}
