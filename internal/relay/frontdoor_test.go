package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"github.com/grapeid/sp-url-relay/internal/store"
)

// --- two front doors ------------------------------------------------------

// With a separate connect host, Identity Agents are admitted and send control
// requests only there, and callers reach addresses only at the caller-facing
// hosts.
func TestTheConnectHostAndTheCallerHostsServeOnlyTheirOwn(t *testing.T) {
	h := newHarnessWith(t, relayproto.ModePrivate, func(c *Config) {
		c.Apex, c.ConnectHost = "relay.test", apex
	})
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	a := h.allocate(id)

	if resp, m := h.do("GET", "/"+a.label+"/"+id.aid+"/did.json", "relay.test", nil); resp.StatusCode != 200 || m["host"] != "relay.test" {
		t.Fatalf("a caller at the caller-facing host: %d %v", resp.StatusCode, m)
	}
	if resp, _ := h.do("GET", "/"+a.label+"/"+id.aid+"/did.json", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a caller's request at the connect host: %d, want 404", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/tunnel", "relay.test", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the session endpoint at the caller-facing host: %d, want 404", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", h.ts.URL+"/allocate", strings.NewReader(string(signedBody(t, id, "allocate", map[string]any{"commitment": a.secret}))))
	req.Host = "relay.test"
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a control request at the caller-facing host: %d, want 404", resp.StatusCode)
	}
}

func TestTheConnectHostsNameCannotBeClaimed(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "r.db"))
	defer st.Close()
	s, err := New(Config{Mode: relayproto.ModePublic, Apex: "relay.test", ConnectHost: "door.relay.test", Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if !s.reserved["door"] || !s.reserved["connect"] {
		t.Fatal("a caller could claim the connect host's name and stand in front of every Identity Agent's session")
	}
}

func TestTheDescriptorPutsEverythingAnIdentityAgentUsesAtTheConnectHost(t *testing.T) {
	for _, mode := range []relayproto.Mode{relayproto.ModePublic, relayproto.ModePrivate} {
		st, _ := store.Open(filepath.Join(t.TempDir(), "r.db"))
		s, err := New(Config{Mode: mode, Apex: "relay.example", ConnectHost: "connect.relay.example", Store: st})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		s.handleDescriptor(rec, httptest.NewRequest("GET", "/.well-known/url-relay-service.json", nil))
		st.Close()

		golden := filepath.Join("testdata", "descriptor."+string(mode)+".json")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			os.WriteFile(golden, rec.Body.Bytes(), 0o644)
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if !jsonEqual(t, rec.Body.Bytes(), want) {
			t.Fatalf("%s descriptor changed:\n%s\nwant:\n%s", mode, rec.Body.Bytes(), want)
		}

		// What the Identity Agent's client checks (ADR-048 §8).
		var d struct {
			Protocol, Service, ConnectHost, TunnelEndpoint string
			Endpoints                                      map[string]string
		}
		var raw map[string]any
		json.Unmarshal(rec.Body.Bytes(), &raw)
		d.Protocol, _ = raw["protocol"].(string)
		d.Service, _ = raw["service"].(string)
		d.ConnectHost, _ = raw["connect_host"].(string)
		d.TunnelEndpoint, _ = raw["tunnel_endpoint"].(string)
		for k, v := range raw["endpoints"].(map[string]any) {
			if d.Endpoints == nil {
				d.Endpoints = map[string]string{}
			}
			d.Endpoints[k] = v.(string)
		}
		if d.Protocol != relayproto.ProtocolVersion || d.Service != d.ConnectHost ||
			!strings.HasSuffix(d.ConnectHost, ".relay.example") {
			t.Fatalf("%s: %+v", mode, d)
		}
		if u, _ := url.Parse(d.TunnelEndpoint); u.Scheme != "wss" || u.Host != d.ConnectHost {
			t.Fatalf("%s: session endpoint %q is not at the connect host", mode, d.TunnelEndpoint)
		}
		for op, ep := range d.Endpoints {
			if u, _ := url.Parse(ep); u.Scheme != "https" || u.Host != d.ConnectHost {
				t.Fatalf("%s: %s endpoint %q is not at the connect host", mode, op, ep)
			}
		}
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return string(ja) == string(jb)
}

// The Identity Agent's client reads a refusal's "error" code.
func TestRefusalsCarryTheCodesTheClientReads(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	owner, other := newIdentity(t), newIdentity(t)
	h.connect(owner, http.HandlerFunc(echo))
	h.connect(other, http.HandlerFunc(echo))
	h.control(owner, "/names/claim", "claim-name", map[string]any{"name": "acme"})
	h.control(owner, "/names/claim", "claim-name", map[string]any{"name": "acme-two"})
	for _, c := range []struct {
		who  *identity
		name string
		want string
	}{
		{other, "acme", "taken"},
		{other, "login", "reserved"},
		{owner, "acme-three", "quota"},
		{other, "No", "invalid_name"},
	} {
		status, m := h.control(c.who, "/names/claim", "claim-name", map[string]any{"name": c.name})
		if status == 200 || m["error"] != c.want || m["message"] == "" || len(m) != 2 {
			t.Errorf("claim %q: %d %v, want error %q with a message", c.name, status, m, c.want)
		}
	}
	h.control(other, "/domains/request", "request-domain", map[string]any{"domain": "x.example.org"})
	if _, m := h.control(other, "/domains/verify", "verify-domain", map[string]any{"domain": "x.example.org"}); m["error"] != "unproven" {
		t.Errorf("verify without proof: %v", m)
	}
}

// --- behind a CDN ---------------------------------------------------------

func TestACallerFacingHostIsReachedOnlyThroughTheCDN(t *testing.T) {
	serverCA, serverCAKey := newCA(t, "test server CA")
	pullCA, pullCAKey := newCA(t, "test origin-pull CA")
	strangerCA, strangerCAKey := newCA(t, "somebody else")
	serverCert := leaf(t, serverCA, serverCAKey, false,
		"relay.test", "*.relay.test", "connect.relay.test", "owner.example.org")

	st, _ := store.Open(filepath.Join(t.TempDir(), "r.db"))
	defer st.Close()
	pool := x509.NewCertPool()
	pool.AddCert(pullCA)
	srv, err := New(Config{Mode: relayproto.ModePublic, Apex: "relay.test", ConnectHost: "connect.relay.test",
		OriginPullCAs: pool, Store: st, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = srv.WithOriginPulls(&tls.Config{Certificates: []tls.Certificate{serverCert}})
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(serverCA)

	get := func(sni, host string, client *tls.Certificate) (int, error) {
		cfg := &tls.Config{RootCAs: roots, ServerName: sni}
		if client != nil {
			cfg.Certificates = []tls.Certificate{*client}
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		req, _ := http.NewRequest("GET", ts.URL+"/health", nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	cdn := leaf(t, pullCA, pullCAKey, true, "origin-pull")
	stranger := leaf(t, strangerCA, strangerCAKey, true, "origin-pull")

	if _, err := get("relay.test", "relay.test", nil); err == nil {
		t.Fatal("a caller-facing host answered a connection with no CDN certificate")
	}
	if _, err := get("acme.relay.test", "acme.relay.test", &stranger); err == nil {
		t.Fatal("a caller-facing host answered a certificate the CDN did not issue")
	}
	if status, err := get("relay.test", "relay.test", &cdn); err != nil || status != 200 {
		t.Fatalf("through the CDN: %d %v", status, err)
	}
	if status, err := get("connect.relay.test", "connect.relay.test", nil); err != nil || status != 200 {
		t.Fatalf("Identity Agents reach the connect host directly: %d %v", status, err)
	}
	if status, err := get("connect.relay.test", "relay.test", nil); err != nil || status != http.StatusForbidden {
		t.Fatalf("a caller-facing request carried in under the connect host's SNI: %d %v, want 403", status, err)
	}
	if _, err := get("owner.example.org", "owner.example.org", nil); err != nil {
		t.Fatalf("a custom domain is reached directly, with no CDN certificate: %v", err)
	}
}

func TestOriginPullsNeedASeparateConnectHost(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "r.db"))
	defer st.Close()
	if _, err := New(Config{Mode: relayproto.ModePrivate, Apex: "relay.test", OriginPullCAs: x509.NewCertPool(), Store: st}); err == nil {
		t.Fatal("origin pulls were required on the host Identity Agents connect to")
	}
}

func TestOnlyTheCDNMayNameTheClient(t *testing.T) {
	_, cdn, _ := net.ParseCIDR("10.0.0.0/8")
	s := &Server{cfg: Config{TrustedProxies: []*net.IPNet{cdn}}}
	for _, c := range []struct{ peer, header, want string }{
		{"10.1.2.3:443", "203.0.113.7", "203.0.113.7"},
		{"198.51.100.1:443", "203.0.113.7", "198.51.100.1"},
		{"10.1.2.3:443", "not-an-address", "10.1.2.3"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		r.Header.Set("CF-Connecting-IP", c.header)
		if got := s.clientIP(r); got != c.want {
			t.Errorf("peer %s with header %s: %s, want %s", c.peer, c.header, got, c.want)
		}
	}
}

func TestTheCDNsRangesAndAuthorityAreRead(t *testing.T) {
	dir := t.TempDir()
	ranges := filepath.Join(dir, "ranges")
	os.WriteFile(ranges, []byte("# published ranges\n173.245.48.0/20\n\n2400:cb00::/32 # v6\n"), 0o644)
	nets, err := LoadNetworks(ranges)
	if err != nil || len(nets) != 2 {
		t.Fatalf("%v %v", nets, err)
	}
	os.WriteFile(ranges, []byte("not a range\n"), 0o644)
	if _, err := LoadNetworks(ranges); err == nil {
		t.Fatal("a malformed range was accepted")
	}
	if _, err := LoadCertPool(ranges); err == nil {
		t.Fatal("a file with no certificate was accepted as an authority")
	}
}

// --- certificates for tests -----------------------------------------------

func newCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func leaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: names}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A private relay behind a CDN obtains its apex and its connect host by
// DNS-01; a public relay's wildcard covers a connect host one level down.
func TestEachRelayAsksForTheCertificateItsHostsNeed(t *testing.T) {
	for _, c := range []struct {
		mode          relayproto.Mode
		apex, connect string
		want          []string
	}{
		{relayproto.ModePrivate, "relay.grapeid.example", "connect.relay.grapeid.example",
			[]string{"relay.grapeid.example", "connect.relay.grapeid.example"}},
		{relayproto.ModePublic, "grapeid.example", "connect.grapeid.example",
			[]string{"grapeid.example", "*.grapeid.example"}},
	} {
		st, _ := store.Open(filepath.Join(t.TempDir(), "r.db"))
		s, err := New(Config{Mode: c.mode, Apex: c.apex, ConnectHost: c.connect, Store: st})
		st.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got := s.ownDomains(); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v, want %v", c.mode, got, c.want)
		}
	}
}
