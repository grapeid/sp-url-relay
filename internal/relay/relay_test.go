package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"github.com/grapeid/sp-url-relay/internal/store"
)

// --- an Identity Agent's identity ----------------------------------------

type identity struct {
	t        *testing.T
	mu       sync.Mutex
	aid      string
	current  *keri.SoftwareSigner
	next     *keri.SoftwareSigner
	lastSAID string
	sn       int
	messages [][]byte
}

func newIdentity(t *testing.T) *identity {
	t.Helper()
	cur, _ := keri.GenerateSigner(true)
	nxt, _ := keri.GenerateSigner(true)
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, err := keri.NextDigest(npub)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd},
		Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, cur)
	if err != nil {
		t.Fatal(err)
	}
	return &identity{t: t, aid: parsed.Identifier, current: cur, next: nxt,
		lastSAID: parsed.SAID, messages: [][]byte{signed.Message}}
}

func (id *identity) kel() []byte {
	id.mu.Lock()
	defer id.mu.Unlock()
	out, err := keri.ExportKEL(id.messages)
	if err != nil {
		id.t.Fatal(err)
	}
	return out
}

func (id *identity) Sign(data []byte) ([]byte, error) {
	id.mu.Lock()
	s := id.current
	id.mu.Unlock()
	return s.Sign(data)
}

// snapshot is the identity as it stands now: what somebody who copied its
// key and log today would hold after it rotates away from them.
func (id *identity) snapshot() *identity {
	id.mu.Lock()
	defer id.mu.Unlock()
	return &identity{t: id.t, aid: id.aid, current: id.current, next: id.next,
		lastSAID: id.lastSAID, sn: id.sn, messages: append([][]byte(nil), id.messages...)}
}

func (id *identity) rotate() {
	id.mu.Lock()
	defer id.mu.Unlock()
	newNext, _ := keri.GenerateSigner(true)
	pub, _ := id.next.PublicKey()
	npub, _ := newNext.PublicKey()
	nd, _ := keri.NextDigest(npub)
	ev, err := keri.BuildRotation(keri.RotationInput{Prefix: id.aid, Keys: []string{pub},
		PriorSAID: id.lastSAID, SN: id.sn + 1, NextDigests: []string{nd}})
	if err != nil {
		id.t.Fatal(err)
	}
	signed, err := keri.SignEvent(ev, id.next)
	if err != nil {
		id.t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	id.sn++
	id.lastSAID = parsed.SAID
	id.current, id.next = id.next, newNext
	id.messages = append(id.messages, signed.Message)
}

// --- a relay under test ---------------------------------------------------

type fakeResolver struct {
	mu      sync.Mutex
	records map[string][]string
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.records[name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("no such record")
}

func (f *fakeResolver) set(name, value string) {
	f.mu.Lock()
	f.records[name] = []string{value}
	f.mu.Unlock()
}

type harness struct {
	t        *testing.T
	tweak    func(*Config)
	logs     *syncBuffer
	mode     relayproto.Mode
	dbPath   string
	st       *store.Store
	srv      *Server
	ts       *httptest.Server
	resolver *fakeResolver
	client   *http.Client
}

const apex = "127.0.0.1"

func newHarness(t *testing.T, mode relayproto.Mode) *harness {
	return newHarnessWith(t, mode, nil)
}

// newHarnessWith starts a relay whose configuration tweak adjusts.
func newHarnessWith(t *testing.T, mode relayproto.Mode, tweak func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, mode: mode, dbPath: filepath.Join(t.TempDir(), "relay.db"),
		resolver: &fakeResolver{records: map[string][]string{}}, tweak: tweak, logs: &syncBuffer{}}
	h.start()
	return h
}

// syncBuffer collects the relay's log lines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// start runs a relay on the harness's database: called again, it is the same
// relay after a restart.
func (h *harness) start() {
	h.t.Helper()
	st, err := store.Open(h.dbPath)
	if err != nil {
		h.t.Fatal(err)
	}
	cfg := Config{Mode: h.mode, Apex: apex, Store: st, Resolver: h.resolver,
		ReservedNames: []string{"examplebrand"}, PerIdentity: 2,
		Logger: slog.New(slog.NewTextHandler(h.logs, nil))}
	if h.tweak != nil {
		h.tweak(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	h.st, h.srv, h.ts, h.client = st, srv, ts, ts.Client()
	h.t.Cleanup(func() { ts.Close(); st.Close() })
}

// restart stops the relay and starts it again on the same database.
func (h *harness) restart() {
	h.ts.CloseClientConnections()
	h.ts.Close()
	h.st.Close()
	h.start()
}

func (h *harness) tlsConfig() *tls.Config {
	return h.client.Transport.(*http.Transport).TLSClientConfig
}

func (h *harness) agentConfig(id *identity) *relayproto.AgentConfig {
	return &relayproto.AgentConfig{
		URL: "wss" + strings.TrimPrefix(h.ts.URL, "https") + "/tunnel",
		AID: id.aid, KEL: id.kel, Signer: id, TLS: h.tlsConfig(),
	}
}

// connect admits id and serves handler on its session.
func (h *harness) connect(id *identity, handler http.Handler) *relayproto.AgentSession {
	h.t.Helper()
	a, err := relayproto.Dial(context.Background(), h.agentConfig(id))
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	go a.Serve(handler)
	h.t.Cleanup(func() { a.Close() })
	h.waitFor(func() bool { s, ok := h.srv.registry.Get(id.aid); return ok && s.ID == a.ID })
	return a
}

func (h *harness) waitFor(cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func randomString() string {
	b := make([]byte, 16)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// signedBody builds a control request signed by id.
func signedBody(t *testing.T, id *identity, op string, fields map[string]any) []byte {
	t.Helper()
	m := map[string]any{"op": op, "relay": apex, "signed_by": id.aid,
		"t": time.Now().UTC().Format(time.RFC3339), "nonce": randomString()}
	for k, v := range fields {
		m[k] = v
	}
	body, err := canonicalControl(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	m["signature"] = b64.EncodeToString(sig)
	out, _ := json.Marshal(m)
	return out
}

func (h *harness) post(path string, body []byte) (int, map[string]any) {
	h.t.Helper()
	resp, err := h.client.Post(h.ts.URL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (h *harness) control(id *identity, path, op string, fields map[string]any) (int, map[string]any) {
	h.t.Helper()
	return h.post(path, signedBody(h.t, id, op, fields))
}

func (h *harness) do(method, path, host string, body io.Reader) (*http.Response, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.ts.URL+path, body)
	if host != "" {
		req.Host = host
	}
	client := *h.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &m)
	return resp, m
}

// echo reports what the Identity Agent saw of a request.
func echo(w http.ResponseWriter, r *http.Request) {
	p, ok := relayproto.PreambleFrom(r.Context())
	body, _ := io.ReadAll(r.Body)
	json.NewEncoder(w).Encode(map[string]any{
		"method": r.Method, "path": r.URL.Path, "query": r.URL.RawQuery, "body": string(body),
		"relayed": ok, "allocation": p.Allocation, "host": r.Host,
		"prefix": r.Header.Get("X-Forwarded-Prefix"), "via": r.Header.Get(relayproto.ViaRelayHeader),
	})
}

// allocation is a private allocation and the secret that proves it.
type allocation struct {
	label  string
	secret string
}

func (h *harness) allocate(id *identity) allocation {
	h.t.Helper()
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	status, m := h.control(id, "/allocate", "allocate", map[string]any{"commitment": b64.EncodeToString(sum[:])})
	if status != http.StatusOK {
		h.t.Fatalf("allocate: %d %v", status, m)
	}
	return allocation{label: m["allocation"].(string), secret: b64.EncodeToString(secret)}
}

// --- private --------------------------------------------------------------

func TestAPrivateAddressPassesArtifactsAndMessagesOnly(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	a := h.allocate(id)

	resp, m := h.do("GET", "/"+a.label+"/"+id.aid+"/did.json", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("artifact: %d", resp.StatusCode)
	}
	if m["path"] != "/"+id.aid+"/did.json" || m["allocation"] != a.label || m["prefix"] != "/"+a.label ||
		m["via"] != "relay" || m["relayed"] != true {
		t.Fatalf("the Identity Agent saw %v", m)
	}

	resp, m = h.do("POST", "/"+a.label+"/didcomm", "", strings.NewReader("sealed"))
	if resp.StatusCode != 200 || m["body"] != "sealed" {
		t.Fatalf("message: %d %v", resp.StatusCode, m)
	}

	for _, refused := range []struct{ method, path string }{
		{"GET", "/" + a.label + "/api/settings"},
		{"GET", "/" + a.label + "/" + id.aid + "/did.json/"},
		{"POST", "/" + a.label + "/" + id.aid + "/did.json"},
		{"GET", "/" + a.label + "/%2F" + id.aid + "/did.json"},
	} {
		if resp, _ := h.do(refused.method, refused.path, "", nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", refused.method, refused.path, resp.StatusCode)
		}
	}
}

func TestAnAddressSurvivesAReconnectAndARestart(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	first := h.connect(id, http.HandlerFunc(echo))
	a := h.allocate(id)
	path := "/" + a.label + "/" + id.aid + "/did.json"

	first.Close()
	h.connect(id, http.HandlerFunc(echo))
	if resp, _ := h.do("GET", path, "", nil); resp.StatusCode != 200 {
		t.Fatalf("after a reconnect: %d", resp.StatusCode)
	}

	h.restart()
	h.connect(id, http.HandlerFunc(echo))
	if resp, _ := h.do("GET", path, "", nil); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("a restarted relay knows the label but not whose it is: got %d, want 502", resp.StatusCode)
	}

	other := newIdentity(t)
	h.connect(other, http.HandlerFunc(echo))
	if status, _ := h.control(other, "/bind", "bind", map[string]any{"allocation": a.label, "secret": randomString() + randomString()}); status != http.StatusForbidden {
		t.Fatalf("another identity bound the label without its secret: %d", status)
	}
	if status, m := h.control(id, "/bind", "bind", map[string]any{"allocation": a.label, "secret": a.secret}); status != 200 {
		t.Fatalf("bind: %d %v", status, m)
	}
	if resp, _ := h.do("GET", path, "", nil); resp.StatusCode != 200 {
		t.Fatalf("after binding again: %d", resp.StatusCode)
	}

	if status, _ := h.control(id, "/release", "release", map[string]any{"allocation": a.label, "secret": a.secret}); status != 200 {
		t.Fatalf("release: %d", status)
	}
	if resp, _ := h.do("GET", path, "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a released address still answers: %d", resp.StatusCode)
	}
}

func TestTheRelaysRecordsDoNotLinkAnIdentityToItsRelationships(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	a := h.allocate(id)
	h.allocate(id)

	rows := dumpTables(t, h.dbPath)
	for table, cells := range rows {
		if table == "key_logs" {
			continue
		}
		for _, cell := range cells {
			if strings.Contains(cell, id.aid) {
				t.Fatalf("table %s names the identifier beside its allocations", table)
			}
		}
	}
	if !strings.Contains(strings.Join(rows["private_allocations"], " "), a.label) {
		t.Fatal("the allocation itself was not recorded")
	}
}

// dumpTables reads every cell of every table, as text.
func dumpTables(t *testing.T, path string) map[string][]string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tables, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var n string
		tables.Scan(&n)
		names = append(names, n)
	}
	tables.Close()
	out := map[string][]string{}
	for _, n := range names {
		rows, err := db.Query(`SELECT * FROM ` + n)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...)
			for _, v := range vals {
				out[n] = append(out[n], fmt.Sprintf("%s", v))
			}
		}
		rows.Close()
	}
	return out
}

func TestAKeyRotatedAwayFromIsRefusedEvenAfterARestart(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	first := h.connect(id, http.HandlerFunc(echo))
	stolen := id.snapshot()

	id.rotate()
	first.Close()
	h.connect(id, http.HandlerFunc(echo))
	if _, err := relayproto.Dial(context.Background(), h.agentConfig(stolen)); err == nil {
		t.Fatal("a key rotated away from was admitted")
	}

	h.restart()
	if _, err := relayproto.Dial(context.Background(), h.agentConfig(stolen)); err == nil {
		t.Fatal("after a restart, a key rotated away from was admitted")
	}
	h.connect(id, http.HandlerFunc(echo))
}

func TestAControlRequestIsSignedAndUsedOnce(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	sum := sha256.Sum256([]byte("x"))
	fields := map[string]any{"commitment": b64.EncodeToString(sum[:])}

	if status, _ := h.control(id, "/allocate", "allocate", fields); status != http.StatusForbidden {
		t.Fatalf("an identity that never connected: %d, want 403", status)
	}
	h.connect(id, http.HandlerFunc(echo))

	body := signedBody(t, id, "allocate", fields)
	if status, _ := h.post("/allocate", body); status != 200 {
		t.Fatalf("first use: %d", status)
	}
	if status, _ := h.post("/allocate", body); status != http.StatusConflict {
		t.Fatalf("replayed: %d, want 409", status)
	}
	if status, _ := h.control(id, "/allocate", "release", fields); status != http.StatusBadRequest {
		t.Fatalf("a signature for another request: %d, want 400", status)
	}

	impostor := newIdentity(t)
	forged := signedBody(t, impostor, "allocate", fields)
	var m map[string]any
	json.Unmarshal(forged, &m)
	m["signed_by"] = id.aid
	forged, _ = json.Marshal(m)
	if status, _ := h.post("/allocate", forged); status != http.StatusUnauthorized {
		t.Fatalf("signed by another key: %d, want 401", status)
	}

	json.Unmarshal(signedBody(t, id, "allocate", fields), &m)
	m["relay"] = "relay.example.org"
	elsewhere, _ := json.Marshal(m)
	if status, _ := h.post("/allocate", elsewhere); status != http.StatusBadRequest {
		t.Fatalf("a request for another relay: %d, want 400", status)
	}
}

func TestAPrivateRelayServesNoPublicNamesAndNoOtherHost(t *testing.T) {
	h := newHarness(t, relayproto.ModePrivate)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	if status, _ := h.control(id, "/names/claim", "claim-name", map[string]any{"name": "acme"}); status != http.StatusNotFound {
		t.Fatalf("a private relay took a name claim: %d", status)
	}
	if resp, _ := h.do("GET", "/health", "id.example.org", nil); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("another host: %d, want 421", resp.StatusCode)
	}
	if h.srv.HostAllowed("id.example.org") {
		t.Fatal("a private relay would request a certificate for another host")
	}
}

func TestTheModeIsFixedAtStart(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "r.db"))
	defer st.Close()
	if _, err := New(Config{Mode: "both", Apex: apex, Store: st}); err == nil {
		t.Fatal("a relay started in no defined mode")
	}
}

// --- public ---------------------------------------------------------------

func TestAPublicNameIsClaimedAndServesEverything(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	if status, m := h.control(id, "/names/claim", "claim-name", map[string]any{"name": "acme"}); status != 200 {
		t.Fatalf("claim: %d %v", status, m)
	}

	// Each name is its own host, so its own browser origin.
	resp, m := h.do("POST", "/api/settings?view=all", "acme."+apex, strings.NewReader("{}"))
	if resp.StatusCode != 200 || m["path"] != "/api/settings" || m["query"] != "view=all" ||
		m["allocation"] != "acme" || m["host"] != "acme."+apex || m["prefix"] != "" {
		t.Fatalf("a public address passes everything to the Identity Agent's gate: %d %v", resp.StatusCode, m)
	}
	if resp, _ := h.do("GET", "/acme/api/settings", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a name served as a path under the apex shares one origin with every other name: %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/", "nobody."+apex, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unclaimed name: %d, want 404", resp.StatusCode)
	}
}

func TestNamesCannotBeSquatted(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	owner, other := newIdentity(t), newIdentity(t)
	h.connect(owner, http.HandlerFunc(echo))
	h.connect(other, http.HandlerFunc(echo))
	claim := func(id *identity, name string) int {
		status, _ := h.control(id, "/names/claim", "claim-name", map[string]any{"name": name})
		return status
	}

	for _, name := range []string{"login", "support", "tunnel", "examplebrand"} {
		if got := claim(owner, name); got != http.StatusForbidden {
			t.Errorf("reserved %q: %d, want 403", name, got)
		}
	}
	if got := claim(owner, "acme"); got != 200 {
		t.Fatalf("claim: %d", got)
	}
	if got := claim(other, "acme"); got != http.StatusConflict {
		t.Fatalf("somebody else's name: %d, want 409", got)
	}
	if got := claim(owner, "acme-two"); got != 200 {
		t.Fatalf("second name: %d", got)
	}
	if got := claim(owner, "acme-three"); got != http.StatusForbidden {
		t.Fatalf("beyond the quota: %d, want 403", got)
	}
	if status, _ := h.control(other, "/names/release", "release-name", map[string]any{"name": "acme"}); status != http.StatusForbidden {
		t.Fatalf("released by another identity: %d, want 403", status)
	}
	if status, _ := h.control(owner, "/names/release", "release-name", map[string]any{"name": "acme"}); status != 200 {
		t.Fatalf("release: %d", status)
	}
	if got := claim(other, "acme"); got != http.StatusConflict {
		t.Fatalf("a name released moments ago was taken by somebody else: %d, want 409", got)
	}
	if got := claim(owner, "acme"); got != 200 {
		t.Fatalf("its own holder may take it back: %d", got)
	}
}

func TestAWebsocketOpensThroughAPublicName(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id := newIdentity(t)
	up := websocket.Upgrader{}
	h.connect(id, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, msg, err := c.ReadMessage()
		if err == nil {
			c.WriteMessage(websocket.TextMessage, append([]byte("heard "), msg...))
		}
	}))
	h.control(id, "/names/claim", "claim-name", map[string]any{"name": "acme"})

	d := websocket.Dialer{TLSClientConfig: h.tlsConfig()}
	c, _, err := d.Dial("wss"+strings.TrimPrefix(h.ts.URL, "https")+"/api/ws/events",
		http.Header{"Host": []string{"acme." + apex}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.WriteMessage(websocket.TextMessage, []byte("hello"))
	_, got, err := c.ReadMessage()
	if err != nil || string(got) != "heard hello" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestACustomDomainNeedsItsDNSToProveIt(t *testing.T) {
	h := newHarness(t, relayproto.ModePublic)
	id, other := newIdentity(t), newIdentity(t)
	h.connect(id, http.HandlerFunc(echo))
	h.connect(other, http.HandlerFunc(echo))
	const domain = "id.example.org"

	status, m := h.control(id, "/domains/request", "request-domain", map[string]any{"domain": domain})
	if status != 200 || m["txt_name"] != "_iarelay."+domain || m["txt_value"] != "iarelay-aid="+id.aid {
		t.Fatalf("request: %d %v", status, m)
	}
	if status, _ := h.control(other, "/domains/request", "request-domain", map[string]any{"domain": domain}); status != http.StatusConflict {
		t.Fatalf("another identity asked for the same domain: %d, want 409", status)
	}
	if status, _ := h.control(id, "/domains/verify", "verify-domain", map[string]any{"domain": domain}); status != http.StatusForbidden {
		t.Fatalf("verified with no DNS record: %d, want 403", status)
	}
	h.resolver.set("_iarelay."+domain, "iarelay-aid="+other.aid)
	if status, _ := h.control(id, "/domains/verify", "verify-domain", map[string]any{"domain": domain}); status != http.StatusForbidden {
		t.Fatalf("verified by a record naming somebody else: %d, want 403", status)
	}
	if h.srv.HostAllowed(domain) {
		t.Fatal("a certificate would be requested before the domain is proved")
	}
	if resp, _ := h.do("GET", "/", domain, nil); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("an unproved domain was served: %d", resp.StatusCode)
	}

	h.resolver.set("_iarelay."+domain, "iarelay-aid="+id.aid)
	if status, m := h.control(id, "/domains/verify", "verify-domain", map[string]any{"domain": domain}); status != 200 {
		t.Fatalf("verify: %d %v", status, m)
	}
	if !h.srv.HostAllowed(domain) {
		t.Fatal("a proved domain gets no certificate")
	}
	resp, got := h.do("GET", "/api/profile", domain, nil)
	if resp.StatusCode != 200 || got["host"] != domain || got["path"] != "/api/profile" || got["prefix"] != "" {
		t.Fatalf("the proved domain: %d %v", resp.StatusCode, got)
	}
	for _, bad := range []string{apex, "sub." + apex, "localhost", "x..y", "10.0.0.1"} {
		if validDomain(bad, apex) {
			t.Errorf("%q accepted as a custom domain", bad)
		}
	}
}
