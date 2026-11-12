// Package e2e runs the Identity Agent core's own relay client (relay.Manager
// and relay.Client, from identity-agent-core) against this repository's real
// relay server, not the core's in-process test relay.
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"github.com/grapeid/sp-url-relay/internal/relay"
	"github.com/grapeid/sp-url-relay/internal/store"
	corerelay "identity-agent-core/relay"
)

type enrolment struct {
	aid  string
	kel  []byte
	seed []byte
	keri *keri.SoftwareSigner
}

func newEnrolment(t *testing.T) *enrolment {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	cur, err := keri.NewSoftwareSigner(seed, true)
	if err != nil {
		t.Fatal(err)
	}
	nxt, _ := keri.GenerateSigner(true)
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, _ := keri.NextDigest(npub)
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, cur)
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := keri.ExportKEL([][]byte{signed.Message})
	return &enrolment{aid: parsed.Identifier, kel: kel, seed: seed, keri: cur}
}

func (e *enrolment) SignCanonical(_ string, body map[string]interface{}) (string, error) {
	canon, err := relayproto.CanonicalBody(body)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(e.seed), canon)), nil
}

func agent() http.Handler {
	mux := http.NewServeMux()
	// SEAM-17 artifact paths, answered by one handler (the mux cannot hold
	// /oobi/{aid} beside /{aid}/did.json).
	mux.HandleFunc("GET /{aid}/{file}", func(w http.ResponseWriter, r *http.Request) {
		switch f := r.PathValue("file"); f {
		case "did.json", "kel", "keri.cesr":
			w.Write([]byte(f + " of " + r.PathValue("aid")))
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("GET /oobi/{aid}", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("oobi of " + r.PathValue("aid"))) })
	return mux
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The core's client reads this relay's descriptor, is admitted by it, is
// allocated a private path label, and the address is reached through the
// relay for the artifact route; a released address stops answering.
func TestTheCoresClientAgainstThisRelay(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// The relay names itself by host, port 443 implied, as in production. The
	// test cannot bind 443, so every dial to it is sent to the real listener.
	const name = "127.0.0.1"
	srv, err := relay.New(relay.Config{Mode: relayproto.ModePrivate, Apex: name, Store: st,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	defer ts.Close()
	tlsCfg := ts.Client().Transport.(*http.Transport).TLSClientConfig
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
		}}}

	e := newEnrolment(t)
	c := corerelay.NewClient("https://"+name, e)
	c.HTTPClient = hc
	d, err := c.FetchDescriptor(context.Background())
	if err != nil {
		t.Fatalf("the core refuses this relay's descriptor: %v", err)
	}

	// Admission: the first connection is the enrolment, bound to the TLS channel.
	sess, err := relayproto.Dial(context.Background(), &relayproto.AgentConfig{
		URL: "wss" + strings.TrimPrefix(ts.URL, "https") + "/tunnel", AID: e.aid,
		KEL: func() []byte { return e.kel }, Signer: e.keri, TLS: tlsCfg})
	if err != nil {
		t.Fatalf("admission: %v (descriptor tunnel %s)", err, d.TunnelEndpoint)
	}
	defer sess.Close()
	go sess.Serve(agent())

	secret, commitment := corerelay.NewSecret()
	label, addr, err := c.Allocate(context.Background(), e.aid, commitment)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := relayproto.CheckPrivateURL(addr, label); err != nil {
		t.Fatalf("the allocated address fails the protocol's own check: %v", err)
	}
	if err := c.Bind(context.Background(), e.aid, label, secret); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if code, body := get(t, hc, addr+"/oobi/"+e.aid); code != 200 || body != "oobi of "+e.aid {
		t.Fatalf("artifact through the relay: %d %q", code, body)
	}
	for _, f := range []string{"did.json", "kel", "keri.cesr"} {
		if code, body := get(t, hc, addr+"/"+e.aid+"/"+f); code != 200 || body != f+" of "+e.aid {
			t.Fatalf("did:webs artifact %s through the relay: %d %q", f, code, body)
		}
	}
	if err := c.Release(context.Background(), e.aid, label, secret); err != nil {
		t.Fatalf("release: %v", err)
	}
	if code, _ := get(t, hc, addr+"/oobi/"+e.aid); code == 200 {
		t.Fatal("a released address still answers")
	}
}
