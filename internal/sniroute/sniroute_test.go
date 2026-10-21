package sniroute

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/grapeid/sp-url-relay/internal/proxylisten"
)

// clientHello is what a real TLS client sends first, asking for name.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(b, body); err != nil {
		t.Fatal(err)
	}
	a.Close()
	b.Close()
	return append(hdr, body...)
}

// reframe splits a one-record ClientHello into records of at most n bytes of
// handshake data each, as a client or middlebox may.
func reframe(hello []byte, n int) []byte {
	var out bytes.Buffer
	data := hello[5:]
	for len(data) > 0 {
		k := min(n, len(data))
		out.Write([]byte{hello[0], hello[1], hello[2], byte(k >> 8), byte(k)})
		out.Write(data[:k])
		data = data[k:]
	}
	return out.Bytes()
}

// feed writes b to a connection in pieces of at most n bytes, slowly.
func feed(b []byte, n int) net.Conn {
	a, c := net.Pipe()
	go func() {
		for len(b) > 0 {
			k := min(n, len(b))
			if _, err := a.Write(b[:k]); err != nil {
				return
			}
			b = b[k:]
		}
	}()
	return c
}

func TestTheServerNameIsReadFromAnyShapeOfClientHello(t *testing.T) {
	hello := clientHello(t, "acme.relay.test")
	for _, c := range []struct {
		name string
		in   []byte
		step int
	}{
		{"whole", hello, len(hello)},
		{"split across reads", hello, 7},
		{"fragmented across records", reframe(hello, 40), 1000},
		{"fragmented and split", reframe(hello, 13), 3},
	} {
		conn := feed(c.in, c.step)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		name, read, err := readServerName(conn, 64<<10)
		if err != nil || name != "acme.relay.test" {
			t.Errorf("%s: %q, %v", c.name, name, err)
			continue
		}
		if !bytes.Equal(read, c.in) {
			t.Errorf("%s: the bytes kept to replay are not the bytes the client sent", c.name)
		}
	}
}

func TestAClientHelloWithNoNameOrTooLargeIsDropped(t *testing.T) {
	conn := feed(clientHello(t, ""), 1000)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := readServerName(conn, 64<<10); err == nil {
		t.Fatal("a ClientHello naming no server was routed")
	}
	conn = feed(clientHello(t, "acme.relay.test"), 1000)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := readServerName(conn, 50); err == nil {
		t.Fatal("more than the limit was read before the name was known")
	}
}

// backend is a TLS server behind a PROXY-protocol listener that reports who
// it believes the client is.
func backend(t *testing.T, label string) *httptest.Server {
	t.Helper()
	ln, err := proxylisten.Listen("127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "%s %s %s", label, host, r.TLS.ServerName)
	}))
	ts.Listener.Close()
	ts.Listener = ln
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func TestEachNameReachesItsBackendWithTheClientsAddress(t *testing.T) {
	public, private := backend(t, "public"), backend(t, "private")
	addr := func(ts *httptest.Server) string { return strings.TrimPrefix(ts.URL, "https://") }
	var asked atomic.Int32
	ask := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if r.URL.Query().Get("host") == "owner.example.org" {
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ask.Close()

	ln, err := proxylisten.Listen("127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := New(Config{
		Routes: []Route{
			{Host: "public.test", Backend: addr(public)},
			{Host: "*.public.test", Backend: addr(public)},
			{Host: "private.test", Backend: addr(private)},
		},
		Asks:   []Ask{{URL: ask.URL, Backend: addr(public)}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	go r.Serve(ln)

	// A platform proxy in front announces the client 203.0.113.9.
	get := func(sni string) (string, error) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return "", err
		}
		hdr := &proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.TCPv4,
			SourceAddr:      &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000},
			DestinationAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}}
		hdr.WriteTo(c)
		tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		tc.SetDeadline(time.Now().Add(3 * time.Second))
		defer tc.Close()
		if err := tc.Handshake(); err != nil {
			return "", err
		}
		fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
		raw, err := io.ReadAll(tc)
		if err != nil {
			return "", err
		}
		body := string(raw)
		return body[strings.Index(body, "\r\n\r\n")+4:], nil
	}

	for sni, want := range map[string]string{
		"public.test":       "public 203.0.113.9 public.test",
		"acme.public.test":  "public 203.0.113.9 acme.public.test",
		"private.test":      "private 203.0.113.9 private.test",
		"owner.example.org": "public 203.0.113.9 owner.example.org",
	} {
		got, err := get(sni)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", sni, got, err, want)
		}
	}
	for _, sni := range []string{"unknown.example.net", "evilpublic.test", "x.private.test"} {
		if got, err := get(sni); err == nil {
			t.Errorf("%s was routed: %q", sni, got)
		}
	}
	before := asked.Load()
	get("owner.example.org")
	if asked.Load() != before {
		t.Error("the answer for a custom domain was not kept")
	}
}

func TestRoutesAndAsksAreParsed(t *testing.T) {
	r, err := ParseRoutes("Public.test=127.0.0.1:9443, *.public.test=127.0.0.1:9443")
	if err != nil || len(r) != 2 || r[0].Host != "public.test" || r[1].Host != "*.public.test" {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := ParseRoutes("nobackend"); err == nil {
		t.Fatal("a route with no backend was accepted")
	}
	a, err := ParseAsks("http://127.0.0.1:9180/hosts=127.0.0.1:9443")
	if err != nil || len(a) != 1 || a[0].URL != "http://127.0.0.1:9180/hosts" || a[0].Backend != "127.0.0.1:9443" {
		t.Fatalf("%v %v", a, err)
	}
}
