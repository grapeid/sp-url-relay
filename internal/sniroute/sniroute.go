// Package sniroute sends each incoming TLS connection, unopened, to a backend
// chosen by the server name its ClientHello asks for.
//
// It never decrypts anything: it reads the ClientHello only to learn the SNI,
// then replays those bytes to the backend and splices the two connections.
// The TLS session, and anything bound to it, runs end to end between the
// client and the backend. It lets several TLS servers share one address.
//
// The client's address reaches the backend in a PROXY protocol v2 header: the
// address announced to the router by the proxy in front of it, if it uses
// one, or else the router's TCP peer.
package sniroute

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Route sends a server name to a backend address.
type Route struct {
	// Host is an exact server name, or "*.<suffix>" for every name under
	// suffix (not suffix itself).
	Host    string
	Backend string
}

// Ask sends server names no Route matches to Backend when URL, asked with
// ?host=<name>, answers 200. A backend that serves names nobody can list in
// advance (custom domains) answers for itself.
type Ask struct {
	URL     string
	Backend string
}

// Config is a router.
type Config struct {
	Routes []Route
	Asks   []Ask
	// HelloTimeout bounds how long a client may take to send its ClientHello.
	HelloTimeout time.Duration
	// MaxHelloBytes bounds how much is read before the name is known.
	MaxHelloBytes int
	Logger        *slog.Logger
	// Dial reaches a backend; nil means net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// HTTPClient asks; nil means a client with a short timeout.
	HTTPClient *http.Client
}

// Router routes connections.
type Router struct {
	cfg Config

	mu    sync.Mutex
	cache map[string]askAnswer
}

type askAnswer struct {
	backend string
	until   time.Time
}

// ParseRoutes reads "host=backend,host=backend".
func ParseRoutes(s string) ([]Route, error) {
	var out []Route
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, backend, ok := strings.Cut(item, "=")
		if !ok || host == "" || backend == "" {
			return nil, fmt.Errorf("route %q is not host=backend", item)
		}
		out = append(out, Route{Host: strings.ToLower(host), Backend: backend})
	}
	return out, nil
}

// ParseAsks reads "url=backend,url=backend". The URL is split at its last "=".
func ParseAsks(s string) ([]Ask, error) {
	var out []Ask
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		i := strings.LastIndex(item, "=")
		if i <= 0 || i == len(item)-1 {
			return nil, fmt.Errorf("ask %q is not url=backend", item)
		}
		if _, err := url.Parse(item[:i]); err != nil {
			return nil, fmt.Errorf("ask %q: %w", item, err)
		}
		out = append(out, Ask{URL: item[:i], Backend: item[i+1:]})
	}
	return out, nil
}

// New makes a router.
func New(cfg Config) *Router {
	if cfg.HelloTimeout == 0 {
		cfg.HelloTimeout = 10 * time.Second
	}
	if cfg.MaxHelloBytes == 0 {
		cfg.MaxHelloBytes = 64 << 10
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 3 * time.Second}
	}
	return &Router{cfg: cfg, cache: map[string]askAnswer{}}
}

// Serve routes every connection ln accepts until it is closed.
func (r *Router) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go r.handle(c)
	}
}

// backendFor chooses where a server name goes, or "" to drop it.
func (r *Router) backendFor(ctx context.Context, name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return ""
	}
	for _, rt := range r.cfg.Routes {
		if suffix, ok := strings.CutPrefix(rt.Host, "*."); ok {
			if strings.HasSuffix(name, "."+suffix) {
				return rt.Backend
			}
		} else if name == rt.Host {
			return rt.Backend
		}
	}
	return r.ask(ctx, name)
}

func (r *Router) ask(ctx context.Context, name string) string {
	now := time.Now()
	r.mu.Lock()
	if a, ok := r.cache[name]; ok && now.Before(a.until) {
		r.mu.Unlock()
		return a.backend
	}
	r.mu.Unlock()
	backend, ttl := "", 10*time.Second
	for _, a := range r.cfg.Asks {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL+"?host="+url.QueryEscape(name), nil)
		if err != nil {
			continue
		}
		resp, err := r.cfg.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			backend, ttl = a.Backend, time.Minute
			break
		}
	}
	r.mu.Lock()
	if len(r.cache) > 10000 {
		r.cache = map[string]askAnswer{}
	}
	r.cache[name] = askAnswer{backend: backend, until: now.Add(ttl)}
	r.mu.Unlock()
	return backend
}

func (r *Router) handle(c net.Conn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(r.cfg.HelloTimeout))
	name, hello, err := readServerName(c, r.cfg.MaxHelloBytes)
	if err != nil {
		r.cfg.Logger.Debug("connection dropped", "peer", c.RemoteAddr().String(), "reason", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	backend := r.backendFor(ctx, name)
	if backend == "" {
		cancel()
		r.cfg.Logger.Info("connection dropped", "peer", c.RemoteAddr().String(), "sni", name, "reason", "no backend serves this name")
		return
	}
	b, err := r.cfg.Dial(ctx, "tcp", backend)
	cancel()
	if err != nil {
		r.cfg.Logger.Error("backend unreachable", "backend", backend, "error", err)
		return
	}
	defer b.Close()
	c.SetReadDeadline(time.Time{})

	// The backend learns who the client is from the PROXY header, as it would
	// with nothing in between.
	hdr := proxyproto.HeaderProxyFromAddrs(2, c.RemoteAddr(), c.LocalAddr())
	if _, err := hdr.WriteTo(b); err != nil {
		return
	}
	if _, err := b.Write(hello); err != nil {
		return
	}
	splice(c, b)
}

// splice copies both ways until both directions are done.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go pipe(b, a)
	go pipe(a, b)
	wg.Wait()
}

// errHelloRead stops the handshake once the ClientHello has been read.
var errHelloRead = errors.New("client hello read")

// readServerName reads a TLS ClientHello from c and returns the server name
// it asks for, and every byte read, to replay to the backend. The parsing is
// crypto/tls's own: the handshake is started on a connection that records
// what it reads and refuses to write, and stopped as soon as the ClientHello
// has been parsed. crypto/tls reassembles a ClientHello split across
// records or reads, so a fragmented one is read as easily as a whole one.
func readServerName(c net.Conn, max int) (string, []byte, error) {
	rec := &recorder{Conn: c, max: max}
	var name string
	err := tls.Server(rec, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errHelloRead
		},
	}).Handshake()
	if name == "" {
		if err == nil || errors.Is(err, errHelloRead) {
			err = errors.New("the ClientHello names no server")
		}
		return "", nil, err
	}
	return name, rec.buf.Bytes(), nil
}

// recorder keeps what is read through it, and writes nothing: the handshake
// it carries is only ever started to read the ClientHello.
type recorder struct {
	net.Conn
	buf bytes.Buffer
	max int
}

func (r *recorder) Read(p []byte) (int, error) {
	if r.buf.Len() >= r.max {
		return 0, errors.New("the ClientHello is too large")
	}
	if room := r.max - r.buf.Len(); len(p) > room {
		p = p[:room]
	}
	n, err := r.Conn.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

func (r *recorder) Write(p []byte) (int, error) { return len(p), nil }
