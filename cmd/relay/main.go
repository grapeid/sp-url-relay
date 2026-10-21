// Command relay runs a relay for Identity Agents in one mode, public or
// private, fixed for the life of the process. See README.md for its
// configuration.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"github.com/grapeid/sp-url-relay/internal/proxylisten"
	"github.com/grapeid/sp-url-relay/internal/relay"
	"github.com/grapeid/sp-url-relay/internal/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("relay stopped", "error", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) (int, error) {
	v := env(name, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, errors.New(name + " must be a non-negative whole number")
	}
	return n, nil
}

func run(logger *slog.Logger) error {
	mode := relayproto.Mode(env("RELAY_MODE", ""))
	apex := env("RELAY_APEX", "")
	dataDir := env("RELAY_DATA_DIR", "./data")
	addr := env("RELAY_LISTEN_ADDR", ":443")
	var perIdentity, maxSessions, perIP, maxStreams, privatePer, memoryMB int
	for name, p := range map[string]*int{
		"RELAY_PER_IDENTITY": &perIdentity, "RELAY_MAX_SESSIONS": &maxSessions,
		"RELAY_SESSIONS_PER_IP": &perIP, "RELAY_MAX_STREAMS": &maxStreams,
		"RELAY_PRIVATE_PER_SESSION": &privatePer, "RELAY_MEMORY_LIMIT_MB": &memoryMB,
	} {
		v, err := envInt(name, 0)
		if err != nil {
			return err
		}
		*p = v
	}
	var reserved []string
	if v := env("RELAY_RESERVED_NAMES", ""); v != "" {
		reserved = strings.Split(v, ",")
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "relay.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	originPulls, err := relay.LoadCertPool(env("RELAY_ORIGIN_PULL_CA", ""))
	if err != nil {
		return err
	}
	trusted, err := relay.LoadNetworks(env("RELAY_TRUSTED_PROXIES_FILE", ""))
	if err != nil {
		return err
	}
	srv, err := relay.New(relay.Config{
		Mode: mode, Apex: apex, ConnectHost: env("RELAY_CONNECT_HOST", ""),
		OriginPullCAs: originPulls, TrustedProxies: trusted,
		Store: st, ReservedNames: reserved,
		PerIdentity: perIdentity, MaxSessions: maxSessions, SessionsPerIP: perIP,
		MaxStreams: maxStreams, PrivatePerSession: privatePer,
		MemoryLimit: uint64(memoryMB) << 20, Logger: logger,
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	var tlsConfig *tls.Config
	switch env("RELAY_TLS", "acme") {
	case "acme":
		tlsConfig, err = srv.ACMETLS(relay.ACMEConfig{
			Dir:          filepath.Join(dataDir, "certs"),
			Email:        env("RELAY_ACME_EMAIL", ""),
			DirectoryURL: env("RELAY_ACME_DIRECTORY", ""),
			DNSProvider:  env("RELAY_ACME_DNS_PROVIDER", ""),
		}, ctx.Done())
	case "files":
		tlsConfig, err = srv.FileTLS(env("RELAY_TLS_CERT", ""), env("RELAY_TLS_KEY", ""))
	default:
		err = errors.New(`RELAY_TLS must be "acme" or "files"`)
	}
	if err != nil {
		return err
	}
	go srv.KeepDomainsProved(ctx)

	// PROXY protocol: the platform's TCP proxy announces each client's
	// address, so per-address limits apply to clients (proxylisten.Listen).
	useProxyProto := env("RELAY_PROXY_PROTOCOL", "") == "1"
	listen := func(a string) (net.Listener, error) { return proxylisten.Listen(a, useProxyProto) }

	httpsSrv := &http.Server{
		Handler: srv, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: responses stream, and websockets live long.
		// relayproto ends a stream on which nothing moves.
		IdleTimeout: 2 * time.Minute,
		ErrorLog:    slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	errs := make(chan error, 3)
	go func() { errs <- httpsSrv.ServeTLS(ln, "", "") }()
	servers := []*http.Server{httpsSrv}

	// An optional plain-HTTP port only sends browsers to HTTPS, on a host
	// this relay serves.
	if httpAddr := env("RELAY_HTTP_ADDR", ""); httpAddr != "" {
		hl, err := listen(httpAddr)
		if err != nil {
			return err
		}
		plain := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(srv.RedirectToHTTPS)}
		servers = append(servers, plain)
		go func() { errs <- plain.Serve(hl) }()
	}
	// An optional loopback-only endpoint answering whether this relay serves a
	// host, for an SNI router in front of it (cmd/snirouter).
	if adminAddr := env("RELAY_ADMIN_ADDR", ""); adminAddr != "" {
		host, _, err := net.SplitHostPort(adminAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("RELAY_ADMIN_ADDR must be a loopback address")
		}
		al, err := net.Listen("tcp", adminAddr)
		if err != nil {
			return err
		}
		admin := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(srv.HandleHostCheck)}
		servers = append(servers, admin)
		go func() { errs <- admin.Serve(al) }()
	}
	logger.Info("relay starting", "mode", mode, "apex", apex, "addr", addr,
		"protocol", relayproto.ProtocolVersion, "proxy_protocol", useProxyProto)

	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	return nil
}
