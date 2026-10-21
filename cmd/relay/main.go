// Command relay runs a relay for Identity Agents in one mode, public or
// private, fixed for the life of the process. See README.md for its
// configuration.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

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
	perIdentity, err := envInt("RELAY_PER_IDENTITY", relay.DefaultPerIdentity)
	if err != nil {
		return err
	}
	maxSessions, err := envInt("RELAY_MAX_SESSIONS", 0)
	if err != nil {
		return err
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

	srv, err := relay.New(relay.Config{
		Mode: mode, Apex: apex, Store: st, ReservedNames: reserved,
		PerIdentity: perIdentity, MaxSessions: maxSessions, Logger: logger,
	})
	if err != nil {
		return err
	}

	var tlsConfig *tls.Config
	switch env("RELAY_TLS", "acme") {
	case "acme":
		tlsConfig, err = srv.ACMETLS(relay.ACMEConfig{
			CacheDir:     filepath.Join(dataDir, "certs"),
			Email:        env("RELAY_ACME_EMAIL", ""),
			DirectoryURL: env("RELAY_ACME_DIRECTORY", ""),
		})
	case "files":
		tlsConfig, err = relay.FileTLS(env("RELAY_TLS_CERT", ""), env("RELAY_TLS_KEY", ""))
	default:
		err = errors.New(`RELAY_TLS must be "acme" or "files"`)
	}
	if err != nil {
		return err
	}

	httpsSrv := &http.Server{
		Addr: addr, Handler: srv, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: responses stream, and websockets live long.
		// relayproto ends a stream on which nothing moves.
		IdleTimeout: 2 * time.Minute,
		ErrorLog:    slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	servers := []*http.Server{httpsSrv}

	// An optional plain-HTTP port only sends browsers to HTTPS.
	if httpAddr := env("RELAY_HTTP_ADDR", ""); httpAddr != "" {
		servers = append(servers, &http.Server{
			Addr: httpAddr, ReadHeaderTimeout: 10 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			}),
		})
	}

	errs := make(chan error, len(servers))
	go func() { errs <- httpsSrv.ListenAndServeTLS("", "") }()
	for _, s := range servers[1:] {
		s := s
		go func() { errs <- s.ListenAndServe() }()
	}
	logger.Info("relay starting", "mode", mode, "apex", apex, "addr", addr, "protocol", relayproto.ProtocolVersion)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
	return nil
}
