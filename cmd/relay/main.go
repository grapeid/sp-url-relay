package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grapeid/sp-url-relay/internal/api"
	"github.com/grapeid/sp-url-relay/internal/store"
	"github.com/grapeid/sp-common/verify"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dbPath := os.Getenv("SQLITE_PATH")
	if dbPath == "" {
		dbPath = "./data/relay.db"
	}
	if err := os.MkdirAll("./data", 0o755); err != nil {
		logger.Error("mkdir data", "error", err)
		os.Exit(1)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		logger.Error("open store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	apex := os.Getenv("RELAY_APEX")
	if apex == "" {
		apex = "relay.grapeid.org"
	}
	relayAID := os.Getenv("RELAY_AID")
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":5000"
	}

	// Refuse to run silently unverified.
	//
	// Allocation and release are checked against the key recorded at
	// enrollment, so whoever enrolls an AID controls its relay presence
	// afterwards — its hostname, where that hostname points, and what is
	// served from an address claiming to be somebody else's. Without a KERI
	// service there is no way to tell whether an enrolling key belongs to the
	// AID it names, so that is a takeover waiting to happen. A legitimate
	// choice for development; a bad one to make by forgetting a flag.
	var verifier verify.Verifier = verify.Unverified{}
	switch keriService := os.Getenv("KERI_SERVICE"); {
	case keriService != "":
		verifier = verify.NewKeriService(keriService)
		logger.Info("enrollments verified", "keri_service", keriService)
	case os.Getenv("ALLOW_UNVERIFIED_ENROLLMENT") == "1":
		logger.Warn("running with unverified enrollment: anyone can claim any AID " +
			"and take over its relay presence. Development only.")
	default:
		logger.Error("refusing to start: set KERI_SERVICE so an enrolling key can be " +
			"checked against the AID it claims, or ALLOW_UNVERIFIED_ENROLLMENT=1 if " +
			"this is a development instance")
		os.Exit(1)
	}

	srv := api.New(api.Config{
		Apex: apex, RelayAID: relayAID, ListenAddr: addr, Store: st, Logger: logger,
		Verifier: verifier,
	})

	httpSrv := &http.Server{Addr: addr, Handler: srv.Handler()}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	logger.Info("url-relay M35 starting", "addr", addr, "apex", apex)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}