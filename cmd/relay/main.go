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

	srv := api.New(api.Config{
		Apex: apex, RelayAID: relayAID, ListenAddr: addr, Store: st, Logger: logger,
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