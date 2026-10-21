// Command snirouter lets several TLS servers share one address: it reads each
// connection's ClientHello for the server name, and splices the connection,
// still encrypted, to the backend serving that name. Names nothing serves are
// dropped. The client's address is passed on in a PROXY protocol header.
//
//	ROUTER_LISTEN_ADDR      where to listen (default :8443)
//	ROUTER_PROXY_PROTOCOL   1: every incoming connection begins with a PROXY
//	                        protocol header (from a platform TCP proxy), whose
//	                        client address is passed on
//	ROUTER_ROUTES           host=backend pairs, comma-separated; a host
//	                        "*.example.org" matches every name under
//	                        example.org, "example.org" only itself
//	ROUTER_ASKS             url=backend pairs: a name no route matches goes to
//	                        backend when GET url?host=<name> answers 200
package main

import (
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/grapeid/sp-url-relay/internal/proxylisten"
	"github.com/grapeid/sp-url-relay/internal/sniroute"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("router stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	routes, err := sniroute.ParseRoutes(os.Getenv("ROUTER_ROUTES"))
	if err != nil {
		return err
	}
	asks, err := sniroute.ParseAsks(os.Getenv("ROUTER_ASKS"))
	if err != nil {
		return err
	}
	if len(routes) == 0 && len(asks) == 0 {
		return errors.New("ROUTER_ROUTES names no route")
	}
	addr := strings.TrimSpace(os.Getenv("ROUTER_LISTEN_ADDR"))
	if addr == "" {
		addr = ":8443"
	}
	ln, err := proxylisten.Listen(addr, os.Getenv("ROUTER_PROXY_PROTOCOL") == "1")
	if err != nil {
		return err
	}
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
		<-stop
		ln.Close()
	}()
	logger.Info("router starting", "addr", addr, "routes", len(routes), "asks", len(asks))
	return sniroute.New(sniroute.Config{Routes: routes, Asks: asks, Logger: logger}).Serve(ln)
}
