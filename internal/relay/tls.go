package relay

import (
	"context"
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// The relay terminates TLS itself, always. An admission is bound to the TLS
// connection between the relay and the Identity Agent (RFC 9266), so a front
// that terminates TLS in between would make every admission fail
// (ADR-048 §10). A TCP or SNI pass-through in front is fine.

// ACMEConfig obtains certificates automatically, by TLS-ALPN-01 on the
// relay's own TLS port: no HTTP port is needed.
type ACMEConfig struct {
	// CacheDir keeps the account key and certificates across restarts.
	CacheDir string
	// Email is the contact the certificate authority is given.
	Email string
	// DirectoryURL overrides the certificate authority (a staging endpoint,
	// say). Empty means Let's Encrypt.
	DirectoryURL string
}

// ACMETLS returns a TLS configuration that obtains certificates only for the
// hosts s may serve: its apex, and verified custom domains.
func (s *Server) ACMETLS(cfg ACMEConfig) (*tls.Config, error) {
	if cfg.CacheDir == "" {
		return nil, fmt.Errorf("ACME needs a cache directory, or every restart requests new certificates")
	}
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cfg.CacheDir),
		Email:  cfg.Email,
		HostPolicy: func(_ context.Context, host string) error {
			if !s.HostAllowed(host) {
				return fmt.Errorf("this relay does not serve %q", host)
			}
			return nil
		},
	}
	if cfg.DirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.DirectoryURL}
	}
	t := m.TLSConfig()
	// TLS 1.2 is still accepted for browsers reaching a public address. An
	// Identity Agent always dials with 1.3, and admission needs it: the
	// channel binding is a TLS 1.3 exporter.
	t.MinVersion = tls.VersionTLS12
	return t, nil
}

// FileTLS serves a certificate and key from files: for a relay whose
// certificates are managed elsewhere, and for local use.
func FileTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load the TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
