package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// The relay terminates TLS itself, always. An admission is bound to the TLS
// connection between the relay and the Identity Agent, so a front that
// terminates TLS in between would make every admission fail (ADR-048 §10). A
// TCP or SNI pass-through in front is fine.

// ACMEConfig obtains certificates automatically.
//
//   - The apex of a private relay, and every custom domain of a public one,
//     by TLS-ALPN-01 on the relay's own TLS port.
//   - The apex of a public relay and *.<apex>, its names, as one wildcard
//     certificate by DNS-01 through DNSProvider.
type ACMEConfig struct {
	// Dir keeps account keys and certificates across restarts.
	Dir string
	// Email is the contact the certificate authority is given.
	Email string
	// DirectoryURL overrides the certificate authority. Empty means Let's
	// Encrypt.
	DirectoryURL string
	// DNSProvider names the DNS provider a public relay proves its apex
	// through (see dnsProviders). Unused by a private relay.
	DNSProvider string
}

// ACMETLS returns a TLS configuration that obtains certificates only for the
// hosts s may serve. A public relay's first wildcard certificate is obtained
// before it returns, so the relay does not start unable to serve its names.
func (s *Server) ACMETLS(cfg ACMEConfig, stop <-chan struct{}) (*tls.Config, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("ACME needs a directory to keep certificates in, or every restart requests new ones")
	}
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(cfg.Dir, "autocert")),
		Email:  cfg.Email,
		HostPolicy: func(_ context.Context, host string) error {
			if s.cfg.Mode == relayproto.ModePrivate && host == s.cfg.Apex {
				return nil
			}
			if s.cfg.Mode == relayproto.ModePublic && s.verifiedDomain(host) {
				return nil
			}
			return fmt.Errorf("this relay obtains no certificate for %q here", host)
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
	if s.cfg.Mode == relayproto.ModePrivate {
		return t, nil
	}

	w, err := newWildcardCert(s.cfg.Apex, filepath.Join(cfg.Dir, "wildcard"), cfg.Email, cfg.DirectoryURL, cfg.DNSProvider, s.cfg.Logger)
	if err != nil {
		return nil, err
	}
	if err := w.keep(stop); err != nil {
		return nil, err
	}
	viaALPN := t.GetCertificate
	t.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
		if name == s.cfg.Apex || s.nameOf(name) != "" {
			return w.get()
		}
		return viaALPN(hello)
	}
	return t, nil
}

// FileTLS serves a certificate and key from files: for a relay whose
// certificates are managed elsewhere, and for local use. A public relay's
// certificate must cover <apex> and *.<apex>.
func FileTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load the TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
