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
// TCP or SNI pass-through in front is fine, and so is a CDN in front of the
// caller-facing hosts, as long as Identity Agents reach the connect host
// directly.

// ACMEConfig obtains certificates automatically.
//
//   - With DNSProvider set, the relay's own hosts (apex, connect host, and on a
//     public relay *.<apex> for its names) come in one certificate by DNS-01.
//     This is required for a public relay (a wildcard has no other way) and
//     for any host a CDN answers TLS for.
//   - Without it, a private relay's apex and connect host come by TLS-ALPN-01
//     on the relay's own TLS port.
//   - A public relay's custom domains each come by TLS-ALPN-01, once proved.
type ACMEConfig struct {
	// Dir keeps account keys and certificates across restarts.
	Dir string
	// Email is the contact the certificate authority is given.
	Email string
	// DirectoryURL overrides the certificate authority. Empty means Let's
	// Encrypt.
	DirectoryURL string
	// DNSProvider names the DNS provider the relay's hosts are proved through
	// (see dnsProviders).
	DNSProvider string
}

// ownDomains are the hosts the relay's own certificate must name.
func (s *Server) ownDomains() []string {
	d := []string{s.cfg.Apex}
	if s.cfg.Mode == relayproto.ModePublic {
		d = append(d, "*."+s.cfg.Apex)
		if s.nameOf(s.cfg.ConnectHost) != "" {
			return d
		}
	}
	if s.cfg.ConnectHost != s.cfg.Apex {
		d = append(d, s.cfg.ConnectHost)
	}
	return d
}

// ownHost reports whether host is covered by the relay's own certificate.
func (s *Server) ownHost(host string) bool {
	return host == s.cfg.Apex || host == s.cfg.ConnectHost || s.nameOf(host) != ""
}

// ACMETLS returns a TLS configuration that obtains certificates only for the
// hosts s may serve. A DNS-01 certificate is obtained before it returns, so
// the relay does not start unable to serve its own hosts.
func (s *Server) ACMETLS(cfg ACMEConfig, stop <-chan struct{}) (*tls.Config, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("ACME needs a directory to keep certificates in, or every restart requests new ones")
	}
	viaDNS := cfg.DNSProvider != ""
	if s.cfg.Mode == relayproto.ModePublic && !viaDNS {
		return nil, fmt.Errorf("a public relay serves its names under a wildcard certificate, which needs RELAY_ACME_DNS_PROVIDER")
	}
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(cfg.Dir, "autocert")),
		Email:  cfg.Email,
		HostPolicy: func(_ context.Context, host string) error {
			if !viaDNS && s.ownHost(host) {
				return nil
			}
			if s.cfg.Mode == relayproto.ModePublic && s.verifiedDomain(host) {
				return nil
			}
			return fmt.Errorf("this relay obtains no certificate for %q this way", host)
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
	if viaDNS {
		w, err := newWildcardCert(s.ownDomains(), filepath.Join(cfg.Dir, "dns01"), cfg.Email, cfg.DirectoryURL, cfg.DNSProvider, s.cfg.Logger)
		if err != nil {
			return nil, err
		}
		if err := w.keep(stop); err != nil {
			return nil, err
		}
		viaALPN := t.GetCertificate
		t.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if s.ownHost(strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))) {
				return w.get()
			}
			return viaALPN(hello)
		}
	}
	return s.WithOriginPulls(t), nil
}

// FileTLS serves a certificate and key from files: for a relay whose
// certificates are managed elsewhere, and for local use. It must name the
// apex and the connect host, and on a public relay *.<apex>.
func (s *Server) FileTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load the TLS certificate: %w", err)
	}
	return s.WithOriginPulls(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
}

// WithOriginPulls requires, when origin pulls are on, a client certificate
// from the CDN on every connection whose SNI names a caller-facing host. The
// connect host and custom domains are reached directly and ask for none. The
// request handler checks again by Host, so a connection made under another
// SNI cannot carry a caller-facing request past this.
func (s *Server) WithOriginPulls(base *tls.Config) *tls.Config {
	if s.cfg.OriginPullCAs == nil {
		return base
	}
	pulled := base.Clone()
	pulled.ClientAuth = tls.RequireAndVerifyClientCert
	pulled.ClientCAs = s.cfg.OriginPullCAs
	out := base.Clone()
	out.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if s.callerFacing(strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))) {
			return pulled, nil
		}
		return nil, nil
	}
	return out
}
