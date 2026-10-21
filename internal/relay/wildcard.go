package relay

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// A public relay serves every name as its own subdomain, so that each name is
// its own browser origin. That needs one certificate for <apex> and *.<apex>,
// and a wildcard can only be obtained by proving control of the apex's DNS
// (ACME DNS-01). The relay does that through a DNS provider's API.

// dnsProviders are the DNS providers a relay can prove its apex through. Each
// reads its credentials from its own environment variables, as lego
// documents them (Cloudflare: CLOUDFLARE_DNS_API_TOKEN, scoped to edit DNS of
// the apex's zone only). Adding a provider is one line.
var dnsProviders = map[string]func() (challenge.Provider, error){
	"cloudflare": func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
}

// renewWithin is how long before a certificate expires the relay renews it.
const renewWithin = 30 * 24 * time.Hour

// wildcardCert obtains and renews the certificate for <apex> and *.<apex>,
// keeping it, and the ACME account, in a directory on the relay's volume.
type wildcardCert struct {
	apex, dir, email, directoryURL string
	provider                       challenge.Provider
	logger                         *slog.Logger

	mu   sync.RWMutex
	cert *tls.Certificate
}

func newWildcardCert(apex, dir, email, directoryURL, providerName string, logger *slog.Logger) (*wildcardCert, error) {
	make, ok := dnsProviders[providerName]
	if !ok {
		return nil, fmt.Errorf("a public relay needs a wildcard certificate, obtained through a DNS provider: set RELAY_ACME_DNS_PROVIDER (supported: cloudflare)")
	}
	p, err := make()
	if err != nil {
		return nil, fmt.Errorf("DNS provider %s: %w", providerName, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &wildcardCert{apex: apex, dir: dir, email: email, directoryURL: directoryURL, provider: p, logger: logger}
	if c, err := w.load(); err == nil {
		w.cert = c
	}
	return w, nil
}

func (w *wildcardCert) certPath() string { return filepath.Join(w.dir, "wildcard.pem") }
func (w *wildcardCert) keyPath() string  { return filepath.Join(w.dir, "wildcard.key") }

func (w *wildcardCert) load() (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(w.certPath(), w.keyPath())
	if err != nil {
		return nil, err
	}
	if c.Leaf == nil && len(c.Certificate) > 0 {
		c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	return &c, nil
}

// get returns the current certificate.
func (w *wildcardCert) get() (*tls.Certificate, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cert == nil {
		return nil, fmt.Errorf("no certificate for %s yet", w.apex)
	}
	return w.cert, nil
}

// needsRenewal reports whether the certificate is missing or near expiry.
func (w *wildcardCert) needsRenewal(now time.Time) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cert == nil || w.cert.Leaf == nil || w.cert.Leaf.NotAfter.Sub(now) < renewWithin
}

// keep obtains the certificate if needed and checks twice a day after that.
// It returns once a certificate is held, or the first attempt has failed.
func (w *wildcardCert) keep(stop <-chan struct{}) error {
	first := w.ensure()
	go func() {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := w.ensure(); err != nil {
					w.logger.Error("renew the wildcard certificate", "apex", w.apex, "error", err)
				}
			}
		}
	}()
	return first
}

func (w *wildcardCert) ensure() error {
	if !w.needsRenewal(time.Now()) {
		return nil
	}
	user, err := w.account()
	if err != nil {
		return err
	}
	cfg := lego.NewConfig(user)
	if w.directoryURL != "" {
		cfg.CADirURL = w.directoryURL
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return err
	}
	if err := client.Challenge.SetDNS01Provider(w.provider); err != nil {
		return err
	}
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("register with the certificate authority: %w", err)
		}
		user.Registration = reg
		if err := w.saveAccount(user); err != nil {
			return err
		}
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{w.apex, "*." + w.apex}, Bundle: true,
	})
	if err != nil {
		return fmt.Errorf("obtain the certificate for %s and *.%s: %w", w.apex, w.apex, err)
	}
	if err := os.WriteFile(w.keyPath(), res.PrivateKey, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(w.certPath(), res.Certificate, 0o600); err != nil {
		return err
	}
	c, err := w.load()
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.cert = c
	w.mu.Unlock()
	w.logger.Info("wildcard certificate obtained", "apex", w.apex, "not_after", c.Leaf.NotAfter)
	return nil
}

// acmeUser is the relay's ACME account, kept beside the certificate.
type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (w *wildcardCert) account() (*acmeUser, error) {
	keyFile, accFile := filepath.Join(w.dir, "account.key"), filepath.Join(w.dir, "account.json")
	u := &acmeUser{Email: w.email}
	if raw, err := os.ReadFile(keyFile); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("%s is not a PEM key", keyFile)
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		u.key = k
		if raw, err := os.ReadFile(accFile); err == nil {
			json.Unmarshal(raw, u)
		}
		return u, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	u.key = k
	return u, nil
}

func (w *wildcardCert) saveAccount(u *acmeUser) error {
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(w.dir, "account.json"), raw, 0o600)
}
