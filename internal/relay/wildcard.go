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
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// Some certificates can only be obtained by proving control of a domain's
// DNS (ACME DNS-01), which the relay does through a DNS provider's API:
//
//   - a public relay serves every name as its own subdomain, so that each name
//     is its own browser origin, which needs one certificate for <apex> and
//     *.<apex>;
//   - a host behind a TLS-terminating CDN cannot answer TLS-ALPN-01, because
//     the CDN, not the relay, answers its TLS.

// dnsProviders are the DNS providers a relay can prove its apex through. Each
// reads its credentials from its own environment variables, as lego
// documents them (Cloudflare: CLOUDFLARE_DNS_API_TOKEN, scoped to edit DNS of
// the apex's zone only). Adding a provider is one line.
var dnsProviders = map[string]func() (challenge.Provider, error){
	"cloudflare": func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
}

// renewWithin is how long before a certificate expires the relay renews it.
const renewWithin = 30 * 24 * time.Hour

// wildcardCert obtains and renews one certificate for domains by DNS-01,
// keeping it, and the ACME account, in a directory on the relay's volume.
type wildcardCert struct {
	domains                        []string
	apex, dir, email, directoryURL string
	provider                       challenge.Provider
	logger                         *slog.Logger
	obtain                         func() error // ensure, unless a test replaces it

	mu   sync.RWMutex
	cert *tls.Certificate
}

func newWildcardCert(domains []string, dir, email, directoryURL, providerName string, logger *slog.Logger) (*wildcardCert, error) {
	make, ok := dnsProviders[providerName]
	if !ok {
		return nil, fmt.Errorf("certificates for %v need DNS-01, through a DNS provider: set RELAY_ACME_DNS_PROVIDER (supported: cloudflare)", domains)
	}
	apex := domains[0]
	p, err := make()
	if err != nil {
		return nil, fmt.Errorf("DNS provider %s: %w", providerName, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &wildcardCert{domains: domains, apex: apex, dir: dir, email: email, directoryURL: directoryURL, provider: p, logger: logger}
	if c, err := w.load(); err == nil && covers(c, domains) {
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
// It never gives up and never returns an error: a relay that exited on a
// failed attempt was restarted at once and tried again, and every attempt is an
// order with the certificate authority, so a crash loop spends its rate limits
// in minutes. A failed attempt is retried after a delay that doubles from one
// minute to an hour. Until a certificate is held, handshakes are refused.
func (w *wildcardCert) keep(stop <-chan struct{}) error {
	obtain := w.obtain
	if obtain == nil {
		obtain = w.ensure
	}
	shortest, longest := firstRetry, lastRetry
	go func() {
		delay := shortest
		for {
			wait := 12 * time.Hour
			if err := obtain(); err != nil {
				w.logger.Error("obtain the certificate; trying again later", "apex", w.apex, "retry_in", delay.String(), "error", err)
				wait = delay
				if delay *= 2; delay > longest {
					delay = longest
				}
			} else {
				delay = shortest
			}
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
		}
	}()
	return nil
}

// How soon a failed certificate attempt is tried again, at first and at most.
var (
	firstRetry = time.Minute
	lastRetry  = time.Hour
)

// resolvers are the public resolvers the challenge record is checked through:
// RELAY_ACME_RESOLVERS (host:port, comma-separated) or two well-known ones.
func (w *wildcardCert) resolvers() []string {
	if v := strings.TrimSpace(os.Getenv("RELAY_ACME_RESOLVERS")); v != "" {
		var out []string
		for _, r := range strings.Split(v, ",") {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		return out
	}
	return []string{"1.1.1.1:53", "8.8.8.8:53"}
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
	// The challenge record is checked through public resolvers. A platform's
	// own resolver can keep answering from a cache, and a CNAME it still
	// remembers sent the record to a zone this relay cannot write.
	if err := client.Challenge.SetDNS01Provider(w.provider, dns01.AddRecursiveNameservers(w.resolvers())); err != nil {
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
		Domains: w.domains, Bundle: true,
	})
	if err != nil {
		return fmt.Errorf("obtain the certificate for %v: %w", w.domains, err)
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

// covers reports whether a cached certificate names every domain wanted, so a
// changed configuration obtains a new one rather than serving the old.
func covers(c *tls.Certificate, domains []string) bool {
	if c.Leaf == nil {
		return false
	}
	have := map[string]bool{}
	for _, d := range c.Leaf.DNSNames {
		have[d] = true
	}
	for _, d := range domains {
		if !have[d] {
			return false
		}
	}
	return true
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
