package relay

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// LoadCertPool reads PEM certificates from a file: the authority a CDN signs
// its origin-pull client certificates with. An empty path means none.
func LoadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the origin-pull authority: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return pool, nil
}

// LoadNetworks reads CIDR ranges, one per line (# comments allowed): the
// networks a CDN's connections come from, as it publishes them. An empty path
// means none.
func LoadNetworks(path string) ([]*net.IPNet, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the trusted proxy ranges: %w", err)
	}
	defer f.Close()
	var out []*net.IPNet
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a CIDR range", path, line)
		}
		out = append(out, n)
	}
	return out, sc.Err()
}

// HandleHostCheck answers GET ?host=<host> with 200 when this relay serves
// the host and 404 when it does not. It is for an SNI router on the same
// machine, deciding where a connection naming a custom domain goes; serve it
// on loopback only.
func (s *Server) HandleHostCheck(w http.ResponseWriter, r *http.Request) {
	if s.HostAllowed(hostOnly(r.URL.Query().Get("host"))) {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}
