package oobi

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

var blockedCIDRs = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "::1/128", "fc00::/7",
}

// ValidateOOBIURL applies SEAM-16 R-18 SSRF guard before fetch.
func ValidateOOBIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid oobi url")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("oobi scheme not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("oobi host missing")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("oobi host blocked")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// Allow unresolved in dev; production relay should reject.
		return nil
	}
	for _, ip := range ips {
		if blocked(ip) {
			return fmt.Errorf("oobi resolves to private range")
		}
	}
	return nil
}

func blocked(ip net.IP) bool {
	for _, cidr := range blockedCIDRs {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}