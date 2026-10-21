package relay

import (
	"regexp"
	"strings"
)

// builtinReserved are names nobody may claim: the relay's own endpoints,
// which share the path space with names, and names a person would read as the
// operator speaking.
var builtinReserved = []string{
	"tunnel", "allocate", "bind", "release", "names", "domains", "health",
	"well-known", "login", "logout", "signin", "signup", "support", "help",
	"admin", "administrator", "root", "www", "api", "relay", "status", "security",
	"abuse", "postmaster", "hostmaster", "webmaster", "mail", "about", "account",
	"billing", "docs", "official", "verify", "oobi", "didcomm", "public", "connect",
}

func reservedNames(extra []string) map[string]bool {
	m := map[string]bool{}
	for _, n := range builtinReserved {
		m[n] = true
	}
	for _, n := range extra {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			m[n] = true
		}
	}
	return m
}

// A name is 3 to 32 characters of lowercase letters, digits and inner
// hyphens: something a person can read aloud and type.
var nameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,30})[a-z0-9]$`)

func validName(n string) bool {
	return nameRE.MatchString(n) && !strings.Contains(n, "--")
}

// A private label is what relayproto.NewAllocationToken makes: 26 characters
// of lowercase base32.
var labelRE = regexp.MustCompile(`^[a-z2-7]{26}$`)

func validLabel(l string) bool { return labelRE.MatchString(l) }

var domainLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// validDomain reports whether d is a host name a custom domain may be: at
// least two labels, each a valid DNS label, at most 253 characters, and not
// the relay's own apex or anything under it.
func validDomain(d, apex string) bool {
	if len(d) > 253 || d == apex || strings.HasSuffix(d, "."+apex) {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !domainLabelRE.MatchString(l) {
			return false
		}
	}
	// The last label is a top-level domain, never all digits: that would be an
	// IP address.
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}
