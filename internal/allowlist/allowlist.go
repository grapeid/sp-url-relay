package allowlist

import (
	"regexp"
	"strings"
)

var aidPattern = regexp.MustCompile(`^E[A-Za-z0-9_-]{43,}$`)

// Allowed reports whether method+path is on the SEAM-16 §5 allowlist (GET-only v1).
func Allowed(method, path string) bool {
	if method != "GET" {
		return false
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	if path == "/.well-known/did-configuration.json" {
		return true
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 2 {
		return false
	}
	aid := segments[0]
	if segments[0] == "oobi" && len(segments) == 2 {
		return aidPattern.MatchString(segments[1])
	}
	if !aidPattern.MatchString(aid) {
		return false
	}
	switch segments[1] {
	case "did.json", "kel", "keri.cesr", "oobi":
		return len(segments) == 2
	default:
		return false
	}
}