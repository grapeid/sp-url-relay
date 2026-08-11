package hostname

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// Base58 alphabet without 0, O, I, l (relay-blind CSPRNG tokens).
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// MinLen is the shortest acceptable token. 8 base58 characters is ~200 billion
// combinations; the subdomain scheme needed that against wildcard-DNS
// enumeration, and it is retained because the token is still a public
// unauthenticated identifier.
const MinLen = 8

// Valid reports whether s is a well-formed allocation token: 8+ characters,
// base58 only. Inbound requests are unauthenticated, so this rejects junk
// before it reaches the store rather than turning every stray crawler path
// into a database lookup.
func Valid(s string) bool {
	if len(s) < MinLen {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

// Mint returns an n-character base58 hostname token (SEAM-16 §2, Decision 6).
func Mint(n int) (string, error) {
	if n < 8 {
		n = 8
	}
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("csprng: %w", err)
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}