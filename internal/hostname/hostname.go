package hostname

import (
	"crypto/rand"
	"fmt"
	"math/big"

)

// Base58 alphabet without 0, O, I, l (relay-blind CSPRNG tokens).
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

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