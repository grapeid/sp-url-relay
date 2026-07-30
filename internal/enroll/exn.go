package enroll

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// ExnToken is the KERI-signed exn enrollment credential (SEAM-16 OQ-2 @beta).
type ExnToken struct {
	V  string                 `json:"v"`
	T  string                 `json:"t"`
	P  string                 `json:"p"`
	Dt string                 `json:"dt"`
	R  string                 `json:"r"`
	A  map[string]interface{} `json:"a"`
	D  string                 `json:"d"`
	I  string                 `json:"i"`
	S  string                 `json:"s,omitempty"`
}

// IssueToken mints an enrollment exn for the enrollment AID (relay-issued ack).
func IssueToken(relayAID, enrollmentAID string) (string, *ExnToken, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	token := &ExnToken{
		V:  "KERI10JSON",
		T:  "exn",
		P:  relayAID,
		Dt: now,
		R:  "/enroll/ack",
		A: map[string]interface{}{
			"enrollment_aid": enrollmentAID,
			"enrolled_at":    now,
			"protocol":       "IARELAY10JSON",
		},
		D: randomSAID(),
		I: enrollmentAID,
	}
	raw, err := json.Marshal(token)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(raw), token, nil
}

// ParseAuthorization decodes Authorization header to exn JSON.
func ParseAuthorization(auth string) (*ExnToken, error) {
	auth = trimBearer(auth)
	raw, err := base64.RawURLEncoding.DecodeString(auth)
	if err != nil {
		raw = []byte(auth)
	}
	var tok ExnToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("invalid enrollment token")
	}
	if tok.T != "exn" || tok.I == "" {
		return nil, fmt.Errorf("not an enrollment exn")
	}
	return &tok, nil
}

func trimBearer(s string) string {
	if len(s) > 7 && (s[:7] == "Bearer " || s[:7] == "bearer ") {
		return s[7:]
	}
	return s
}

func randomSAID() string {
	// 32 bytes, because that is what the shape requires: a Blake3-256 SAID is
	// "E" followed by 43 base64url characters, and 43 characters is exactly
	// what 32 bytes encode to. This used to take 16 bytes and slice [:43] from
	// the 22 characters they produce, which panicked on every call — so
	// issuing an enrollment token has never once succeeded.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Unreachable in practice, and not worth returning an error for: a
		// system that cannot produce randomness cannot issue tokens safely
		// anyway, and a silently predictable one would be worse than a panic.
		panic("no randomness available for token generation: " + err.Error())
	}
	return "E" + base64.RawURLEncoding.EncodeToString(b)
}
