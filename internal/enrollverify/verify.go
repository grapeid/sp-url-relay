// Package enrollverify binds an enrolling key to the AID it claims.
//
// Enrollment asks two questions and needs both answered. A signature over the
// request proves the caller HOLDS the key it presents. Nothing in the request
// proves that key BELONGS to the AID named alongside it — the AID is just a
// string field, and the key is public. Answering the second question means
// reading the identity's key event log, and only the log can answer it.
//
// The log is checked here, in process, using keri-go. It does not need to come
// from a trusted source: a KERI identifier is a digest of its own inception
// event, so a log fabricated with the attacker's keys derives a different AID
// and fails, while a replay of the victim's genuine log establishes the
// victim's keys, which the attacker cannot sign with. The sender may therefore
// hand us the log directly — which matters, because agents reach the internet
// through this relay's tunnel, and at enrollment time there is not yet a tunnel
// to fetch anything back through.
package enrollverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	keri "github.com/grapeid/keri-go"
)

type Result struct {
	Verified bool
	// Reason is written for whoever reads the rejection, not for a log grep.
	Reason string
}

// Verifier answers whether publicKeyB64 is authoritative for aid, given the
// key event log presented as a CESR stream.
type Verifier interface {
	Enabled() bool
	Verify(aid, publicKeyB64 string, kelCESR []byte) Result
}

// Unverified accepts anything. Anyone can enroll any AID and take over its
// relay presence; it exists so that choice has to be made out loud.
type Unverified struct{}

func (Unverified) Enabled() bool { return false }

func (Unverified) Verify(string, string, []byte) Result {
	return Result{Verified: true}
}

// Local validates the key log in process with keri-go.
type Local struct{}

func (Local) Enabled() bool { return true }

func (Local) Verify(aid, publicKeyB64 string, kelCESR []byte) Result {
	if len(kelCESR) == 0 {
		return Result{Reason: "a key event log is required: without one there is " +
			"nothing to check this key against"}
	}

	messages, err := keri.ParseKELStream(kelCESR)
	if err != nil {
		return Result{Reason: "the key event log could not be read as a CESR stream: " + err.Error()}
	}

	// ValidateSignedKEL checks inception derivation, chaining, pre-rotation and
	// the signatures on every event against the key state in force at that
	// point — not against whatever keys an event happens to carry.
	state, err := keri.ValidateSignedKEL(messages)
	if err != nil {
		return Result{Reason: "the key event log did not verify: " + err.Error()}
	}

	if state.Identifier != aid {
		// The honest version of this — a log pasted for the wrong identity —
		// looks identical to the dishonest one, so name both sides.
		return Result{Reason: fmt.Sprintf(
			"that key event log establishes %s, not %s", state.Identifier, aid)}
	}

	want, err := decodeKey(publicKeyB64)
	if err != nil {
		return Result{Reason: "the public key presented is unreadable: " + err.Error()}
	}

	for _, k := range state.Keys {
		have, err := qb64Key(k)
		if err != nil {
			continue
		}
		if bytes.Equal(have, want) {
			return Result{Verified: true}
		}
	}

	// The key is real and the AID is real; they are just not each other's.
	// Most often this is an agent enrolling with a key it has since rotated
	// away from.
	return Result{Reason: "the key presented is not among this identity's current signing keys"}
}

// qb64Key converts a CESR-qualified verification key to its raw bytes. The
// leading character is the derivation code — 'D' for a transferable Ed25519
// key, 'B' for a non-transferable one — and both are 32 raw bytes underneath.
func qb64Key(k string) ([]byte, error) {
	if k == "" {
		return nil, fmt.Errorf("empty key")
	}
	return keri.MatterRaw(k[:1], k, ed25519.PublicKeySize)
}

// decodeKey accepts standard and url-safe base64, padded or unpadded, matching
// what the signing path already tolerates: agents encode signatures url-safe
// and unpadded while keys arrive standard-padded, and rejecting one spelling
// fails valid requests for a reason nobody can see.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil {
			if len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("key is %d bytes, expected %d", len(raw), ed25519.PublicKeySize)
			}
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}
