package enrollverify

import (
	"encoding/base64"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// realIdentity mints an actual KERI identity and returns its AID, its current
// signing key in the base64 form the enrollment request carries, and its key
// log as a CESR stream. Nothing here is a fixture — the log is produced by the
// same library that will be asked to verify it.
func realIdentity(t *testing.T, name string) (aid, pubB64 string, kel []byte) {
	t.Helper()
	chain, err := keri.NewKeychain(keri.NewMemoryKeyStore(), name, 1)
	if err != nil {
		t.Fatalf("keychain: %v", err)
	}
	keys, err := chain.CurrentKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	next, err := chain.NextDigests()
	if err != nil {
		t.Fatalf("next digests: %v", err)
	}
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: keys, NextDigests: next})
	if err != nil {
		t.Fatalf("incept: %v", err)
	}
	signed, err := keri.SignEvent(icp, chain.Signers()...)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	stream, err := keri.ExportKEL([][]byte{signed.Message})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	msgs, err := keri.ParseKELStream(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	state, err := keri.ValidateSignedKEL(msgs)
	if err != nil {
		t.Fatalf("the log this test just produced does not verify: %v", err)
	}
	raw, err := qb64Key(state.Keys[0])
	if err != nil {
		t.Fatalf("key decode: %v", err)
	}
	return state.Identifier, base64.StdEncoding.EncodeToString(raw), stream
}

func TestAcceptsTheRealOwner(t *testing.T) {
	aid, pub, kel := realIdentity(t, "owner")
	if r := (Local{}).Verify(aid, pub, kel); !r.Verified {
		t.Fatalf("the real owner was refused: %s", r.Reason)
	}
}

// The attack the whole check exists to stop: claim somebody else's AID while
// presenting a key you generated yourself. The signature over the request would
// verify perfectly — it is made with the key being offered.
func TestRefusesAnotherIdentitysAID(t *testing.T) {
	victimAID, _, _ := realIdentity(t, "victim")
	_, attackerPub, attackerKEL := realIdentity(t, "attacker")

	r := (Local{}).Verify(victimAID, attackerPub, attackerKEL)
	if r.Verified {
		t.Fatal("an attacker enrolled somebody else's AID")
	}
	if !strings.Contains(r.Reason, "establishes") {
		t.Errorf("reason should name both identities, got: %s", r.Reason)
	}
}

// A real log for the right AID, but presenting a key that is not in it.
func TestRefusesAKeyNotInTheLog(t *testing.T) {
	aid, _, kel := realIdentity(t, "owner")
	_, otherPub, _ := realIdentity(t, "other")

	r := (Local{}).Verify(aid, otherPub, kel)
	if r.Verified {
		t.Fatal("a key absent from the log was accepted")
	}
}

func TestRefusesMissingOrCorruptLog(t *testing.T) {
	aid, pub, kel := realIdentity(t, "owner")

	if r := (Local{}).Verify(aid, pub, nil); r.Verified {
		t.Error("an absent log was accepted")
	}
	if r := (Local{}).Verify(aid, pub, []byte("not a CESR stream")); r.Verified {
		t.Error("garbage was accepted as a log")
	}

	// Flip a byte in the middle of the stream: the digests must not survive it.
	tampered := make([]byte, len(kel))
	copy(tampered, kel)
	tampered[len(tampered)/2] ^= 0xFF
	if r := (Local{}).Verify(aid, pub, tampered); r.Verified {
		t.Error("a tampered log was accepted")
	}
}

// Unverified is the escape hatch; it must be unmistakably open.
func TestUnverifiedAcceptsAnything(t *testing.T) {
	if (Unverified{}).Enabled() {
		t.Error("Unverified must report itself disabled")
	}
	if r := (Unverified{}).Verify("EAnything", "not-a-key", nil); !r.Verified {
		t.Error("Unverified should accept")
	}
}

func TestDecodeKeyAcceptsEveryBase64Spelling(t *testing.T) {
	_, pub, _ := realIdentity(t, "owner")
	raw, err := decodeKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		got, err := decodeKey(enc.EncodeToString(raw))
		if err != nil {
			t.Errorf("spelling rejected: %v", err)
			continue
		}
		if string(got) != string(raw) {
			t.Error("decoded to different bytes")
		}
	}
}
