package relay

import (
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// Control requests are signed over the published form: this relay produces
// every vector's bytes and refuses every input the form refuses.
func TestControlRequestsAreSignedOverThePublishedVectors(t *testing.T) {
	set, err := relayproto.SigningVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range set.Vectors {
		fields := map[string]any{}
		for k, s := range v.Fields {
			fields[k] = s
		}
		got, err := canonicalControl(fields)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(got) != v.Canonical {
			t.Fatalf("%s:\n got  %s\n want %s", v.Name, got, v.Canonical)
		}
	}
	for _, r := range set.Refused {
		if _, err := canonicalControl(r.Fields); err == nil {
			t.Fatalf("%s was signed; it must be refused", r.Name)
		}
	}
}
