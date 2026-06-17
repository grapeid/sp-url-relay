package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalBody returns deterministic JSON bytes for signing (body minus signature).
func CanonicalBody(v interface{}) ([]byte, error) {
	m, err := toMap(v)
	if err != nil {
		return nil, err
	}
	delete(m, "signature")
	return marshalSorted(m)
}

func VerifyEd25519(publicKeyB64, signatureB64 string, body []byte) error {
	pubRaw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("invalid public key encoding")
	}
	if len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("public key length %d", len(pubRaw))
	}
	sigRaw, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), body, sigRaw) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

func toMap(v interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func marshalSorted(m map[string]interface{}) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}