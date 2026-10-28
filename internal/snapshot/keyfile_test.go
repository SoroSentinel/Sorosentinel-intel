package snapshot

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Keys here are generated per test run; no key material is committed.
func pemKey(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func writeKey(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadEd25519KeyFile(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadEd25519KeyFile(writeKey(t, pemKey(t, priv), 0o600), "test-only-key")
	if err != nil {
		t.Fatal(err)
	}
	if !s.PublicKey().Equal(pub) || s.KeyID() != "test-only-key" {
		t.Fatal("loaded a different key")
	}
	snap, err := Build(Input{Network: "testnet", Version: 1, GeneratedAt: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC), RulesetVersion: "2026.10.1"}, s)
	if err != nil || Verify(snap, pub) != nil {
		t.Fatalf("signer from file does not verify: %v", err)
	}
}

func TestLoadEd25519KeyFileRejects(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := pemKey(t, priv)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]struct {
		body []byte
		mode os.FileMode
		id   string
	}{
		"group readable": {good, 0o640, "k"},
		"world readable": {good, 0o604, "k"},
		"not ed25519":    {pemKey(t, ec), 0o600, "k"},
		"two blocks":     {append(append([]byte{}, good...), good...), 0o600, "k"},
		"wrong type":     {[]byte(strings.Replace(string(good), "PRIVATE KEY", "PUBLIC KEY", 2)), 0o600, "k"},
		"not pem":        {[]byte("hello"), 0o600, "k"},
		"bad der":        {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), 0o600, "k"},
		"too large":      {append(good, make([]byte, 5000)...), 0o600, "k"},
		"bad key id":     {good, 0o600, "Bad ID"},
	}
	for name, c := range cases {
		_, err := LoadEd25519KeyFile(writeKey(t, c.body, c.mode), c.id)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// Errors must never carry key bytes.
		if strings.Contains(err.Error(), "MC4CAQ") || strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: error leaks key material: %v", name, err)
		}
	}
	if _, err := LoadEd25519KeyFile(filepath.Join(t.TempDir(), "missing.pem"), "k"); err == nil {
		t.Error("accepted a missing file")
	}
	if _, err := LoadEd25519KeyFile(t.TempDir(), "k"); err == nil {
		t.Error("accepted a directory")
	}
}
