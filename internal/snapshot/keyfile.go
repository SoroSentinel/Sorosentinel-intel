package snapshot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

const maxKeyFileBytes = 4 << 10

// LoadEd25519KeyFile reads a PEM "PRIVATE KEY" (PKCS#8 Ed25519, as written by
// `openssl genpkey -algorithm ed25519`) and returns a signer for keyID.
//
// This is the interim path until the KMS signer exists: the file must be
// readable by its owner only, and no error ever contains key bytes.
func LoadEd25519KeyFile(path, keyID string) (*Ed25519Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot: open signing key file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("snapshot: stat signing key file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("snapshot: signing key file is not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("snapshot: signing key file must not be readable by group or others (chmod 600)")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, errors.New("snapshot: read signing key file failed")
	}
	if len(b) > maxKeyFileBytes {
		return nil, errors.New("snapshot: signing key file too large")
	}
	block, rest := pem.Decode(b)
	extra := len(bytes.TrimSpace(rest))
	clear(b)
	if block == nil || block.Type != "PRIVATE KEY" || extra != 0 {
		return nil, errors.New("snapshot: signing key file must hold exactly one PEM PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil {
		return nil, errors.New("snapshot: signing key is not a valid PKCS#8 key")
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("snapshot: signing key is not Ed25519")
	}
	return NewEd25519Signer(keyID, priv)
}

// PublicKey returns the signer's public key, which Guard pins (32 raw bytes).
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}
