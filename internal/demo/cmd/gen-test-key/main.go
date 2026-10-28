// Command gen-test-key writes a THROWAWAY Ed25519 snapshot signing key for
// the local demo stack (deploy/docker-compose.yml, docs/runbooks/local-demo.md).
//
// TEST ONLY. Production signing keys live in KMS and are never generated or
// written to disk like this. The private key goes to <dir>/signing-key.pem
// (PEM PKCS#8, mode 0600, the format snapshot.LoadEd25519KeyFile reads); the
// public key Guard pins goes to <dir>/pubkey.hex (32 raw bytes, hex). If the
// key file already exists it is kept, so restarting the stack keeps its key.
// It prints only the public key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	dir := flag.String("dir", "", "directory to write signing-key.pem and pubkey.hex to (required)")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "gen-test-key: -dir is required")
		os.Exit(2)
	}
	pub, kept, err := run(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-test-key:", err)
		os.Exit(1)
	}
	state := "generated"
	if kept {
		state = "kept existing"
	}
	fmt.Printf("TEST-ONLY snapshot signing key %s; public key %s\n", state, pub)
}

func run(dir string) (pubHex string, kept bool, err error) {
	keyPath := filepath.Join(dir, "signing-key.pem")
	pubPath := filepath.Join(dir, "pubkey.hex")
	if b, err := os.ReadFile(pubPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return string(b), true, nil
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", false, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	clear(priv)
	if err != nil {
		return "", false, err
	}
	defer clear(der)

	// O_EXCL: never overwrite a key file this run did not create.
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", false, fmt.Errorf("create key file: %w", err)
	}
	werr := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", false, errors.Join(errors.New("write key file failed"), os.Remove(keyPath))
	}
	pubHex = hex.EncodeToString(pub)
	if err := os.WriteFile(pubPath, []byte(pubHex), 0o644); err != nil {
		return "", false, fmt.Errorf("write public key: %w", err)
	}
	return pubHex, false, nil
}
