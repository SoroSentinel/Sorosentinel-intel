package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
)

func TestRunWritesKeyTheWorkerLoads(t *testing.T) {
	dir := t.TempDir()
	pub, kept, err := run(dir)
	if err != nil || kept {
		t.Fatalf("run: kept=%v err=%v", kept, err)
	}
	if b, err := hex.DecodeString(pub); err != nil || len(b) != 32 {
		t.Fatalf("public key %q is not 32 hex bytes", pub)
	}
	fi, err := os.Stat(filepath.Join(dir, "signing-key.pem"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", fi, err)
	}
	if _, err := snapshot.LoadEd25519KeyFile(filepath.Join(dir, "signing-key.pem"), "demo-test-key"); err != nil {
		t.Fatalf("worker cannot load the key: %v", err)
	}

	again, kept, err := run(dir)
	if err != nil || !kept || again != pub {
		t.Fatalf("second run must keep the key: kept=%v same=%v err=%v", kept, again == pub, err)
	}
}

func TestRunNeverOverwritesAnOrphanKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing-key.pem")
	if err := os.WriteFile(keyPath, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(dir); err == nil {
		t.Fatal("run overwrote a key file without its public key")
	}
	if b, _ := os.ReadFile(keyPath); string(b) != "not ours" {
		t.Fatal("existing key file was changed")
	}
}
