package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

func testSigner(t *testing.T) (*snapshot.Ed25519Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.NewEd25519Signer("test-only-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, pub
}

func readSnapshot(t *testing.T, path string) snapshot.Snapshot {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s snapshot.Snapshot
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPublishWritesSignedVersionedAndLatest(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.p.Ledger(ctx, facts(100, usdc(lookIssuer))); err != nil {
		t.Fatal(err)
	}
	signer, pub := testSigner(t)
	dir := t.TempDir()
	p := &Publisher{Network: entity.Testnet, Dir: dir, RulesetVersion: verdict.V1.Version, Signer: signer, Store: h.st}

	gen := time.Date(2026, 10, 28, 12, 5, 0, 999, time.UTC)
	s, err := p.Publish(ctx, gen)
	if err != nil {
		t.Fatal(err)
	}
	want := entity.SnapshotHash("testnet|asset|USDC:" + lookIssuer)
	if s.Version != 1 || len(s.Entries) != 1 || s.Entries[0] != want || s.GeneratedAt != "2026-10-28T12:05:00Z" {
		t.Fatalf("snapshot = %+v", s)
	}
	for _, name := range []string{"snapshot-testnet-1.json", "snapshot-testnet-latest.json"} {
		got := readSnapshot(t, filepath.Join(dir, name))
		if err := snapshot.Verify(got, pub); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if got.Signature != s.Signature {
			t.Errorf("%s differs from the published snapshot", name)
		}
	}
	rec := h.st.snapshots[0]
	if rec.Version != 1 || rec.EntryCount != 1 || rec.ObjectKey != "snapshot-testnet-1.json" ||
		rec.SigningKeyID != "test-only-key" || len(rec.Signature) != ed25519.SignatureSize || !rec.GeneratedAt.Equal(gen.Truncate(time.Second)) {
		t.Errorf("record = %+v", rec)
	}

	s2, err := p.Publish(ctx, gen.Add(5*time.Minute))
	if err != nil || s2.Version != 2 {
		t.Fatalf("second publish: %+v, %v", s2, err)
	}
	if got := readSnapshot(t, filepath.Join(dir, "snapshot-testnet-latest.json")); got.Version != 2 {
		t.Errorf("latest is version %d", got.Version)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*tmp*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestPublishEmptySnapshot(t *testing.T) {
	signer, pub := testSigner(t)
	p := &Publisher{Network: entity.Testnet, Dir: t.TempDir(), RulesetVersion: verdict.V1.Version, Signer: signer, Store: newMemStore()}
	s, err := p.Publish(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 0 || snapshot.Verify(s, pub) != nil {
		t.Errorf("empty snapshot = %+v", s)
	}
}

func TestPublishRecordFailureKeepsLatest(t *testing.T) {
	st := newMemStore()
	signer, _ := testSigner(t)
	dir := t.TempDir()
	p := &Publisher{Network: entity.Testnet, Dir: dir, RulesetVersion: verdict.V1.Version, Signer: signer, Store: st}
	if _, err := p.Publish(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	st.recordErr = errors.New("db down")
	if _, err := p.Publish(context.Background(), t0.Add(time.Minute)); err == nil {
		t.Fatal("record failure was swallowed")
	}
	if got := readSnapshot(t, filepath.Join(dir, LatestName(entity.Testnet))); got.Version != 1 {
		t.Errorf("latest moved to unrecorded version %d", got.Version)
	}
}

func TestPublishRejectsMissingConfig(t *testing.T) {
	if _, err := (&Publisher{Network: entity.Testnet}).Publish(context.Background(), t0); err == nil {
		t.Error("accepted a publisher without dir, signer and store")
	}
	signer, _ := testSigner(t)
	p := &Publisher{Network: entity.Testnet, Dir: filepath.Join(t.TempDir(), "missing"), RulesetVersion: verdict.V1.Version, Signer: signer, Store: newMemStore()}
	if _, err := p.Publish(context.Background(), t0); err == nil {
		t.Error("wrote into a directory that does not exist")
	}
}

func TestLoadReference(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "ref.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ref, err := LoadReference(write(`{"USDC": ["` + refIssuer + `"], "XLM": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if evs, _ := ref.Detect(entity.Testnet, "USDC:"+lookIssuer, t0); len(evs) != 1 {
		t.Errorf("loaded reference does not flag a look-alike")
	}
	for _, bad := range []string{
		``,
		`[]`,
		`{"USDC": "` + refIssuer + `"}`,
		`{"USDC": [1]}`,
		`{"USDC": [], "USDC": []}`,
		`{"USDC": ["not-an-issuer"]}`,
		`{"US DC": []}`,
		`{}`,
		`{"XLM": []} {}`,
		`{"XLM": [], }`,
	} {
		if _, err := LoadReference(write(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := LoadReference(write(`{"XLM": [` + strings.Repeat(`"`+refIssuer+`",`, 20000) + `"` + refIssuer + `"]}`)); err == nil {
		t.Error("accepted an oversized file")
	}
}

// The reviewed testnet reference file in config/ must load.
func TestCommittedTestnetReferenceLoads(t *testing.T) {
	if _, err := LoadReference(filepath.Join("..", "..", "config", "reference-assets.testnet.json")); err != nil {
		t.Fatal(err)
	}
}
