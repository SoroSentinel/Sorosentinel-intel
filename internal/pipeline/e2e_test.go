package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/assetlookalike"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

// End-to-end tests need a disposable Postgres 16 server; see
// internal/store/store_test.go for a docker command. Each test creates and
// drops its own database.
const dbEnv = "INTEL_TEST_DATABASE_URL"

func freshDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv(dbEnv)
	if url == "" {
		t.Skip(dbEnv + " is unset; skipping the Postgres end-to-end test (see internal/store/store_test.go for setup)")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	name := "intel_e2e_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") //nolint:errcheck
		admin.Close(ctx)
	})
	if _, err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

// memSource is an ingest.Source over synthetic ledgers.
type memSource struct{ ledgers []xdrtest.Ledger }

func (s memSource) NetworkPassphrase(context.Context) (string, error) {
	return ingest.TestnetPassphrase, nil
}

func (s memSource) Range(context.Context) (ingest.Range, error) {
	return ingest.Range{Oldest: s.ledgers[0].Seq, Latest: s.ledgers[len(s.ledgers)-1].Seq}, nil
}

func (s memSource) Ledgers(_ context.Context, start, limit uint32) ([]ingest.RawLedger, error) {
	var out []ingest.RawLedger
	for _, l := range s.ledgers {
		if l.Seq >= start && uint32(len(out)) < limit {
			h := xdrtest.Hash(l.Seq)
			out = append(out, ingest.RawLedger{Sequence: l.Seq, Hash: hex.EncodeToString(h[:]), Meta: l.Bytes()})
		}
	}
	return out, nil
}

// runE2E feeds trustlines (holder, code, issuer) through ingestion, the
// pipeline and Postgres, publishes a snapshot, and returns it.
func runE2E(t *testing.T, trustlines [][3]any) (snapshot.Snapshot, *store.Postgres) {
	t.Helper()
	pool := freshDB(t)
	ctx := context.Background()
	lock, err := store.AcquireWriter(ctx, pool, entity.Testnet)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release(ctx)

	var ops []xdr.LedgerEntryChanges
	for _, tl := range trustlines {
		ops = append(ops, xdr.LedgerEntryChanges{xdrtest.Created(xdrtest.Trustline(tl[0].(byte), tl[1].(string), tl[2].(byte)))})
	}
	// Ledger 200 is empty, 201 carries the trustlines.
	src := memSource{ledgers: xdrtest.Chain(200, 201, map[uint32][]xdr.LedgerEntryChanges{201: ops})}

	st := store.New(pool)
	ref, err := assetlookalike.NewReference(map[string][]string{"USDC": {refIssuer}, "XLM": {}})
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Unix(1_790_000_000+201*5, 0).Add(time.Minute).UTC()}
	pl, err := New(ctx, Config{Network: entity.Testnet, Reference: ref, Ruleset: verdict.V1, Now: clk.Now},
		st, &fakeDomains{domains: map[string]string{lookIssuer: "", refIssuer: ""}}, &fakeFetcher{})
	if err != nil {
		t.Fatal(err)
	}
	in, err := ingest.New(ingest.Config{Network: entity.Testnet, StartLedger: 200, PageSize: 1}, src, store.NewCheckpoint(pool), pl)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	for range 2 {
		if n, err := in.Step(ctx); err != nil || n != 1 {
			t.Fatalf("step: %d, %v", n, err)
		}
	}
	if n, err := in.Step(ctx); err != nil || n != 0 {
		t.Fatalf("caught-up step: %d, %v", n, err)
	}
	if last, ok, _ := store.NewCheckpoint(pool).Last(ctx, entity.Testnet); !ok || last != 201 {
		t.Fatalf("checkpoint = %d", last)
	}

	signer, pub := testSigner(t)
	dir := t.TempDir()
	pub0 := &Publisher{Network: entity.Testnet, Dir: dir, RulesetVersion: verdict.V1.Version, Signer: signer, Store: st}
	if _, err := pub0.Publish(ctx, clk.t); err != nil {
		t.Fatal(err)
	}
	s := readSnapshot(t, filepath.Join(dir, LatestName(entity.Testnet)))
	if err := snapshot.Verify(s, pub); err != nil {
		t.Fatalf("published snapshot does not verify: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM snapshot WHERE network = 'testnet' AND version = $1
		AND object_key = $2`, int64(s.Version), VersionedName(entity.Testnet, s.Version)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("snapshot row missing: %d, %v", count, err)
	}
	return s, st
}

func TestEndToEndLookalikeLandsInSignedSnapshot(t *testing.T) {
	s, st := runE2E(t, [][3]any{
		{byte(3), "USDC", byte(2)}, // look-alike: reference code, unknown issuer
		{byte(4), "USDC", byte(1)}, // the reference issuer itself
	})
	canonical, err := entity.Canonical(entity.Testnet, entity.Asset, "USDC:"+lookIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 1 || s.Entries[0] != entity.SnapshotHash(canonical) {
		t.Fatalf("entries = %v, want [%s]", s.Entries, entity.SnapshotHash(canonical))
	}

	// The stored verdict replays from its stored evidence, as_of and ruleset.
	ctx := context.Background()
	id, err := st.UpsertEntity(ctx, entity.Testnet, entity.Asset, "USDC:"+lookIssuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := st.Verdict(ctx, id)
	if err != nil || v == nil || v.Level != signal.Suspicious {
		t.Fatalf("verdict = %+v, %v", v, err)
	}
	d, err := st.Replay(ctx, id)
	if err != nil || d.Level != v.Level || d.RuleID != v.RuleID {
		t.Fatalf("replay = %+v, %v", d, err)
	}
}

func TestEndToEndReferenceIssuerProducesNoEntry(t *testing.T) {
	s, _ := runE2E(t, [][3]any{{byte(4), "USDC", byte(1)}})
	if len(s.Entries) != 0 {
		t.Fatalf("entries = %v for the reference issuer", s.Entries)
	}
}
