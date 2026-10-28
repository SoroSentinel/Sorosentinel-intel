package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

// Integration tests need a disposable Postgres 16 server, e.g.
//
//	docker run -d --rm --name intel-store-test -e POSTGRES_USER=intel \
//	  -e POSTGRES_PASSWORD=intel-test-only -p 127.0.0.1:55432:5432 postgres:16
//	INTEL_TEST_DATABASE_URL=postgres://intel:intel-test-only@127.0.0.1:55432/postgres make test-integration
//
// Each test creates and drops its own fresh database, so the migration is
// always exercised from scratch.
const dbEnv = "INTEL_TEST_DATABASE_URL"

func freshDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv(dbEnv)
	if url == "" {
		t.Skip(dbEnv + " is unset; skipping Postgres integration test (see store_test.go for setup)")
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
	name := "intel_test_" + hex.EncodeToString(b)
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
	return pool
}

func migrated(t *testing.T) (*Postgres, *pgxpool.Pool) {
	t.Helper()
	pool := freshDB(t)
	if _, err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(pool), pool
}

var (
	t0     = time.Date(2026, 10, 20, 9, 30, 0, 123456000, time.UTC)
	issuer = "GA" + strings.Repeat("A", 54)
	other  = "GB" + strings.Repeat("B", 54)
	sac    = "CA" + strings.Repeat("C", 54)
)

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

func TestMigrateFreshDatabase(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	ran, err := Migrate(ctx, pool)
	if err != nil || !slices.Equal(ran, []string{"0001_init.sql"}) {
		t.Fatalf("ran %v err %v", ran, err)
	}
	ran, err = Migrate(ctx, pool)
	if err != nil || len(ran) != 0 {
		t.Fatalf("second run: ran %v err %v", ran, err)
	}
	var tables []string
	rows, _ := pool.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1`)
	tables, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"entity", "entity_link", "evidence", "ingest_checkpoint", "public_statement",
		"schema_migrations", "snapshot", "source", "verdict", "verdict_events"}
	if !slices.Equal(tables, want) {
		t.Fatalf("tables %v, want %v (v1 cut list: no report/dispute/webhook/wording_template/scan_job)", tables, want)
	}
	var partitioned bool
	if err := pool.QueryRow(ctx, `SELECT relkind = 'p' FROM pg_class WHERE relname = 'evidence'`).Scan(&partitioned); err != nil || partitioned {
		t.Fatalf("evidence must be a plain table (partitioned=%v err=%v)", partitioned, err)
	}
	var scoreCols int
	pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'verdict'
		AND column_name IN ('score', 'confidence')`).Scan(&scoreCols) //nolint:errcheck
	if scoreCols != 0 {
		t.Fatal("verdict must not carry a numeric score")
	}
}

func TestMigrateRefusesEditedOrUnknownMigration(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	v1 := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a (id int);")}}
	if _, err := migrate(ctx, pool, v1); err != nil {
		t.Fatal(err)
	}
	edited := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a (id bigint);")}}
	if _, err := migrate(ctx, pool, edited); err == nil {
		t.Fatal("edited migration accepted")
	}
	if _, err := migrate(ctx, pool, fstest.MapFS{"0002_b.sql": {Data: []byte("SELECT 1;")}}); err == nil {
		t.Fatal("database ahead of the build accepted")
	}
	broken := fstest.MapFS{"0001_a.sql": v1["0001_a.sql"], "0002_b.sql": {Data: []byte("CREATE TABLE b (; CREATE TABLE c (id int);")}}
	if _, err := migrate(ctx, pool, broken); err == nil {
		t.Fatal("broken migration accepted")
	}
	var applied int
	pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied) //nolint:errcheck
	if applied != 1 {
		t.Fatalf("failed migration must roll back; %d recorded", applied)
	}
}

type fixture struct {
	s         *Postgres
	pool      *pgxpool.Pool
	heuristic int16
	curated   int16
	asset     int64
}

func setup(t *testing.T) fixture {
	t.Helper()
	s, pool := migrated(t)
	ctx := context.Background()
	h, err := s.EnsureSource(ctx, "intel-heuristics", evidence.Heuristic)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.EnsureSource(ctx, "analyst-desk", evidence.Curated)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := s.UpsertEntity(ctx, entity.Testnet, entity.Asset, "USDC:"+issuer, json.RawMessage(`{"holders": 3}`))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{s: s, pool: pool, heuristic: h, curated: c, asset: asset}
}

func (f fixture) lookalike(t *testing.T, entityID int64, observed time.Time, expires *time.Time) int64 {
	t.Helper()
	id, err := f.s.AppendEvidence(context.Background(), evidence.New{EntityID: entityID, SourceID: f.heuristic,
		Detector: evidence.DetectorAssetLookalike, Class: evidence.ClassOnchainPattern, Category: "impersonation_asset",
		Payload: json.RawMessage(`{"reference_code":"USDC"}`), ObservedAt: observed, ExpiresAt: expires, LedgerSeq: 1234})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEntityUpsertIsLazyAndNormalized(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	again, err := f.s.UpsertEntity(ctx, entity.Testnet, entity.Asset, "USDC:"+issuer, json.RawMessage(`{"home_domain":"example.com"}`))
	if err != nil || again != f.asset {
		t.Fatalf("upsert returned %d (%v), want %d", again, err, f.asset)
	}
	var attrs map[string]any
	f.pool.QueryRow(ctx, `SELECT attrs FROM entity WHERE id = $1`, f.asset).Scan(&attrs) //nolint:errcheck
	if attrs["holders"] == nil || attrs["home_domain"] != "example.com" {
		t.Fatalf("attrs not merged: %v", attrs)
	}
	// Same key on the other network is a different entity.
	pub, _ := f.s.UpsertEntity(ctx, entity.Public, entity.Asset, "USDC:"+issuer, nil)
	if pub == f.asset {
		t.Fatal("networks share an entity")
	}
	if _, err := f.s.UpsertEntity(ctx, entity.Testnet, entity.Account, "M"+strings.Repeat("A", 68), nil); err == nil {
		t.Fatal("muxed account accepted without normalization")
	}
	if _, err := f.s.UpsertEntity(ctx, "futurenet", entity.Account, issuer, nil); err == nil {
		t.Fatal("unknown network accepted")
	}
	if _, err := f.s.UpsertEntity(ctx, entity.Testnet, entity.Account, issuer, json.RawMessage(`[1]`)); err == nil {
		t.Fatal("non-object attrs accepted")
	}
	if _, err := f.s.EnsureSource(ctx, "intel-heuristics", evidence.Curated); err == nil {
		t.Fatal("source kind silently changed")
	}
}

func TestEvidenceIsAppendOnly(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := f.lookalike(t, f.asset, at(0), nil)
	if _, err := f.pool.Exec(ctx, `UPDATE evidence SET category = 'other' WHERE id = $1`, id); err == nil {
		t.Fatal("evidence UPDATE allowed")
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM evidence WHERE id = $1`, id); err == nil {
		t.Fatal("evidence DELETE allowed")
	}
	if _, err := f.pool.Exec(ctx, `TRUNCATE evidence CASCADE`); err == nil {
		t.Fatal("evidence TRUNCATE allowed")
	}
	// The database rejects a confirmation on an automated detector even if the Go check is bypassed.
	if _, err := f.pool.Exec(ctx, `INSERT INTO evidence (entity_id, source_id, detector, evidence_class, category,
		payload, observed_at, confirmed_level, confirmed_by) VALUES ($1, $2, 'D-ASSET-LOOKALIKE', 'onchain-pattern',
		'x', '{}', now(), 'malicious', 'someone')`, f.asset, f.heuristic); err == nil {
		t.Fatal("database accepted a confirmation from an automated detector")
	}
	// A confirmation from a non-curated source is refused by the store.
	_, err := f.s.AppendEvidence(ctx, evidence.New{EntityID: f.asset, SourceID: f.heuristic, Detector: evidence.DetectorCurated,
		Class: evidence.ClassHuman, Category: "impersonation_asset", Payload: json.RawMessage(`{}`), ObservedAt: at(0),
		ConfirmedLevel: signal.Malicious, ConfirmedBy: "analyst-1"})
	if err == nil {
		t.Fatal("confirmation from a heuristic source accepted")
	}
}

func TestRecomputeWritesVerdictAndEventTogether(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	if _, _, err := f.s.Recompute(ctx, f.asset, at(1), verdict.V1); !errors.Is(err, verdict.ErrNoEvidence) {
		t.Fatalf("verdict without evidence: %v", err)
	}
	if v, _ := f.s.Verdict(ctx, f.asset); v != nil {
		t.Fatal("verdict stored without evidence")
	}

	exp := at(48)
	e1 := f.lookalike(t, f.asset, at(0), &exp)
	v, changed, err := f.s.Recompute(ctx, f.asset, at(1), verdict.V1)
	if err != nil || !changed || v.Level != signal.Suspicious || v.Status != verdict.Active {
		t.Fatalf("recompute: %+v changed=%v err=%v", v, changed, err)
	}
	stored, err := f.s.Verdict(ctx, f.asset)
	if err != nil || stored == nil || !stored.AsOf.Equal(at(1)) || !slices.Equal(stored.EvidenceIDs, []int64{e1}) {
		t.Fatalf("stored %+v err %v", stored, err)
	}

	// Unchanged: no new event.
	if _, changed, err := f.s.Recompute(ctx, f.asset, at(2), verdict.V1); err != nil || changed {
		t.Fatalf("unchanged recompute changed=%v err=%v", changed, err)
	}
	// Human confirmation reaches malicious; expiry of automated evidence doesn't undo it.
	c, err := f.s.AppendEvidence(ctx, evidence.New{EntityID: f.asset, SourceID: f.curated, Detector: evidence.DetectorCurated,
		Class: evidence.ClassHuman, Category: "impersonation_asset", Payload: json.RawMessage(`{"ticket":"R-1"}`),
		ObservedAt: at(3), ConfirmedLevel: signal.Malicious, ConfirmedBy: "analyst-1", ArtifactRefs: []string{"artifacts/r-1.json"}})
	if err != nil {
		t.Fatal(err)
	}
	v, _, err = f.s.Recompute(ctx, f.asset, at(72), verdict.V1)
	if err != nil || v.Level != signal.Malicious || !slices.Equal(v.EvidenceIDs, []int64{e1, c}) {
		t.Fatalf("after confirmation: %+v %v", v, err)
	}

	if err := f.s.SetDisputed(ctx, f.asset, true, "analyst-2", "dispute mailbox 2026-10-23"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetDisputed(ctx, f.asset, true, verdict.EngineActor, ""); err == nil {
		t.Fatal("engine set a dispute")
	}

	type ev struct {
		To       string
		Disputed bool
		Actor    string
	}
	rows, _ := f.pool.Query(ctx, `SELECT to_level::text, to_disputed, actor FROM verdict_events WHERE entity_id = $1 ORDER BY id`, f.asset)
	events, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ev])
	if err != nil {
		t.Fatal(err)
	}
	want := []ev{{"suspicious", false, "engine"}, {"malicious", false, "engine"}, {"malicious", true, "analyst-2"}}
	if !slices.Equal(events, want) {
		t.Fatalf("events %+v, want %+v", events, want)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE verdict_events SET actor = 'x'`); err == nil {
		t.Fatal("verdict_events UPDATE allowed")
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM verdict_events`); err == nil {
		t.Fatal("verdict_events DELETE allowed")
	}

	// Recompute keeps the dispute flag.
	f.lookalike(t, f.asset, at(80), nil)
	v, _, err = f.s.Recompute(ctx, f.asset, at(81), verdict.V1)
	if err != nil || !v.Disputed {
		t.Fatalf("dispute lost: %+v %v", v, err)
	}
}

func TestReplayReproducesStoredVerdict(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	exp := at(10)
	f.lookalike(t, f.asset, at(0), &exp)
	if _, _, err := f.s.Recompute(ctx, f.asset, at(1), verdict.V1); err != nil {
		t.Fatal(err)
	}
	// Later evidence, even backdated before the stored as_of, must not change the replay.
	f.lookalike(t, f.asset, at(0), nil)
	stored, _ := f.s.Verdict(ctx, f.asset)
	d, err := f.s.Replay(ctx, f.asset)
	if err != nil {
		t.Fatal(err)
	}
	if d.Level != stored.Level || d.RuleID != stored.RuleID || d.Category != stored.Category ||
		!d.AsOf.Equal(stored.AsOf) || !slices.Equal(d.EvidenceIDs, stored.EvidenceIDs) {
		t.Fatalf("replay %+v != stored %+v", d, stored)
	}
	// After expiry the level drops to unknown; that verdict replays too.
	if _, _, err := f.s.Recompute(ctx, f.asset, at(20), verdict.V1); err != nil {
		t.Fatal(err)
	}
	stored, _ = f.s.Verdict(ctx, f.asset)
	d, err = f.s.Replay(ctx, f.asset)
	if err != nil || d.Level != stored.Level || d.RuleID != stored.RuleID {
		t.Fatalf("replay %+v != stored %+v (%v)", d, stored, err)
	}
}

func TestListFlaggedForSnapshot(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	contract, _ := f.s.UpsertEntity(ctx, entity.Testnet, entity.Contract, sac, nil)
	if err := f.s.LinkSAC(ctx, contract, f.asset); err != nil {
		t.Fatal(err)
	}
	if err := f.s.LinkSAC(ctx, f.asset, contract); err == nil {
		t.Fatal("sac_of with the types swapped accepted")
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO entity_link VALUES ($1, $2, 'same_issuer')`, contract, f.asset); err == nil {
		t.Fatal("entity_link relation other than sac_of accepted")
	}

	revoked, _ := f.s.UpsertEntity(ctx, entity.Testnet, entity.Asset, "USDT:"+other, nil)
	quiet, _ := f.s.UpsertEntity(ctx, entity.Testnet, entity.Asset, "EURC:"+other, nil)
	mainnet, _ := f.s.UpsertEntity(ctx, entity.Public, entity.Asset, "USDC:"+other, nil)
	for _, id := range []int64{f.asset, revoked, mainnet} {
		f.lookalike(t, id, at(0), nil)
		if _, _, err := f.s.Recompute(ctx, id, at(1), verdict.V1); err != nil {
			t.Fatal(err)
		}
	}
	exp := at(1)
	f.lookalike(t, quiet, at(0), &exp)
	if _, _, err := f.s.Recompute(ctx, quiet, at(2), verdict.V1); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetStatus(ctx, revoked, verdict.Revoked, "analyst-1", "overturned"); err != nil {
		t.Fatal(err)
	}

	got, err := f.s.ListFlagged(ctx, entity.Testnet)
	if err != nil {
		t.Fatal(err)
	}
	want := []snapshot.Entity{{Type: entity.Asset, Key: "USDC:" + issuer}, {Type: entity.Contract, Key: sac}}
	if !slices.Equal(got, want) {
		t.Fatalf("flagged %+v, want %+v", got, want)
	}
	// The list feeds the snapshot builder directly.
	if _, err := snapshot.Build(snapshot.Input{Network: entity.Testnet, Version: 1, GeneratedAt: at(3),
		RulesetVersion: verdict.V1.Version, Entities: got}, testSigner(t)); err != nil {
		t.Fatalf("snapshot.Build: %v", err)
	}
	if _, err := f.s.ListFlagged(ctx, "futurenet"); err == nil {
		t.Fatal("unknown network accepted")
	}
}

func testSigner(t *testing.T) snapshot.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.NewEd25519Signer("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPublicStatementImmutableExceptSupersede(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var id int64
	err := f.pool.QueryRow(ctx, `INSERT INTO public_statement (entity_id, template_id, template_version, signal_level,
		rendered_text, facts, as_of, evidence_artifacts) VALUES ($1, 'asset.lookalike', 1, 'caution', 'text', '{}', $2, '{}')
		RETURNING id`, f.asset, at(0)).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO public_statement (entity_id, template_id, template_version, signal_level,
		rendered_text, facts, as_of, evidence_artifacts) VALUES ($1, 'x', 1, 'suspicious', 't', '{}', now(), '{}')`, f.asset); err == nil {
		t.Fatal("internal level accepted as a public signal")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE public_statement SET rendered_text = 'changed' WHERE id = $1`, id); err == nil {
		t.Fatal("rendered_text changed")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE public_statement SET superseded_at = $2 WHERE id = $1`, id, at(1)); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE public_statement SET superseded_at = $2 WHERE id = $1`, id, at(2)); err == nil {
		t.Fatal("superseded_at changed twice")
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM public_statement WHERE id = $1`, id); err == nil {
		t.Fatal("public_statement DELETE allowed")
	}
}
