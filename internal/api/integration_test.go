package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/assetlookalike"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/homedomain"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/pipeline"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

// Integration tests need a disposable Postgres 16 server; see
// internal/store/store_test.go for a docker command. Each test creates and
// drops its own database.
const dbEnv = "INTEL_TEST_DATABASE_URL"

func freshDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv(dbEnv)
	if url == "" {
		t.Skip(dbEnv + " is unset; skipping the API Postgres integration test (see internal/store/store_test.go for setup)")
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
	name := "intel_api_" + hex.EncodeToString(b)
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

func TestPostgresEndToEnd(t *testing.T) {
	ctx := context.Background()
	st := store.New(freshDB(t))
	src, err := st.EnsureSource(ctx, "heuristic", evidence.Heuristic)
	if err != nil {
		t.Fatal(err)
	}
	flag := func(asset string, at time.Time) int64 {
		t.Helper()
		id, err := st.UpsertEntity(ctx, entity.Testnet, entity.Asset, asset, nil)
		if err != nil {
			t.Fatal(err)
		}
		issuer := asset[len("USDC:"):]
		for _, e := range []evidence.New{
			{Detector: assetlookalike.Code, Class: evidence.ClassOnchainPattern, Category: assetlookalike.Category,
				Payload: payload(t, "asset", asset, "code", "USDC", "issuer", issuer, "reference_code", "USDC",
					"match", "exact", "known_issuer_count", "1", "known_assets", refAsset)},
			{Detector: homedomain.Code, Class: evidence.ClassDomain, Category: homedomain.Category,
				Payload: payload(t, "asset", asset, "issuer", issuer, "home_domain", "issuer.example", "reason", "asset_not_listed")},
		} {
			e.EntityID, e.SourceID, e.ObservedAt, e.LedgerSeq = id, src, at, 5429263
			if _, err := st.AppendEvidence(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		v, _, err := st.Recompute(ctx, id, at, verdict.V1)
		if err != nil || v.Level != signal.Suspicious {
			t.Fatalf("recompute: %v %v", v.Level, err)
		}
		return id
	}

	assetID := flag(lookAsset, testAsOf)
	sac := cKey(3)
	sacID, err := st.UpsertEntity(ctx, entity.Testnet, entity.Contract, sac, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkSAC(ctx, sacID, assetID); err != nil {
		t.Fatal(err)
	}
	revokedAsset := "USDC:" + gKey(6)
	revokedID := flag(revokedAsset, testAsOf)
	if err := st.SetStatus(ctx, revokedID, verdict.Revoked, "analyst-1", "internal note"); err != nil {
		t.Fatal(err)
	}
	disputedAsset := "USDC:" + gKey(8)
	if err := st.SetDisputed(ctx, flag(disputedAsset, testAsOf), true, "analyst-1", "internal note"); err != nil {
		t.Fatal(err)
	}

	// Two published snapshots, as the worker writes them.
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer, _ := snapshot.NewEd25519Signer("intel-test-1", priv)
	p := &pipeline.Publisher{Network: entity.Testnet, Dir: dir, RulesetVersion: verdict.V1.Version, Signer: signer, Store: st}
	for i := range 2 {
		if _, err := p.Publish(ctx, testNow.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	h := newServer(t, st, dir, nil)
	v := loadSchemas(t)
	unknown := gKey(9)
	body := batchBody(t,
		Entity{"testnet", "asset", lookAsset},
		Entity{"testnet", "contract", sac},
		Entity{"testnet", "asset", revokedAsset},
		Entity{"testnet", "account", mKey(t, unknown, 3)},
		Entity{"public", "asset", lookAsset}, // same key, other network
		Entity{"testnet", "asset", disputedAsset},
	)
	rec := do(t, h, "POST", "/v1/entities:batchGet", "application/json", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: %d %s", rec.Code, rec.Body)
	}
	v.check(t, "batch", "batchGetResponse", rec.Body.Bytes())
	var got batchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		key      string
		level    signal.Public
		disputed *bool
	}{
		{lookAsset, signal.Caution, new(false)},
		{sac, signal.Caution, new(false)}, // the SAC carries its asset's signal
		{revokedAsset, signal.NoSignals, nil},
		{unknown, signal.NoSignals, nil},
		{lookAsset, signal.NoSignals, nil},
		{disputedAsset, signal.Caution, new(true)},
	}
	for i, w := range want {
		r := got.Results[i]
		if r.Entity.Key != w.key || r.SignalLevel != w.level || (r.Disputed == nil) != (w.disputed == nil) ||
			(w.disputed != nil && *r.Disputed != *w.disputed) {
			t.Errorf("result %d = %+v, want %+v", i, r, w)
		}
	}
	if f := got.Results[0].Facts; f["known_issuer"] != refIssuer || f["home_domain"] != "issuer.example" ||
		f["as_of"] != "2026-10-28T09:30:15Z" || len(got.Results[0].Statements) != 0 {
		t.Errorf("facts = %v", f)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("analyst")) || bytes.Contains(rec.Body.Bytes(), []byte("internal note")) {
		t.Error("analyst data leaked")
	}

	rec = do(t, h, "GET", entityPath("asset", lookAsset, "testnet"), "", nil)
	v.check(t, "single", "EntitySignal", rec.Body.Bytes())

	for path, version := range map[string]uint64{
		"/v1/snapshots/latest?network=testnet": 2,
		"/v1/snapshots/1?network=testnet":      1,
	} {
		rec := do(t, h, "GET", path, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		v.check(t, path, "Snapshot", rec.Body.Bytes())
		var s snapshot.Snapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		if s.Version != version || snapshot.Verify(s, pub) != nil {
			t.Errorf("%s: version %d, verify %v", path, s.Version, snapshot.Verify(s, pub))
		}
		// Flagged asset, its SAC and the disputed asset; not the revoked one.
		if len(s.Entries) != 3 {
			t.Errorf("%s: %d entries", path, len(s.Entries))
		}
	}
	if rec := do(t, h, "GET", "/v1/snapshots/3?network=testnet", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unpublished version: %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/snapshots/latest?network=public", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("network without snapshots: %d", rec.Code)
	}
}

func TestPostgresLookupLimits(t *testing.T) {
	st := store.New(freshDB(t))
	keys := make([]store.LookupKey, store.MaxLookupKeys+1)
	for i := range keys {
		keys[i] = store.LookupKey{Network: entity.Public, Type: entity.Account, Key: gKey(9)}
	}
	if _, err := st.LookupEntities(context.Background(), keys); err == nil {
		t.Error("more than MaxLookupKeys keys must be refused")
	}
	if _, err := st.LookupEntities(context.Background(), []store.LookupKey{{Network: "futurenet", Type: entity.Account, Key: gKey(9)}}); err == nil {
		t.Error("unknown network must be refused")
	}
	res, err := st.LookupEntities(context.Background(), keys[:store.MaxLookupKeys])
	if err != nil || len(res) != store.MaxLookupKeys {
		t.Fatalf("%d results, %v", len(res), err)
	}
}
