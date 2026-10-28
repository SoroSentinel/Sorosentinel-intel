package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
)

func TestCheckpointAdvancesByOne(t *testing.T) {
	_, pool := migrated(t)
	ctx := context.Background()
	cp := NewCheckpoint(pool)
	if _, ok, err := cp.Last(ctx, entity.Testnet); ok || err != nil {
		t.Fatalf("fresh checkpoint: ok=%v err=%v", ok, err)
	}
	if err := cp.Set(ctx, entity.Testnet, 100); err != nil {
		t.Fatal(err)
	}
	if err := cp.Set(ctx, entity.Testnet, 101); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []uint32{101, 100, 103, 0} {
		if err := cp.Set(ctx, entity.Testnet, bad); err == nil {
			t.Errorf("Set(%d) after 101 accepted", bad)
		}
	}
	if last, ok, err := cp.Last(ctx, entity.Testnet); last != 101 || !ok || err != nil {
		t.Errorf("Last = %d, %v, %v", last, ok, err)
	}
	if _, ok, _ := cp.Last(ctx, entity.Public); ok {
		t.Error("networks share a checkpoint")
	}
	if err := cp.Set(ctx, "futurenet", 1); err == nil {
		t.Error("unknown network accepted")
	}
	if err := cp.Set(ctx, entity.Testnet, 105); !errors.Is(err, ingest.ErrGap) {
		t.Errorf("skip ahead: err = %v, want ErrGap", err)
	}
}

func TestWriterLockIsExclusivePerNetwork(t *testing.T) {
	_, pool := migrated(t)
	ctx := context.Background()
	l, err := AcquireWriter(ctx, pool, entity.Testnet)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if _, err := AcquireWriter(ctx, pool, entity.Testnet); !errors.Is(err, ingest.ErrWriterActive) {
		t.Fatalf("second writer: err = %v", err)
	}
	pub, err := AcquireWriter(ctx, pool, entity.Public)
	if err != nil {
		t.Fatalf("other network blocked: %v", err)
	}
	pub.Release(ctx)
	l.Release(ctx)
	l.Release(ctx) // idempotent
	if err := l.Ping(ctx); err == nil {
		t.Error("ping after release succeeded")
	}
	again, err := AcquireWriter(ctx, pool, entity.Testnet)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again.Release(ctx)
}

func TestHasEvidenceAndAssetsByIssuer(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	payload := json.RawMessage(`{"a": 1, "b": [2]}`)
	_, err := f.s.AppendEvidence(ctx, evidence.New{EntityID: f.asset, SourceID: f.heuristic,
		Detector: evidence.DetectorAssetLookalike, Class: evidence.ClassOnchainPattern, Category: "asset_code_lookalike",
		Payload: payload, ObservedAt: at(0), LedgerSeq: 77})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		q    EvidenceQuery
		want bool
	}{
		{EvidenceQuery{EntityID: f.asset, Detector: evidence.DetectorAssetLookalike}, true},
		{EvidenceQuery{EntityID: f.asset, Detector: evidence.DetectorAssetLookalike, LedgerSeq: 77}, true},
		{EvidenceQuery{EntityID: f.asset, Detector: evidence.DetectorAssetLookalike, LedgerSeq: 78}, false},
		{EvidenceQuery{EntityID: f.asset, Detector: evidence.DetectorAssetLookalike, Payload: json.RawMessage(`{"b":[2],"a":1}`)}, true},
		{EvidenceQuery{EntityID: f.asset, Detector: evidence.DetectorAssetLookalike, Payload: json.RawMessage(`{"a":2}`)}, false},
		{EvidenceQuery{EntityID: f.asset, Detector: evidence.DetectorHomeDomain}, false},
	} {
		got, err := f.s.HasEvidence(ctx, c.q)
		if err != nil || got != c.want {
			t.Errorf("HasEvidence(%+v) = %v, %v; want %v", c.q, got, err, c.want)
		}
	}
	if _, err := f.s.HasEvidence(ctx, EvidenceQuery{}); err == nil {
		t.Error("empty query accepted")
	}

	if _, err := f.s.UpsertEntity(ctx, entity.Testnet, entity.Asset, "EURC:"+issuer, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.UpsertEntity(ctx, entity.Testnet, entity.Asset, "USDC:"+other, nil); err != nil {
		t.Fatal(err)
	}
	keys, err := f.s.AssetsByIssuer(ctx, entity.Testnet, issuer)
	if err != nil || len(keys) != 2 || keys[0] != "EURC:"+issuer || keys[1] != "USDC:"+issuer {
		t.Errorf("AssetsByIssuer = %v, %v", keys, err)
	}
	if keys, _ := f.s.AssetsByIssuer(ctx, entity.Public, issuer); len(keys) != 0 {
		t.Errorf("other network leaked: %v", keys)
	}
	if _, err := f.s.AssetsByIssuer(ctx, entity.Testnet, "%"); err == nil {
		t.Error("pattern issuer accepted")
	}
}

func TestSnapshotRecords(t *testing.T) {
	s, _ := migrated(t)
	ctx := context.Background()
	if v, err := s.NextSnapshotVersion(ctx, entity.Testnet); v != 1 || err != nil {
		t.Fatalf("first version = %d, %v", v, err)
	}
	rec := SnapshotRecord{Network: entity.Testnet, Version: 1, GeneratedAt: t0, RulesetVersion: "2026.10.1",
		EntryCount: 0, ObjectKey: "snapshot-testnet-1.json", SigningKeyID: "k", Signature: []byte{1}}
	if err := s.RecordSnapshot(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSnapshot(ctx, rec); err == nil {
		t.Error("version recorded twice")
	}
	if v, _ := s.NextSnapshotVersion(ctx, entity.Testnet); v != 2 {
		t.Errorf("next version = %d", v)
	}
	if v, _ := s.NextSnapshotVersion(ctx, entity.Public); v != 1 {
		t.Errorf("public next version = %d", v)
	}
	rec.Signature = nil
	rec.Version = 2
	if err := s.RecordSnapshot(ctx, rec); err == nil {
		t.Error("incomplete record accepted")
	}
}
