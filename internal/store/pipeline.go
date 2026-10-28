package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

// EvidenceQuery selects stored evidence for an idempotency check. Zero
// LedgerSeq and nil Payload match any value.
type EvidenceQuery struct {
	EntityID  int64
	Detector  string
	LedgerSeq int64
	Payload   json.RawMessage // compared as JSON (jsonb equality)
}

// HasEvidence reports whether a matching evidence row exists. The pipeline
// uses it so that replaying a ledger, or seeing the same asset again, does
// not append duplicate rows.
func (s *Postgres) HasEvidence(ctx context.Context, q EvidenceQuery) (bool, error) {
	if q.EntityID <= 0 || q.Detector == "" {
		return false, errors.New("store: evidence query needs entity and detector")
	}
	var ledger *int64
	if q.LedgerSeq > 0 {
		ledger = &q.LedgerSeq
	}
	var payload []byte
	if q.Payload != nil {
		payload = q.Payload
	}
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM evidence
		WHERE entity_id = $1 AND detector = $2
		AND ($3::bigint IS NULL OR ledger_seq = $3)
		AND ($4::jsonb IS NULL OR payload = $4::jsonb))`,
		q.EntityID, q.Detector, ledger, payload).Scan(&ok)
	return ok, err
}

// maxAssetsPerIssuer bounds AssetsByIssuer; entities exist only for assets
// that already have evidence, so real issuers stay far below it.
const maxAssetsPerIssuer = 1000

// AssetsByIssuer returns the keys (CODE:ISSUER) of asset entities on network
// issued by issuer, sorted. Only assets that already have an entity row (lazy
// creation) are returned.
func (s *Postgres) AssetsByIssuer(ctx context.Context, network entity.Network, issuer string) ([]string, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	if _, err := entity.NormalizeKey(entity.Account, issuer); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT key FROM entity
		WHERE network = $1 AND type = 'asset' AND right(key, 57) = ':' || $2
		ORDER BY key LIMIT $3`, string(network), issuer, maxAssetsPerIssuer+1)
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(keys) > maxAssetsPerIssuer {
		return nil, errors.New("store: too many assets for one issuer")
	}
	for _, k := range keys {
		if !strings.HasSuffix(k, ":"+issuer) {
			return nil, errors.New("store: asset key does not match issuer")
		}
	}
	return keys, nil
}

// SnapshotRecord is one row of the snapshot table.
type SnapshotRecord struct {
	Network        entity.Network
	Version        uint64
	GeneratedAt    time.Time
	RulesetVersion string
	EntryCount     int
	ObjectKey      string
	SigningKeyID   string
	Signature      []byte
}

// NextSnapshotVersion returns one more than the highest recorded version for
// network (1 for the first). Call it under the network's WriterLock.
func (s *Postgres) NextSnapshotVersion(ctx context.Context, network entity.Network) (uint64, error) {
	if err := checkNetwork(network); err != nil {
		return 0, err
	}
	var v int64
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM snapshot WHERE network = $1`,
		string(network)).Scan(&v); err != nil {
		return 0, err
	}
	if v < 0 || v == math.MaxInt64 {
		return 0, errors.New("store: snapshot version out of range")
	}
	return uint64(v) + 1, nil
}

// RecordSnapshot inserts the row for a published snapshot. A version that is
// already recorded is an error, never an overwrite.
func (s *Postgres) RecordSnapshot(ctx context.Context, r SnapshotRecord) error {
	if err := checkNetwork(r.Network); err != nil {
		return err
	}
	if r.Version < 1 || r.Version > math.MaxInt64 || r.GeneratedAt.IsZero() || r.EntryCount < 0 ||
		r.ObjectKey == "" || r.SigningKeyID == "" || len(r.Signature) == 0 {
		return errors.New("store: incomplete snapshot record")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO snapshot (network, version, generated_at, ruleset_version,
		entry_count, object_key, signing_key_id, signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		string(r.Network), int64(r.Version), dbTime(r.GeneratedAt), r.RulesetVersion, r.EntryCount,
		r.ObjectKey, r.SigningKeyID, r.Signature)
	return err
}
