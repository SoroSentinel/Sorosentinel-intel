package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

// Read-side methods for the public API (cmd/intel-api). They never write:
// a lookup of an unknown key does not create an entity row.

const (
	// MaxLookupKeys bounds one LookupEntities call (the API batch limit).
	MaxLookupKeys = 100
	// MaxLookupEvidence bounds the evidence rows returned per entity, newest first.
	MaxLookupEvidence = 50
)

// LookupKey is an entity key; Key is normalized by LookupEntities.
type LookupKey struct {
	Network entity.Network
	Type    entity.Type
	Key     string
}

// LookupEvidence is the part of a stored evidence row the API may build
// facts from. Payload is the detector's JSON payload.
type LookupEvidence struct {
	ID         int64
	Detector   string
	ObservedAt time.Time
	Payload    json.RawMessage
}

// LookupResult is the current active verdict for an entity, with the newest
// evidence it was decided on. Verdict is nil when no active verdict applies.
//
// The verdict may belong to a sac_of counterpart: a classic asset and its
// Stellar Asset Contract are one asset, so a flag on either identity applies
// to both (ARCHITECTURE §17 T3), as in the snapshot. The more severe active
// verdict wins; on a tie the entity's own verdict wins.
type LookupResult struct {
	Verdict  *verdict.Verdict
	Evidence []LookupEvidence
}

// LookupEntities returns one result per key, in order.
func (s *Postgres) LookupEntities(ctx context.Context, keys []LookupKey) ([]LookupResult, error) {
	if len(keys) > MaxLookupKeys {
		return nil, errors.New("store: too many lookup keys")
	}
	networks := make([]string, len(keys))
	types := make([]string, len(keys))
	norm := make([]string, len(keys))
	for i, k := range keys {
		if err := checkNetwork(k.Network); err != nil {
			return nil, err
		}
		n, err := entity.NormalizeKey(k.Type, k.Key)
		if err != nil {
			return nil, err
		}
		networks[i], types[i], norm[i] = string(k.Network), string(k.Type), n
	}
	out := make([]LookupResult, len(keys))
	if len(keys) == 0 {
		return out, nil
	}

	rows, err := s.pool.Query(ctx, `
		WITH k AS (
			SELECT * FROM unnest($1::text[], $2::text[], $3::text[]) WITH ORDINALITY AS k(network, type, key, ord)
		)
		SELECT k.ord, v.id, v.entity_id, v.level, v.status, v.disputed, coalesce(v.category, ''), v.rule_id,
			v.decided_by, v.ruleset_version, v.as_of, v.evidence_ids
		FROM k
		JOIN entity e ON e.network = k.network AND e.type = k.type::entity_type AND e.key = k.key
		CROSS JOIN LATERAL (
			SELECT v.* FROM verdict v
			WHERE v.status = 'active' AND (v.entity_id = e.id
				OR v.entity_id IN (SELECT to_entity_id FROM entity_link WHERE from_entity_id = e.id
					UNION SELECT from_entity_id FROM entity_link WHERE to_entity_id = e.id))
			ORDER BY v.level DESC, (v.entity_id = e.id) DESC, v.entity_id
			LIMIT 1
		) v`, networks, types, norm)
	if err != nil {
		return nil, err
	}
	byVerdict := map[int64][]int{}
	var verdictIDs []int64
	for rows.Next() {
		var ord int64
		var v verdict.Verdict
		if err := rows.Scan(&ord, &v.ID, &v.EntityID, &v.Level, &v.Status, &v.Disputed, &v.Category, &v.RuleID,
			&v.DecidedBy, &v.RulesetVersion, &v.AsOf, &v.EvidenceIDs); err != nil {
			rows.Close()
			return nil, err
		}
		if ord < 1 || ord > int64(len(keys)) {
			rows.Close()
			return nil, errors.New("store: lookup returned an unexpected row")
		}
		v.AsOf = v.AsOf.UTC()
		i := int(ord - 1)
		out[i].Verdict = &v
		if _, seen := byVerdict[v.ID]; !seen {
			verdictIDs = append(verdictIDs, v.ID)
		}
		byVerdict[v.ID] = append(byVerdict[v.ID], i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(verdictIDs) == 0 {
		return out, nil
	}

	// Only evidence the verdict was decided on, from the verdict's own entity.
	rows, err = s.pool.Query(ctx, `
		SELECT v.id, ev.id, ev.detector, ev.observed_at, ev.payload
		FROM verdict v
		CROSS JOIN LATERAL (
			SELECT ev.id, ev.detector, ev.observed_at, ev.payload FROM evidence ev
			WHERE ev.entity_id = v.entity_id AND ev.id = ANY(v.evidence_ids)
			ORDER BY ev.observed_at DESC, ev.id DESC
			LIMIT $2
		) ev
		WHERE v.id = ANY($1)
		ORDER BY v.id, ev.observed_at DESC, ev.id DESC`, verdictIDs, MaxLookupEvidence)
	if err != nil {
		return nil, err
	}
	evidenceOf := map[int64][]LookupEvidence{}
	for rows.Next() {
		var vid int64
		var e LookupEvidence
		var payload []byte
		if err := rows.Scan(&vid, &e.ID, &e.Detector, &e.ObservedAt, &payload); err != nil {
			rows.Close()
			return nil, err
		}
		e.ObservedAt = e.ObservedAt.UTC()
		e.Payload = payload
		evidenceOf[vid] = append(evidenceOf[vid], e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for vid, idx := range byVerdict {
		for _, i := range idx {
			out[i].Evidence = evidenceOf[vid]
		}
	}
	return out, nil
}

// Snapshot returns the recorded snapshot row for network and version, or the
// highest recorded version when version is 0. ErrNotFound when there is none.
func (s *Postgres) Snapshot(ctx context.Context, network entity.Network, version uint64) (SnapshotRecord, error) {
	if err := checkNetwork(network); err != nil {
		return SnapshotRecord{}, err
	}
	if version > math.MaxInt64 {
		return SnapshotRecord{}, ErrNotFound
	}
	var r SnapshotRecord
	var v int64
	err := s.pool.QueryRow(ctx, `
		SELECT network, version, generated_at, ruleset_version, entry_count, object_key, signing_key_id, signature
		FROM snapshot WHERE network = $1 AND ($2::bigint = 0 OR version = $2)
		ORDER BY version DESC LIMIT 1`, string(network), int64(version)).Scan(
		&r.Network, &v, &r.GeneratedAt, &r.RulesetVersion, &r.EntryCount, &r.ObjectKey, &r.SigningKeyID, &r.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return SnapshotRecord{}, ErrNotFound
	}
	if err != nil {
		return SnapshotRecord{}, err
	}
	if v < 1 {
		return SnapshotRecord{}, errors.New("store: snapshot version out of range")
	}
	r.Version = uint64(v)
	r.GeneratedAt = r.GeneratedAt.UTC()
	return r, nil
}
