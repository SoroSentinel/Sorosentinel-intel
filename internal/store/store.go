// Package store persists entities, evidence and verdicts in Postgres 16
// (migrations/). Evidence and verdict_events are append-only; the database
// enforces it with triggers. Verdict writes and their events share one
// transaction.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

// Store is what ingestion, detectors, analysts and the snapshot builder use.
type Store interface {
	EnsureSource(ctx context.Context, name string, kind evidence.SourceKind) (int16, error)
	// UpsertEntity creates the entity on first use (lazy creation) and merges attrs.
	// The key is normalized first; a muxed account is an error, not a guess.
	UpsertEntity(ctx context.Context, network entity.Network, typ entity.Type, key string, attrs json.RawMessage) (int64, error)
	// LinkSAC records that contractID is the Stellar Asset Contract of assetID.
	LinkSAC(ctx context.Context, contractID, assetID int64) error
	AppendEvidence(ctx context.Context, n evidence.New) (int64, error)
	Evidence(ctx context.Context, entityID int64) ([]evidence.Evidence, error)
	Verdict(ctx context.Context, entityID int64) (*verdict.Verdict, error)
	// Recompute decides the entity's level at asOf and, if it changed, writes
	// the verdict and its event in one transaction.
	Recompute(ctx context.Context, entityID int64, asOf time.Time, rs verdict.Ruleset) (verdict.Verdict, bool, error)
	SetDisputed(ctx context.Context, entityID int64, disputed bool, actor, reason string) error
	SetStatus(ctx context.Context, entityID int64, status verdict.Status, actor, reason string) error
	// Replay re-decides the stored verdict from its stored evidence, as_of and ruleset.
	Replay(ctx context.Context, entityID int64) (verdict.Decision, error)
	// ListFlagged returns active suspicious/malicious entities on network, plus
	// their sac_of counterparts, sorted, for snapshot.Build.
	ListFlagged(ctx context.Context, network entity.Network) ([]snapshot.Entity, error)
}

var ErrNotFound = errors.New("store: not found")

// Postgres implements Store.
type Postgres struct {
	pool *pgxpool.Pool
}

var _ Store = (*Postgres)(nil)

func New(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// Postgres keeps microseconds; truncating up front keeps a decision's as_of
// identical to what is stored, so replays compare exactly.
func dbTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func (s *Postgres) EnsureSource(ctx context.Context, name string, kind evidence.SourceKind) (int16, error) {
	if !kind.Valid() {
		return 0, fmt.Errorf("store: unknown source kind %q", kind)
	}
	var id int16
	var got evidence.SourceKind
	err := s.pool.QueryRow(ctx, `
		INSERT INTO source (name, kind) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id, kind`, name, string(kind)).Scan(&id, &got)
	if err != nil {
		return 0, err
	}
	if got != kind {
		return 0, fmt.Errorf("store: source %q exists with kind %s", name, got)
	}
	return id, nil
}

func (s *Postgres) UpsertEntity(ctx context.Context, network entity.Network, typ entity.Type, key string, attrs json.RawMessage) (int64, error) {
	if network != entity.Public && network != entity.Testnet {
		return 0, &entity.Error{Code: entity.ErrUnknownNetwork}
	}
	norm, err := entity.NormalizeKey(typ, key)
	if err != nil {
		return 0, err
	}
	if len(attrs) == 0 {
		attrs = json.RawMessage(`{}`)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(attrs, &obj) != nil || obj == nil {
		return 0, errors.New("store: attrs must be a JSON object")
	}
	var id int64
	err = s.pool.QueryRow(ctx, `
		INSERT INTO entity (network, type, key, attrs) VALUES ($1, $2, $3, $4)
		ON CONFLICT (network, type, key) DO UPDATE SET attrs = entity.attrs || EXCLUDED.attrs
		RETURNING id`, string(network), string(typ), norm, []byte(attrs)).Scan(&id)
	return id, err
}

func (s *Postgres) LinkSAC(ctx context.Context, contractID, assetID int64) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO entity_link (from_entity_id, to_entity_id, relation)
		SELECT c.id, a.id, 'sac_of' FROM entity c, entity a
		WHERE c.id = $1 AND a.id = $2 AND c.type = 'contract' AND a.type = 'asset' AND c.network = a.network
		ON CONFLICT DO NOTHING`, contractID, assetID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM entity_link
			WHERE from_entity_id = $1 AND to_entity_id = $2 AND relation = 'sac_of')`, contractID, assetID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errors.New("store: sac_of needs a contract and an asset on the same network")
		}
	}
	return nil
}

func (s *Postgres) AppendEvidence(ctx context.Context, n evidence.New) (int64, error) {
	if err := n.Validate(); err != nil {
		return 0, err
	}
	var expires *time.Time
	if n.ExpiresAt != nil {
		t := dbTime(*n.ExpiresAt)
		expires = &t
	}
	var ledger *int64
	if n.LedgerSeq > 0 {
		ledger = &n.LedgerSeq
	}
	var level, by *string
	if n.ConfirmedLevel != "" {
		l := string(n.ConfirmedLevel)
		level, by = &l, &n.ConfirmedBy
	}
	refs := n.ArtifactRefs
	if refs == nil {
		refs = []string{}
	}
	var kind evidence.SourceKind
	if err := s.pool.QueryRow(ctx, `SELECT kind FROM source WHERE id = $1`, n.SourceID).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("store: unknown source %d", n.SourceID)
		}
		return 0, err
	}
	if n.ConfirmedLevel != "" && kind != evidence.Curated {
		return 0, errors.New("store: human confirmations need a curated source")
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO evidence (entity_id, source_id, detector, evidence_class, category, payload,
			observed_at, ledger_seq, expires_at, artifact_refs, confirmed_level, confirmed_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::verdict_level, $12)
		RETURNING id`,
		n.EntityID, n.SourceID, n.Detector, string(n.Class), n.Category, []byte(n.Payload),
		dbTime(n.ObservedAt), ledger, expires, refs, level, by).Scan(&id)
	return id, err
}

const evidenceCols = `e.id, e.entity_id, s.kind, e.detector, e.evidence_class, e.category,
	e.observed_at, e.expires_at, e.confirmed_level, e.confirmed_by`

func (s *Postgres) Evidence(ctx context.Context, entityID int64) ([]evidence.Evidence, error) {
	return queryEvidence(ctx, s.pool, `SELECT `+evidenceCols+` FROM evidence e JOIN source s ON s.id = e.source_id
		WHERE e.entity_id = $1 ORDER BY e.observed_at, e.id LIMIT $2`, entityID, evidence.MaxPerVerdict+1)
}

func queryEvidence(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, sql string, args ...any) ([]evidence.Evidence, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (evidence.Evidence, error) {
		var e evidence.Evidence
		var level, by *string
		err := r.Scan(&e.ID, &e.EntityID, &e.SourceKind, &e.Detector, &e.Class, &e.Category,
			&e.ObservedAt, &e.ExpiresAt, &level, &by)
		if level != nil {
			e.ConfirmedLevel = signal.Internal(*level)
		}
		if by != nil {
			e.ConfirmedBy = *by
		}
		return e, err
	})
	if err != nil {
		return nil, err
	}
	if len(out) > evidence.MaxPerVerdict {
		return nil, errors.New("store: too much evidence for one entity")
	}
	return out, nil
}

const verdictCols = `id, entity_id, level, status, disputed, coalesce(category, ''), rule_id, decided_by,
	ruleset_version, as_of, evidence_ids`

func scanVerdict(row pgx.Row) (*verdict.Verdict, error) {
	var v verdict.Verdict
	err := row.Scan(&v.ID, &v.EntityID, &v.Level, &v.Status, &v.Disputed, &v.Category, &v.RuleID,
		&v.DecidedBy, &v.RulesetVersion, &v.AsOf, &v.EvidenceIDs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.AsOf = v.AsOf.UTC()
	return &v, nil
}

func (s *Postgres) Verdict(ctx context.Context, entityID int64) (*verdict.Verdict, error) {
	return scanVerdict(s.pool.QueryRow(ctx, `SELECT `+verdictCols+` FROM verdict WHERE entity_id = $1`, entityID))
}

func (s *Postgres) Recompute(ctx context.Context, entityID int64, asOf time.Time, rs verdict.Ruleset) (verdict.Verdict, bool, error) {
	asOf = dbTime(asOf)
	var out verdict.Verdict
	var changed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockEntity(ctx, tx, entityID); err != nil {
			return err
		}
		ev, err := queryEvidence(ctx, tx, `SELECT `+evidenceCols+` FROM evidence e JOIN source s ON s.id = e.source_id
			WHERE e.entity_id = $1 ORDER BY e.observed_at, e.id LIMIT $2`, entityID, evidence.MaxPerVerdict+1)
		if err != nil {
			return err
		}
		d, err := verdict.Decide(ev, asOf, rs)
		if err != nil {
			return err // includes ErrNoEvidence: no verdict without stored evidence
		}
		prev, err := scanVerdict(tx.QueryRow(ctx, `SELECT `+verdictCols+` FROM verdict WHERE entity_id = $1`, entityID))
		if err != nil {
			return err
		}
		next, event, ch, err := verdict.Apply(prev, entityID, d, verdict.EngineActor)
		if err != nil {
			return err
		}
		out, changed = next, ch
		if !ch {
			return nil
		}
		out, err = writeVerdict(ctx, tx, next, event)
		return err
	})
	if err != nil {
		return verdict.Verdict{}, false, err
	}
	return out, changed, nil
}

func (s *Postgres) SetDisputed(ctx context.Context, entityID int64, disputed bool, actor, reason string) error {
	return s.analystChange(ctx, entityID, func(prev verdict.Verdict) (verdict.Verdict, verdict.Event, error) {
		return verdict.SetDisputed(prev, disputed, actor, reason)
	})
}

func (s *Postgres) SetStatus(ctx context.Context, entityID int64, status verdict.Status, actor, reason string) error {
	return s.analystChange(ctx, entityID, func(prev verdict.Verdict) (verdict.Verdict, verdict.Event, error) {
		return verdict.SetStatus(prev, status, actor, reason)
	})
}

func (s *Postgres) analystChange(ctx context.Context, entityID int64, change func(verdict.Verdict) (verdict.Verdict, verdict.Event, error)) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockEntity(ctx, tx, entityID); err != nil {
			return err
		}
		prev, err := scanVerdict(tx.QueryRow(ctx, `SELECT `+verdictCols+` FROM verdict WHERE entity_id = $1`, entityID))
		if err != nil {
			return err
		}
		if prev == nil {
			return ErrNotFound
		}
		next, event, err := change(*prev)
		if err != nil {
			return err
		}
		_, err = writeVerdict(ctx, tx, next, event)
		return err
	})
}

func lockEntity(ctx context.Context, tx pgx.Tx, entityID int64) error {
	var id int64
	err := tx.QueryRow(ctx, `SELECT id FROM entity WHERE id = $1 FOR UPDATE`, entityID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// writeVerdict upserts the one current verdict and appends its event in the caller's transaction.
func writeVerdict(ctx context.Context, tx pgx.Tx, v verdict.Verdict, e verdict.Event) (verdict.Verdict, error) {
	var category *string
	if v.Category != "" {
		category = &v.Category
	}
	ids := v.EvidenceIDs
	if ids == nil {
		ids = []int64{}
	}
	err := tx.QueryRow(ctx, `
		INSERT INTO verdict (entity_id, level, status, disputed, category, rule_id, decided_by,
			ruleset_version, as_of, evidence_ids)
		VALUES ($1, $2::verdict_level, $3::verdict_status, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (entity_id) DO UPDATE SET level = EXCLUDED.level, status = EXCLUDED.status,
			disputed = EXCLUDED.disputed, category = EXCLUDED.category, rule_id = EXCLUDED.rule_id,
			decided_by = EXCLUDED.decided_by, ruleset_version = EXCLUDED.ruleset_version,
			as_of = EXCLUDED.as_of, evidence_ids = EXCLUDED.evidence_ids, updated_at = now()
		RETURNING id`,
		v.EntityID, string(v.Level), string(v.Status), v.Disputed, category, v.RuleID, v.DecidedBy,
		v.RulesetVersion, dbTime(v.AsOf), ids).Scan(&v.ID)
	if err != nil {
		return verdict.Verdict{}, err
	}
	var fromLevel, fromStatus *string
	var fromDisputed *bool
	if e.From != nil {
		l, st, d := string(e.From.Level), string(e.From.Status), e.From.Disputed
		fromLevel, fromStatus, fromDisputed = &l, &st, &d
	}
	var reason *string
	if e.Reason != "" {
		reason = &e.Reason
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO verdict_events (entity_id, verdict_id, from_level, to_level, from_status, to_status,
			from_disputed, to_disputed, rule_id, ruleset_version, as_of, evidence_ids, actor, reason)
		VALUES ($1, $2, $3::verdict_level, $4::verdict_level, $5::verdict_status, $6::verdict_status,
			$7, $8, $9, $10, $11, $12, $13, $14)`,
		v.EntityID, v.ID, fromLevel, string(v.Level), fromStatus, string(v.Status),
		fromDisputed, v.Disputed, v.RuleID, v.RulesetVersion, dbTime(v.AsOf), ids, e.Actor, reason)
	return v, err
}

func (s *Postgres) Replay(ctx context.Context, entityID int64) (verdict.Decision, error) {
	v, err := s.Verdict(ctx, entityID)
	if err != nil {
		return verdict.Decision{}, err
	}
	if v == nil {
		return verdict.Decision{}, ErrNotFound
	}
	rs, err := verdict.Lookup(v.RulesetVersion)
	if err != nil {
		return verdict.Decision{}, err
	}
	ev, err := queryEvidence(ctx, s.pool, `SELECT `+evidenceCols+` FROM evidence e JOIN source s ON s.id = e.source_id
		WHERE e.entity_id = $1 AND e.id = ANY($2) ORDER BY e.observed_at, e.id`, entityID, v.EvidenceIDs)
	if err != nil {
		return verdict.Decision{}, err
	}
	if len(ev) != len(v.EvidenceIDs) {
		return verdict.Decision{}, errors.New("store: stored verdict references missing evidence")
	}
	return verdict.Decide(ev, v.AsOf, rs)
}

func (s *Postgres) ListFlagged(ctx context.Context, network entity.Network) ([]snapshot.Entity, error) {
	if network != entity.Public && network != entity.Testnet {
		return nil, &entity.Error{Code: entity.ErrUnknownNetwork}
	}
	rows, err := s.pool.Query(ctx, `
		WITH flagged AS (
			SELECT v.entity_id AS id FROM verdict v JOIN entity e ON e.id = v.entity_id
			WHERE e.network = $1 AND v.status = 'active' AND v.level IN ('suspicious', 'malicious')
		), linked AS (
			SELECT id FROM flagged
			UNION SELECT l.to_entity_id FROM entity_link l JOIN flagged f ON l.from_entity_id = f.id
			UNION SELECT l.from_entity_id FROM entity_link l JOIN flagged f ON l.to_entity_id = f.id
		)
		SELECT e.type, e.key FROM entity e JOIN linked ON linked.id = e.id
		WHERE e.network = $1
		ORDER BY e.type, e.key
		LIMIT $2`, string(network), snapshot.MaxEntries+1)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (snapshot.Entity, error) {
		var e snapshot.Entity
		err := r.Scan(&e.Type, &e.Key)
		return e, err
	})
	if err != nil {
		return nil, err
	}
	if len(out) > snapshot.MaxEntries {
		return nil, errors.New("store: flagged entities exceed snapshot.MaxEntries")
	}
	return slices.Clip(out), nil
}
