// Package pipeline wires ingestion to the Phase 1 detectors, the evidence
// store and the verdict engine (ADR 0002): for each ingested ledger it runs
// D-ASSET-LOOKALIKE on every asset that gained a trustline, runs
// D-HOMEDOMAIN-MISMATCH on look-alike candidates, stores evidence (creating
// entities lazily) and recomputes the touched entities' verdicts.
//
// Home-domain checks are limited to look-alike candidates on purpose: asset
// creation is cheap, so checking every new asset would let anyone drive
// unbounded stellar.toml fetches and fill the entity table (ARCHITECTURE §4.1
// lazy creation).
//
// The detectors and the rule table never read the clock. The pipeline gets
// time only from Config.Now, supplied by the worker, and passes it in as
// observed_at / as_of.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/assetlookalike"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/homedomain"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/fetcher"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

// Source names recorded for the pipeline's evidence (table source).
const (
	SourceAssetLookalike = "detector.asset-lookalike"
	SourceHomeDomain     = "detector.homedomain"
)

// DefaultFetchInterval is the minimum gap between two stellar.toml fetches.
const DefaultFetchInterval = 2 * time.Second

// maxChecked bounds the in-memory set of assets already home-domain checked
// in this process; it is cleared when full (a restart clears it too, which
// only costs one extra fetch per candidate).
const maxChecked = 100_000

// Store is what the pipeline needs from internal/store.
type Store interface {
	EnsureSource(ctx context.Context, name string, kind evidence.SourceKind) (int16, error)
	UpsertEntity(ctx context.Context, network entity.Network, typ entity.Type, key string, attrs json.RawMessage) (int64, error)
	AppendEvidence(ctx context.Context, n evidence.New) (int64, error)
	HasEvidence(ctx context.Context, q store.EvidenceQuery) (bool, error)
	AssetsByIssuer(ctx context.Context, network entity.Network, issuer string) ([]string, error)
	Recompute(ctx context.Context, entityID int64, asOf time.Time, rs verdict.Ruleset) (verdict.Verdict, bool, error)
}

// Domains looks up an account's current home_domain (RPC getLedgerEntries).
// found=false means the account does not exist.
type Domains interface {
	HomeDomain(ctx context.Context, account string) (domain string, found bool, err error)
}

// Fetcher fetches a stellar.toml; *fetcher.Fetcher in production.
type Fetcher interface {
	Get(ctx context.Context, rawURL string) (fetcher.Result, error)
}

// Config controls a Pipeline.
type Config struct {
	Network   entity.Network
	Reference *assetlookalike.Reference
	Ruleset   verdict.Ruleset
	// Now is the worker's clock. It supplies fetch times and as_of; nothing
	// below the pipeline reads the clock.
	Now func() time.Time
	// FetchInterval is the minimum gap between stellar.toml fetches.
	FetchInterval time.Duration
	Log           *slog.Logger
}

// Pipeline is an ingest.Sink. It is used by one ingester at a time.
type Pipeline struct {
	cfg     Config
	st      Store
	domains Domains
	fetch   Fetcher
	srcLook int16
	srcHome int16
	checked map[string]bool // CODE:ISSUER already home-domain checked
	lastGet time.Time
	wait    func(ctx context.Context, d time.Duration) error
}

var _ ingest.Sink = (*Pipeline)(nil)

// New validates cfg and registers the evidence sources.
func New(ctx context.Context, cfg Config, st Store, domains Domains, fetch Fetcher) (*Pipeline, error) {
	if cfg.Network != entity.Public && cfg.Network != entity.Testnet {
		return nil, fmt.Errorf("pipeline: unknown network %q", cfg.Network)
	}
	if cfg.Reference == nil || cfg.Now == nil || st == nil || domains == nil || fetch == nil {
		return nil, errors.New("pipeline: reference, clock, store, domains and fetcher are required")
	}
	if err := cfg.Ruleset.Validate(); err != nil {
		return nil, err
	}
	for _, d := range []string{assetlookalike.Code, homedomain.Code} {
		if _, ok := cfg.Ruleset.Detectors[d]; !ok {
			return nil, fmt.Errorf("pipeline: ruleset %s has no rule for %s", cfg.Ruleset.Version, d)
		}
	}
	if cfg.FetchInterval <= 0 {
		cfg.FetchInterval = DefaultFetchInterval
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	look, err := st.EnsureSource(ctx, SourceAssetLookalike, cfg.Ruleset.Detectors[assetlookalike.Code].Source)
	if err != nil {
		return nil, err
	}
	home, err := st.EnsureSource(ctx, SourceHomeDomain, cfg.Ruleset.Detectors[homedomain.Code].Source)
	if err != nil {
		return nil, err
	}
	return &Pipeline{
		cfg: cfg, st: st, domains: domains, fetch: fetch,
		srcLook: look, srcHome: home, checked: map[string]bool{}, wait: sleep,
	}, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ledgerRun is the state of one Ledger call.
type ledgerRun struct {
	f        ingest.LedgerFacts
	log      *slog.Logger
	domains  map[string]string // home_domain values written in this ledger
	homeDone map[string]bool   // assets home-domain checked in this ledger
	touched  map[int64]bool
	latest   time.Time // latest observed_at stored in this ledger
	appended int
}

// Ledger processes one ledger's facts. It is idempotent by (network,
// sequence): evidence already stored for the same input is not appended
// again, and verdicts only change when the evidence set does.
func (p *Pipeline) Ledger(ctx context.Context, f ingest.LedgerFacts) error {
	if f.Network != p.cfg.Network {
		return fmt.Errorf("pipeline: facts for %s, configured %s", f.Network, p.cfg.Network)
	}
	if f.Sequence == 0 || f.CloseTime <= 0 {
		return fmt.Errorf("pipeline: ledger %d has no sequence or close time", f.Sequence)
	}
	r := &ledgerRun{
		f:        f,
		log:      p.cfg.Log.With("correlation_id", string(f.Network)+"-"+strconv.FormatUint(uint64(f.Sequence), 10)),
		domains:  map[string]string{},
		homeDone: map[string]bool{},
		touched:  map[int64]bool{},
	}
	for _, hd := range f.Facts.HomeDomains {
		r.domains[hd.Account] = hd.Domain
	}
	closeTime := time.Unix(f.CloseTime, 0).UTC()

	for _, a := range f.Facts.Assets {
		if err := p.asset(ctx, r, a.Code+":"+a.Issuer, closeTime); err != nil {
			return err
		}
	}
	// A changed home_domain re-checks the issuer's assets that already have
	// evidence (ARCHITECTURE §17 EC17: re-verify on change).
	for _, hd := range f.Facts.HomeDomains {
		assets, err := p.st.AssetsByIssuer(ctx, f.Network, hd.Account)
		if err != nil {
			return fmt.Errorf("pipeline: assets by issuer: %w", err)
		}
		for _, key := range assets {
			if r.homeDone[key] {
				continue
			}
			id, err := p.st.UpsertEntity(ctx, f.Network, entity.Asset, key, nil)
			if err != nil {
				return err
			}
			if err := p.homeDomain(ctx, r, id, key, hd.Account); err != nil {
				return err
			}
		}
	}

	if len(r.touched) > 0 {
		asOf := p.cfg.Now().UTC()
		if asOf.Before(r.latest) {
			// Clock behind the ledger: as_of must not precede the evidence.
			asOf = r.latest
		}
		changed := 0
		for id := range r.touched {
			_, ch, err := p.st.Recompute(ctx, id, asOf, p.cfg.Ruleset)
			if err != nil {
				return fmt.Errorf("pipeline: recompute: %w", err)
			}
			if ch {
				changed++
			}
		}
		r.log.Info("ledger processed", "seq", f.Sequence, "evidence_appended", r.appended,
			"entities_recomputed", len(r.touched), "verdicts_changed", changed)
	}
	return nil
}

// asset runs the look-alike detector on one asset and, for a candidate,
// the home-domain detector.
func (p *Pipeline) asset(ctx context.Context, r *ledgerRun, key string, observed time.Time) error {
	evs, err := p.cfg.Reference.Detect(r.f.Network, key, observed)
	if err != nil {
		return fmt.Errorf("pipeline: look-alike: %w", err)
	}
	if len(evs) == 0 {
		return nil
	}
	id, err := p.st.UpsertEntity(ctx, r.f.Network, entity.Asset, key, nil)
	if err != nil {
		return err
	}
	for _, ev := range evs {
		// Same asset, same reference match: already recorded (a later
		// trustline or a replayed ledger), so nothing new is observed.
		if _, err := p.store(ctx, r, id, p.srcLook, ev, false); err != nil {
			return err
		}
	}
	if p.checked[key] || r.homeDone[key] {
		return nil
	}
	_, issuer, _ := strings.Cut(key, ":")
	return p.homeDomain(ctx, r, id, key, issuer)
}

// homeDomain fetches the issuer's stellar.toml (rate-limited) and runs
// D-HOMEDOMAIN-MISMATCH for one asset.
func (p *Pipeline) homeDomain(ctx context.Context, r *ledgerRun, id int64, key, issuer string) error {
	r.homeDone[key] = true
	domain, ok := r.domains[issuer]
	if !ok {
		d, found, err := p.domains.HomeDomain(ctx, issuer)
		if err != nil {
			return fmt.Errorf("pipeline: home_domain lookup: %w", err)
		}
		if !found {
			// Issuer merged away: nothing to compare. Not checked, not clean.
			r.log.Info("home-domain not checked", "reason", "issuer_not_found")
			p.markChecked(key)
			return nil
		}
		domain = d
	}
	if domain == "" {
		r.log.Info("home-domain not checked", "reason", "no_home_domain")
		p.markChecked(key)
		return nil
	}

	in := homedomain.Input{Network: r.f.Network, Asset: key, HomeDomain: domain}
	if norm, err := entity.NormalizeKey(entity.Domain, domain); err == nil {
		url, err := fetcher.StellarTOMLURL(norm)
		if err != nil {
			return fmt.Errorf("pipeline: %w", err)
		}
		if err := p.rateLimit(ctx); err != nil {
			return err
		}
		res, ferr := p.fetch.Get(ctx, url)
		if ctx.Err() != nil {
			// Shutdown, not an observation about the domain.
			return ctx.Err()
		}
		in.Fetch = homedomain.Fetch{URL: url, FinalURL: res.FinalURL, Status: res.Status, Body: res.Body,
			Err: ferr, FetchedAt: p.cfg.Now().UTC()}
	}
	in.AsOf = p.cfg.Now().UTC()
	if !in.Fetch.FetchedAt.IsZero() && in.AsOf.Before(in.Fetch.FetchedAt) {
		in.AsOf = in.Fetch.FetchedAt
	}
	res, err := homedomain.Detect(in)
	if errors.Is(err, homedomain.ErrNoHomeDomain) {
		p.markChecked(key)
		return nil
	}
	if err != nil {
		return fmt.Errorf("pipeline: home-domain: %w", err)
	}
	for _, nc := range res.NotChecked {
		r.log.Info("home-domain not checked", "reason", nc)
	}
	for _, ev := range res.Evidence {
		if _, err := p.store(ctx, r, id, p.srcHome, ev, true); err != nil {
			return err
		}
	}
	p.markChecked(key)
	return nil
}

func (p *Pipeline) markChecked(key string) {
	if len(p.checked) >= maxChecked {
		clear(p.checked)
	}
	p.checked[key] = true
}

func (p *Pipeline) rateLimit(ctx context.Context) error {
	now := p.cfg.Now()
	if !p.lastGet.IsZero() {
		if d := p.lastGet.Add(p.cfg.FetchInterval).Sub(now); d > 0 {
			if err := p.wait(ctx, d); err != nil {
				return err
			}
			now = p.cfg.Now()
		}
	}
	p.lastGet = now
	return nil
}

// payload is what an evidence row stores. It holds the detector's facts and
// artifact references and leaves out observed_at, so the same observation
// has the same payload and is not appended twice.
type payload struct {
	Entity    string                  `json:"entity"`
	MaxLevel  string                  `json:"max_level"`
	Facts     []detectors.Fact        `json:"facts"`
	Artifacts []detectors.ArtifactRef `json:"artifacts,omitempty"`
}

// store appends ev unless an equal row exists. perLedger dedups on
// (entity, detector, ledger) instead of on the payload, for detectors whose
// payload carries a fetch time.
func (p *Pipeline) store(ctx context.Context, r *ledgerRun, entityID int64, source int16, ev detectors.Evidence, perLedger bool) (bool, error) {
	if err := ev.Validate(); err != nil {
		return false, fmt.Errorf("pipeline: %w", err)
	}
	asset, _ := ev.Fact("asset")
	if want, err := entity.Canonical(r.f.Network, entity.Asset, asset); err != nil || want != ev.Entity {
		return false, fmt.Errorf("pipeline: evidence entity does not match its asset")
	}
	body, err := json.Marshal(payload{Entity: ev.Entity, MaxLevel: string(ev.MaxLevel), Facts: ev.Facts, Artifacts: ev.Artifacts})
	if err != nil {
		return false, err
	}
	q := store.EvidenceQuery{EntityID: entityID, Detector: ev.Detector}
	if perLedger {
		q.LedgerSeq = int64(r.f.Sequence)
	} else {
		q.Payload = body
	}
	// Recompute even when the row exists: a crash between append and
	// recompute must not leave the stored evidence without a verdict.
	r.touched[entityID] = true
	if ev.ObservedAt.After(r.latest) {
		r.latest = ev.ObservedAt
	}
	exists, err := p.st.HasEvidence(ctx, q)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	// TODO: store raw artifacts (the fetched stellar.toml bytes) write-once in
	// the object store and reference them here; the payload keeps their sha256.
	if _, err := p.st.AppendEvidence(ctx, evidence.New{
		EntityID:   entityID,
		SourceID:   source,
		Detector:   ev.Detector,
		Class:      evidence.Class(ev.Class),
		Category:   ev.Category,
		Payload:    body,
		ObservedAt: ev.ObservedAt,
		LedgerSeq:  int64(r.f.Sequence),
	}); err != nil {
		return false, fmt.Errorf("pipeline: append evidence: %w", err)
	}
	r.appended++
	return true, nil
}
