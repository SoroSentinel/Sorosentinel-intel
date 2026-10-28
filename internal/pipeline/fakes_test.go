package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/fetcher"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

// memStore is an in-memory Store and PublishStore that runs the real rule
// table, so unit tests exercise the same decisions as Postgres.
type memStore struct {
	mu        sync.Mutex
	sources   map[string]evidence.SourceKind
	sourceIDs map[string]int16
	entities  map[string]int64 // network|type|key -> id
	keys      map[int64]snapshot.Entity
	nets      map[int64]entity.Network
	rows      []memRow
	verdicts  map[int64]*verdict.Verdict
	events    []verdict.Event
	snapshots []store.SnapshotRecord
	recordErr error
}

type memRow struct {
	evidence.Evidence
	payload json.RawMessage
	ledger  int64
}

func newMemStore() *memStore {
	return &memStore{
		sources: map[string]evidence.SourceKind{}, sourceIDs: map[string]int16{},
		entities: map[string]int64{}, keys: map[int64]snapshot.Entity{}, nets: map[int64]entity.Network{},
		verdicts: map[int64]*verdict.Verdict{},
	}
}

func (m *memStore) EnsureSource(_ context.Context, name string, kind evidence.SourceKind) (int16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.sources[name]; ok {
		if k != kind {
			return 0, errors.New("kind mismatch")
		}
		return m.sourceIDs[name], nil
	}
	m.sources[name] = kind
	m.sourceIDs[name] = int16(len(m.sources))
	return m.sourceIDs[name], nil
}

func (m *memStore) kindOf(id int16) evidence.SourceKind {
	for n, i := range m.sourceIDs {
		if i == id {
			return m.sources[n]
		}
	}
	return ""
}

func (m *memStore) UpsertEntity(_ context.Context, n entity.Network, typ entity.Type, key string, _ json.RawMessage) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	norm, err := entity.NormalizeKey(typ, key)
	if err != nil {
		return 0, err
	}
	k := string(n) + "|" + string(typ) + "|" + norm
	if id, ok := m.entities[k]; ok {
		return id, nil
	}
	id := int64(len(m.entities) + 1)
	m.entities[k] = id
	m.keys[id] = snapshot.Entity{Type: typ, Key: norm}
	m.nets[id] = n
	return id, nil
}

func (m *memStore) AppendEvidence(_ context.Context, n evidence.New) (int64, error) {
	if err := n.Validate(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := int64(len(m.rows) + 1)
	m.rows = append(m.rows, memRow{
		Evidence: evidence.Evidence{
			ID: id, EntityID: n.EntityID, SourceKind: m.kindOf(n.SourceID), Detector: n.Detector,
			Class: n.Class, Category: n.Category, ObservedAt: n.ObservedAt, ExpiresAt: n.ExpiresAt,
		},
		payload: n.Payload, ledger: n.LedgerSeq,
	})
	return id, nil
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return bytes.Equal(ja, jb)
}

func (m *memStore) HasEvidence(_ context.Context, q store.EvidenceQuery) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.EntityID == q.EntityID && r.Detector == q.Detector &&
			(q.LedgerSeq == 0 || r.ledger == q.LedgerSeq) &&
			(q.Payload == nil || jsonEqual(r.payload, q.Payload)) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) AssetsByIssuer(_ context.Context, n entity.Network, issuer string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for id, e := range m.keys {
		if m.nets[id] == n && e.Type == entity.Asset && strings.HasSuffix(e.Key, ":"+issuer) {
			out = append(out, e.Key)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memStore) evidenceFor(id int64) []evidence.Evidence {
	var ev []evidence.Evidence
	for _, r := range m.rows {
		if r.EntityID == id {
			ev = append(ev, r.Evidence)
		}
	}
	return ev
}

func (m *memStore) Recompute(_ context.Context, id int64, asOf time.Time, rs verdict.Ruleset) (verdict.Verdict, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := verdict.Decide(m.evidenceFor(id), asOf, rs)
	if err != nil {
		return verdict.Verdict{}, false, err
	}
	next, ev, changed, err := verdict.Apply(m.verdicts[id], id, d, verdict.EngineActor)
	if err != nil {
		return verdict.Verdict{}, false, err
	}
	if changed {
		v := next
		m.verdicts[id] = &v
		m.events = append(m.events, ev)
	}
	return next, changed, nil
}

func (m *memStore) ListFlagged(_ context.Context, n entity.Network) ([]snapshot.Entity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []snapshot.Entity
	for id, v := range m.verdicts {
		if m.nets[id] == n && v.Status == verdict.Active && (v.Level == signal.Suspicious || v.Level == signal.Malicious) {
			out = append(out, m.keys[id])
		}
	}
	slices.SortFunc(out, func(a, b snapshot.Entity) int { return strings.Compare(string(a.Type)+a.Key, string(b.Type)+b.Key) })
	return out, nil
}

func (m *memStore) NextSnapshotVersion(_ context.Context, n entity.Network) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var v uint64
	for _, s := range m.snapshots {
		if s.Network == n && s.Version > v {
			v = s.Version
		}
	}
	return v + 1, nil
}

func (m *memStore) RecordSnapshot(_ context.Context, r store.SnapshotRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordErr != nil {
		return m.recordErr
	}
	m.snapshots = append(m.snapshots, r)
	return nil
}

func (m *memStore) verdictOf(n entity.Network, key string) *verdict.Verdict {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.entities[string(n)+"|asset|"+key]
	if !ok {
		return nil
	}
	return m.verdicts[id]
}

func (m *memStore) rowsFor(detector string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.rows {
		if r.Detector == detector {
			n++
		}
	}
	return n
}

// fakeDomains serves home_domain lookups from a map.
type fakeDomains struct {
	domains map[string]string
	calls   int
	err     error
}

func (f *fakeDomains) HomeDomain(_ context.Context, account string) (string, bool, error) {
	f.calls++
	if f.err != nil {
		return "", false, f.err
	}
	d, ok := f.domains[account]
	return d, ok, nil
}

// fakeFetcher serves stellar.toml bodies by URL.
type fakeFetcher struct {
	bodies map[string]string
	urls   []string
	err    error
	onGet  func()
}

func (f *fakeFetcher) Get(_ context.Context, url string) (fetcher.Result, error) {
	f.urls = append(f.urls, url)
	if f.onGet != nil {
		f.onGet()
	}
	if f.err != nil {
		return fetcher.Result{}, f.err
	}
	b, ok := f.bodies[url]
	if !ok {
		return fetcher.Result{FinalURL: url, Status: 404}, nil
	}
	return fetcher.Result{FinalURL: url, Status: 200, Body: []byte(b)}, nil
}

// clock is a manual clock for Config.Now.
type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }
