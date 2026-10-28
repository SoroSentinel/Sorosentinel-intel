package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/assetlookalike"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/homedomain"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

var (
	refIssuer  = xdrtest.Address(1) // the reference set's known USDC issuer
	lookIssuer = xdrtest.Address(2) // issues a look-alike USDC
	otherIssu  = xdrtest.Address(4)
	t0         = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	tomlURL    = "https://example.org/.well-known/stellar.toml"
)

type harness struct {
	p    *Pipeline
	st   *memStore
	dom  *fakeDomains
	fet  *fakeFetcher
	clk  *clock
	wait []time.Duration
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ref, err := assetlookalike.NewReference(map[string][]string{"USDC": {refIssuer}, "XLM": {}})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		st:  newMemStore(),
		dom: &fakeDomains{domains: map[string]string{lookIssuer: "", otherIssu: ""}},
		fet: &fakeFetcher{bodies: map[string]string{}},
		clk: &clock{t: t0},
	}
	h.p, err = New(context.Background(), Config{
		Network: entity.Testnet, Reference: ref, Ruleset: verdict.V1, Now: h.clk.Now, FetchInterval: time.Second,
	}, h.st, h.dom, h.fet)
	if err != nil {
		t.Fatal(err)
	}
	h.p.wait = func(_ context.Context, d time.Duration) error {
		h.wait = append(h.wait, d)
		h.clk.t = h.clk.t.Add(d)
		return nil
	}
	return h
}

func facts(seq uint32, assets []xdrcompat.Asset, domains ...xdrcompat.HomeDomain) ingest.LedgerFacts {
	return ingest.LedgerFacts{
		Network: entity.Testnet, Sequence: seq, CloseTime: t0.Add(-10 * time.Second).Unix(),
		Facts: xdrcompat.Facts{Assets: assets, HomeDomains: domains},
	}
}

func usdc(issuer string) []xdrcompat.Asset {
	return []xdrcompat.Asset{{Code: "USDC", Issuer: issuer}}
}

func tomlListing(code, issuer string) string {
	return "[[CURRENCIES]]\ncode = \"" + code + "\"\nissuer = \"" + issuer + "\"\n"
}

func TestLookalikeIsFlaggedAndReplayIsIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := facts(100, usdc(lookIssuer))
	if err := h.p.Ledger(ctx, f); err != nil {
		t.Fatal(err)
	}
	v := h.st.verdictOf(entity.Testnet, "USDC:"+lookIssuer)
	if v == nil || v.Level != signal.Suspicious || v.RuleID != verdict.RuleAutomated || v.Category != assetlookalike.Category {
		t.Fatalf("verdict = %+v", v)
	}
	if !v.AsOf.Equal(t0) {
		t.Errorf("as_of = %v, want the worker clock %v", v.AsOf, t0)
	}
	if n := h.st.rowsFor(assetlookalike.Code); n != 1 {
		t.Fatalf("look-alike rows = %d", n)
	}
	if len(h.fet.urls) != 0 {
		t.Errorf("fetched %v for an issuer without home_domain", h.fet.urls)
	}

	// Replaying the ledger (crash before the checkpoint) and a later
	// trustline to the same asset add nothing.
	h.clk.t = t0.Add(time.Minute)
	for _, again := range []ingest.LedgerFacts{f, facts(101, usdc(lookIssuer))} {
		if err := h.p.Ledger(ctx, again); err != nil {
			t.Fatal(err)
		}
	}
	if n := h.st.rowsFor(assetlookalike.Code); n != 1 || len(h.st.events) != 1 {
		t.Errorf("after replay: rows = %d, events = %d; want 1, 1", n, len(h.st.events))
	}
}

func TestReferenceIssuerAndUnrelatedAssetsProduceNothing(t *testing.T) {
	h := newHarness(t)
	err := h.p.Ledger(context.Background(), facts(100, []xdrcompat.Asset{
		{Code: "USDC", Issuer: refIssuer},
		{Code: "ABC", Issuer: lookIssuer},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.st.entities) != 0 || len(h.st.rows) != 0 || h.dom.calls != 0 || len(h.fet.urls) != 0 {
		t.Errorf("entities=%d rows=%d lookups=%d fetches=%d; want all 0",
			len(h.st.entities), len(h.st.rows), h.dom.calls, len(h.fet.urls))
	}
	flagged, _ := h.st.ListFlagged(context.Background(), entity.Testnet)
	if len(flagged) != 0 {
		t.Errorf("flagged = %v", flagged)
	}
}

func TestHomeDomainMismatchIsCheckedOnce(t *testing.T) {
	h := newHarness(t)
	h.dom.domains[lookIssuer] = "example.org"
	h.fet.bodies[tomlURL] = tomlListing("EURC", lookIssuer)
	ctx := context.Background()
	if err := h.p.Ledger(ctx, facts(100, usdc(lookIssuer))); err != nil {
		t.Fatal(err)
	}
	if n := h.st.rowsFor(homedomain.Code); n != 1 {
		t.Fatalf("home-domain rows = %d", n)
	}
	if len(h.fet.urls) != 1 || h.fet.urls[0] != tomlURL {
		t.Fatalf("fetches = %v", h.fet.urls)
	}
	if err := h.p.Ledger(ctx, facts(101, usdc(lookIssuer))); err != nil {
		t.Fatal(err)
	}
	if len(h.fet.urls) != 1 || h.st.rowsFor(homedomain.Code) != 1 {
		t.Errorf("second trustline re-fetched (%d) or re-stored (%d)", len(h.fet.urls), h.st.rowsFor(homedomain.Code))
	}
}

func TestHomeDomainListingAddsNoEvidence(t *testing.T) {
	h := newHarness(t)
	h.dom.domains[lookIssuer] = "example.org"
	h.fet.bodies[tomlURL] = tomlListing("USDC", lookIssuer)
	if err := h.p.Ledger(context.Background(), facts(100, usdc(lookIssuer))); err != nil {
		t.Fatal(err)
	}
	if n := h.st.rowsFor(homedomain.Code); n != 0 {
		t.Errorf("home-domain rows = %d for a listed asset", n)
	}
	// Listing itself in its own stellar.toml does not clear the look-alike.
	if v := h.st.verdictOf(entity.Testnet, "USDC:"+lookIssuer); v == nil || v.Level != signal.Suspicious {
		t.Errorf("verdict = %+v", v)
	}
}

func TestHomeDomainChangeRechecksKnownAssets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.p.Ledger(ctx, facts(100, usdc(lookIssuer))); err != nil {
		t.Fatal(err)
	}
	lookups := h.dom.calls
	h.fet.bodies[tomlURL] = "not toml ["
	err := h.p.Ledger(ctx, facts(101, nil, xdrcompat.HomeDomain{Account: lookIssuer, Domain: "example.org"}))
	if err != nil {
		t.Fatal(err)
	}
	if h.dom.calls != lookups {
		t.Errorf("looked up a home_domain the ledger already carried")
	}
	if len(h.fet.urls) != 1 || h.st.rowsFor(homedomain.Code) != 1 {
		t.Errorf("fetches = %v, home-domain rows = %d", h.fet.urls, h.st.rowsFor(homedomain.Code))
	}
	// An unrelated account's change touches nothing.
	if err := h.p.Ledger(ctx, facts(102, nil, xdrcompat.HomeDomain{Account: otherIssu, Domain: "example.org"})); err != nil {
		t.Fatal(err)
	}
	if len(h.fet.urls) != 1 {
		t.Errorf("fetched for an account without assets: %v", h.fet.urls)
	}
}

func TestFetchFailureIsRecordedAsEvidence(t *testing.T) {
	h := newHarness(t)
	h.dom.domains[lookIssuer] = "example.org"
	h.fet.err = errors.New("connection refused")
	if err := h.p.Ledger(context.Background(), facts(100, usdc(lookIssuer))); err != nil {
		t.Fatal(err)
	}
	if n := h.st.rowsFor(homedomain.Code); n != 1 {
		t.Errorf("home-domain rows = %d; an unreachable domain is evidence, not a clean result", n)
	}
}

func TestShutdownDuringFetchRecordsNothing(t *testing.T) {
	h := newHarness(t)
	h.dom.domains[lookIssuer] = "example.org"
	ctx, cancel := context.WithCancel(context.Background())
	h.fet.onGet = cancel
	h.fet.err = context.Canceled
	err := h.p.Ledger(ctx, facts(100, usdc(lookIssuer)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if n := h.st.rowsFor(homedomain.Code); n != 0 {
		t.Errorf("shutdown was stored as a fetch failure (%d rows)", n)
	}
}

func TestDomainLookupErrorFailsTheLedger(t *testing.T) {
	h := newHarness(t)
	h.dom.err = errors.New("rpc down")
	if err := h.p.Ledger(context.Background(), facts(100, usdc(lookIssuer))); err == nil {
		t.Fatal("lookup error was swallowed")
	}
	if len(h.fet.urls) != 0 {
		t.Errorf("fetched after a failed lookup")
	}
}

func TestFetchesAreRateLimited(t *testing.T) {
	h := newHarness(t)
	h.dom.domains[lookIssuer] = "example.org"
	h.dom.domains[otherIssu] = "example.org"
	err := h.p.Ledger(context.Background(), facts(100, []xdrcompat.Asset{
		{Code: "USDC", Issuer: lookIssuer}, {Code: "XLM", Issuer: otherIssu},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.fet.urls) != 2 || len(h.wait) != 1 || h.wait[0] != time.Second {
		t.Errorf("fetches = %d, waits = %v; want 2 fetches and one 1s wait", len(h.fet.urls), h.wait)
	}
}

func TestClockBehindLedgerUsesEvidenceTime(t *testing.T) {
	h := newHarness(t)
	f := facts(100, usdc(lookIssuer))
	h.clk.t = time.Unix(f.CloseTime, 0).Add(-time.Hour)
	if err := h.p.Ledger(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	v := h.st.verdictOf(entity.Testnet, "USDC:"+lookIssuer)
	if v == nil || v.Level != signal.Suspicious || !v.AsOf.Equal(time.Unix(f.CloseTime, 0)) {
		t.Errorf("verdict = %+v; as_of must not precede the evidence", v)
	}
}

func TestLedgerRejectsBadInput(t *testing.T) {
	h := newHarness(t)
	f := facts(100, usdc(lookIssuer))
	f.Network = entity.Public
	if err := h.p.Ledger(context.Background(), f); err == nil {
		t.Error("accepted facts for another network")
	}
	f = facts(100, []xdrcompat.Asset{{Code: "US DC", Issuer: lookIssuer}})
	if err := h.p.Ledger(context.Background(), f); err == nil {
		t.Error("accepted an invalid asset code")
	}
	f = facts(100, nil)
	f.CloseTime = 0
	if err := h.p.Ledger(context.Background(), f); err == nil {
		t.Error("accepted a ledger without close time")
	}
}

func TestNewValidatesConfig(t *testing.T) {
	ref, _ := assetlookalike.NewReference(map[string][]string{"XLM": {}})
	ok := Config{Network: entity.Testnet, Reference: ref, Ruleset: verdict.V1, Now: time.Now}
	bad := []func(c *Config){
		func(c *Config) { c.Network = "futurenet" },
		func(c *Config) { c.Reference = nil },
		func(c *Config) { c.Now = nil },
		func(c *Config) { c.Ruleset = verdict.Ruleset{} },
		func(c *Config) {
			c.Ruleset = verdict.Ruleset{Version: "2026.10.9", Detectors: map[string]verdict.DetectorRule{
				homedomain.Code: verdict.V1.Detectors[homedomain.Code]}}
		},
	}
	for i, mod := range bad {
		c := ok
		mod(&c)
		if _, err := New(context.Background(), c, newMemStore(), &fakeDomains{}, &fakeFetcher{}); err == nil {
			t.Errorf("case %d: accepted", i)
		}
	}
	if _, err := New(context.Background(), ok, newMemStore(), &fakeDomains{}, &fakeFetcher{}); err != nil {
		t.Errorf("valid config: %v", err)
	}
}
