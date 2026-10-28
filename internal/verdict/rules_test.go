package verdict

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

func ptr(t time.Time) *time.Time { return &t }

func lookalike(id int64, observed time.Time, expires *time.Time) evidence.Evidence {
	return evidence.Evidence{ID: id, EntityID: 1, SourceKind: evidence.Heuristic, Detector: evidence.DetectorAssetLookalike,
		Class: evidence.ClassOnchainPattern, Category: "impersonation_asset", ObservedAt: observed, ExpiresAt: expires}
}

func homeDomain(id int64, observed time.Time) evidence.Evidence {
	return evidence.Evidence{ID: id, EntityID: 1, SourceKind: evidence.Heuristic, Detector: evidence.DetectorHomeDomain,
		Class: evidence.ClassDomain, Category: "home_domain_mismatch", ObservedAt: observed}
}

func flagsRisk(id int64, observed time.Time) evidence.Evidence {
	return evidence.Evidence{ID: id, EntityID: 1, SourceKind: evidence.Heuristic, Detector: evidence.DetectorFlagsRisk,
		Class: evidence.ClassOnchainPattern, Category: "issuer_flags", ObservedAt: observed}
}

func confirm(id int64, observed time.Time, lvl signal.Internal) evidence.Evidence {
	return evidence.Evidence{ID: id, EntityID: 1, SourceKind: evidence.Curated, Detector: evidence.DetectorCurated,
		Class: evidence.ClassHuman, Category: "impersonation_asset", ObservedAt: observed, ConfirmedLevel: lvl, ConfirmedBy: "analyst-1"}
}

func mustDecide(t *testing.T, ev []evidence.Evidence, asOf time.Time) Decision {
	t.Helper()
	d, err := Decide(ev, asOf, V1)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return d
}

func TestV1Valid(t *testing.T) {
	if err := V1.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSingleAutomatedDetectorIsSuspicious(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{lookalike(1, at(0), nil)}, at(1))
	if d.Level != signal.Suspicious || d.RuleID != RuleAutomated || d.Category != "impersonation_asset" {
		t.Fatalf("got %+v", d)
	}
}

func TestAutomatedCapsAtSuspicious(t *testing.T) {
	// Two independent automated classes and a community report still stay at suspicious.
	report := evidence.Evidence{ID: 3, EntityID: 1, SourceKind: evidence.Community, Detector: evidence.DetectorCommunityReport,
		Class: evidence.ClassCommunity, Category: "impersonation_asset", ObservedAt: at(2)}
	d := mustDecide(t, []evidence.Evidence{lookalike(1, at(0), nil), homeDomain(2, at(1)), report}, at(3))
	if d.Level != signal.Suspicious {
		t.Fatalf("automated evidence reached %s", d.Level)
	}
}

func TestRulesetRejectsAutomatedMalicious(t *testing.T) {
	rs := Ruleset{Version: "2026.10.99", Detectors: map[string]DetectorRule{
		evidence.DetectorAssetLookalike: {Class: evidence.ClassOnchainPattern, Source: evidence.Heuristic, MaxAlone: signal.Malicious},
	}}
	if _, err := Decide([]evidence.Evidence{lookalike(1, at(0), nil)}, at(1), rs); err == nil {
		t.Fatal("ruleset letting automated evidence reach malicious was accepted")
	}
}

func TestExpiry(t *testing.T) {
	ev := []evidence.Evidence{lookalike(1, at(0), ptr(at(10)))}
	if d := mustDecide(t, ev, at(9)); d.Level != signal.Suspicious {
		t.Fatalf("before expiry: %+v", d)
	}
	// Expiring exactly at as_of no longer counts.
	for _, asOf := range []time.Time{at(10), at(11)} {
		d := mustDecide(t, ev, asOf)
		if d.Level != signal.Unknown || d.RuleID != RuleNoActiveEvidence {
			t.Fatalf("at %v: %+v", asOf, d)
		}
		if !slices.Equal(d.EvidenceIDs, []int64{1}) {
			t.Fatalf("expired evidence must still be recorded as considered: %v", d.EvidenceIDs)
		}
	}
}

func TestFutureEvidenceIgnored(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{lookalike(1, at(5), nil)}, at(1))
	if d.Level != signal.Unknown {
		t.Fatalf("evidence observed after as_of counted: %+v", d)
	}
}

func TestInformationalNeverRaisesAlone(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{flagsRisk(1, at(0))}, at(1))
	if d.Level != signal.Unknown || d.RuleID != RuleInformationalAll {
		t.Fatalf("got %+v", d)
	}
}

func TestMaliciousNeedsHumanConfirmation(t *testing.T) {
	ev := []evidence.Evidence{lookalike(1, at(0), nil), homeDomain(2, at(1))}
	if d := mustDecide(t, ev, at(2)); d.Level == signal.Malicious {
		t.Fatal("malicious without a human confirmation")
	}
	ev = append(ev, confirm(3, at(2), signal.Malicious))
	d := mustDecide(t, ev, at(3))
	if d.Level != signal.Malicious || d.RuleID != RuleHumanConfirmed {
		t.Fatalf("got %+v", d)
	}
}

func TestConfirmationMustComeFromCuratedSource(t *testing.T) {
	c := confirm(1, at(0), signal.Malicious)
	c.SourceKind = evidence.Heuristic
	if _, err := Decide([]evidence.Evidence{c}, at(1), V1); err == nil {
		t.Fatal("confirmation from a heuristic source was accepted")
	}
	c = lookalike(1, at(0), nil)
	c.ConfirmedLevel, c.ConfirmedBy = signal.Malicious, "analyst-1"
	if _, err := Decide([]evidence.Evidence{c}, at(1), V1); err == nil {
		t.Fatal("confirmation on an automated detector was accepted")
	}
}

func TestLatestConfirmationWins(t *testing.T) {
	ev := []evidence.Evidence{confirm(2, at(1), signal.Malicious), confirm(1, at(0), signal.Suspicious)}
	if d := mustDecide(t, ev, at(2)); d.Level != signal.Malicious {
		t.Fatalf("got %+v", d)
	}
	// Same timestamp: higher id is later.
	ev = []evidence.Evidence{confirm(5, at(1), signal.Benign), confirm(4, at(1), signal.Malicious)}
	if d := mustDecide(t, ev, at(2)); d.Level != signal.Benign {
		t.Fatalf("got %+v", d)
	}
}

func TestExpiredConfirmationIgnored(t *testing.T) {
	c := confirm(2, at(1), signal.Malicious)
	c.ExpiresAt = ptr(at(5))
	d := mustDecide(t, []evidence.Evidence{lookalike(1, at(0), nil), c}, at(6))
	if d.Level != signal.Suspicious || d.RuleID != RuleAutomated {
		t.Fatalf("got %+v", d)
	}
}

func TestHumanBenignBeatsOlderAutomated(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{lookalike(1, at(0), nil), confirm(2, at(1), signal.Benign)}, at(2))
	if d.Level != signal.Benign || d.RuleID != RuleHumanConfirmed || d.NeedsReview {
		t.Fatalf("got %+v", d)
	}
}

func TestNewerAutomatedSupersedesHumanBenign(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{confirm(1, at(0), signal.Benign), lookalike(2, at(1), nil)}, at(2))
	if d.Level != signal.Suspicious || d.RuleID != RuleHumanSuperseded || !d.NeedsReview {
		t.Fatalf("got %+v", d)
	}
	// Newer informational evidence does not supersede.
	d = mustDecide(t, []evidence.Evidence{confirm(1, at(0), signal.Benign), flagsRisk(2, at(1))}, at(2))
	if d.Level != signal.Benign {
		t.Fatalf("got %+v", d)
	}
}

func TestNewerAutomatedNeverLowersHumanMalicious(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{confirm(1, at(0), signal.Malicious), lookalike(2, at(1), nil)}, at(2))
	if d.Level != signal.Malicious {
		t.Fatalf("got %+v", d)
	}
}

func TestHostileInputFailsLoud(t *testing.T) {
	unknown := lookalike(1, at(0), nil)
	unknown.Detector = "D-NOT-IN-TABLE"
	wrongClass := lookalike(1, at(0), nil)
	wrongClass.Class = evidence.ClassHuman
	mixed := []evidence.Evidence{lookalike(1, at(0), nil), lookalike(2, at(0), nil)}
	mixed[1].EntityID = 2
	badLevel := confirm(1, at(0), "safe")
	cases := map[string][]evidence.Evidence{
		"unknown detector": {unknown},
		"wrong class":      {wrongClass},
		"mixed entities":   mixed,
		"duplicate id":     {lookalike(1, at(0), nil), lookalike(1, at(1), nil)},
		"bad level":        {badLevel},
		"expires first":    {lookalike(1, at(5), ptr(at(1)))},
	}
	for name, ev := range cases {
		if _, err := Decide(ev, at(10), V1); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Decide(nil, at(1), V1); !errors.Is(err, ErrNoEvidence) {
		t.Errorf("no evidence: %v", err)
	}
	if _, err := Decide([]evidence.Evidence{lookalike(1, at(0), nil)}, time.Time{}, V1); err == nil {
		t.Error("zero as_of accepted")
	}
}

func TestOrderIndependent(t *testing.T) {
	ev := []evidence.Evidence{confirm(3, at(2), signal.Benign), lookalike(1, at(0), nil), homeDomain(2, at(3))}
	a := mustDecide(t, ev, at(4))
	slices.Reverse(ev)
	b := mustDecide(t, ev, at(4))
	if a.Level != b.Level || a.RuleID != b.RuleID || a.Category != b.Category || !slices.Equal(a.EvidenceIDs, b.EvidenceIDs) {
		t.Fatalf("order changed the result: %+v vs %+v", a, b)
	}
}

// Replay: stored (evidence, as_of, ruleset_version) reproduce stored verdicts.
type replayCase struct {
	Name           string              `json:"name"`
	RulesetVersion string              `json:"ruleset_version"`
	AsOf           time.Time           `json:"as_of"`
	Evidence       []evidence.Evidence `json:"evidence"`
	Want           struct {
		Level       signal.Internal `json:"level"`
		RuleID      string          `json:"rule_id"`
		Category    string          `json:"category"`
		EvidenceIDs []int64         `json:"evidence_ids"`
	} `json:"want"`
}

func TestReplayStoredVerdicts(t *testing.T) {
	raw, err := os.ReadFile("testdata/replay_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []replayCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no replay cases")
	}
	for _, c := range cases {
		rs, err := Lookup(c.RulesetVersion)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		d, err := Decide(c.Evidence, c.AsOf, rs)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if d.Level != c.Want.Level || d.RuleID != c.Want.RuleID || d.Category != c.Want.Category ||
			!slices.Equal(d.EvidenceIDs, c.Want.EvidenceIDs) || !d.AsOf.Equal(c.AsOf) {
			t.Errorf("%s: replay got %+v, stored %+v", c.Name, d, c.Want)
		}
	}
}
