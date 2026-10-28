// Package verdict decides an entity's internal level from its stored evidence
// with a rule table (ARCHITECTURE_ESSENTIALS §12 HQ3: no numeric score).
//
// Decide is a pure function of (evidence, as_of, ruleset): it never reads the
// clock, so stored verdicts replay exactly. Automated sources cap at
// suspicious; malicious needs a human confirmation record (v1).
package verdict

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

// Rule IDs recorded with every decision.
const (
	RuleNoActiveEvidence = "R-NO-ACTIVE-EVIDENCE" // everything expired or not yet observed: unknown
	RuleHumanConfirmed   = "R-HUMAN-CONFIRMED"    // latest active human confirmation decides
	RuleHumanSuperseded  = "R-HUMAN-SUPERSEDED"   // newer automated evidence outranks a lower human level; needs review
	RuleAutomated        = "R-AUTOMATED"          // highest level any active automated detector reaches alone
	RuleInformationalAll = "R-INFORMATIONAL-ONLY" // only informational detectors fired: unknown
)

// DetectorRule says what one detector may contribute.
type DetectorRule struct {
	Class  evidence.Class
	Source evidence.SourceKind
	// MaxAlone is the highest level this detector reaches by itself. Never
	// above suspicious for an automated source.
	MaxAlone signal.Internal
	// Informational detectors never raise a level (D-FLAGS-RISK, D-CONTRACT-SCAN
	// indicators); they stay at unknown and are recorded for review.
	Informational bool
}

// Ruleset is one versioned rule table. Change the table, bump the version.
type Ruleset struct {
	Version   string
	Detectors map[string]DetectorRule
}

// V1 is ruleset 2026.10.1 (ARCHITECTURE §4.2, Phase 1).
var V1 = Ruleset{
	Version: "2026.10.1",
	Detectors: map[string]DetectorRule{
		evidence.DetectorAssetLookalike:  {Class: evidence.ClassOnchainPattern, Source: evidence.Heuristic, MaxAlone: signal.Suspicious},
		evidence.DetectorHomeDomain:      {Class: evidence.ClassDomain, Source: evidence.Heuristic, MaxAlone: signal.Suspicious},
		evidence.DetectorFlagsRisk:       {Class: evidence.ClassOnchainPattern, Source: evidence.Heuristic, MaxAlone: signal.Unknown, Informational: true},
		evidence.DetectorTrustlineSpam:   {Class: evidence.ClassOnchainPattern, Source: evidence.Heuristic, MaxAlone: signal.Suspicious},
		evidence.DetectorAccountTakeover: {Class: evidence.ClassOnchainPattern, Source: evidence.Heuristic, MaxAlone: signal.Suspicious},
		// TODO: known-bad-hash and combined-with-another-class raises for scan
		// evidence wait for the Scan decision (ADR 0002, still open).
		evidence.DetectorContractScan:    {Class: evidence.ClassScan, Source: evidence.Scan, MaxAlone: signal.Unknown, Informational: true},
		evidence.DetectorCommunityReport: {Class: evidence.ClassCommunity, Source: evidence.Community, MaxAlone: signal.Suspicious},
		evidence.DetectorCurated:         {Class: evidence.ClassHuman, Source: evidence.Curated, MaxAlone: signal.Malicious},
	},
}

var rulesets = map[string]Ruleset{V1.Version: V1}

// Lookup returns a known ruleset by version, for replaying stored verdicts.
func Lookup(version string) (Ruleset, error) {
	rs, ok := rulesets[version]
	if !ok {
		return Ruleset{}, fmt.Errorf("verdict: unknown ruleset %q", version)
	}
	return rs, nil
}

var versionRe = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]+$`)

// Validate rejects a table that would let automated evidence exceed suspicious.
func (rs Ruleset) Validate() error {
	if !versionRe.MatchString(rs.Version) || len(rs.Detectors) == 0 {
		return errors.New("verdict: invalid ruleset")
	}
	for id, r := range rs.Detectors {
		if _, err := signal.ToPublic(r.MaxAlone); err != nil || !r.Source.Valid() {
			return fmt.Errorf("verdict: invalid rule for %s", id)
		}
		if r.Source != evidence.Curated && rank(r.MaxAlone) > rank(signal.Suspicious) {
			return fmt.Errorf("verdict: automated detector %s exceeds suspicious", id)
		}
		if r.Informational && r.MaxAlone != signal.Unknown {
			return fmt.Errorf("verdict: informational detector %s must stay at unknown", id)
		}
	}
	return nil
}

// Decision is the rule table's output. It carries everything needed to replay it.
type Decision struct {
	Level          signal.Internal
	RuleID         string
	Category       string // category of the evidence that decided the level; empty for unknown
	AsOf           time.Time
	RulesetVersion string
	// EvidenceIDs are every row considered (active or not), sorted. Replaying
	// Decide over exactly these rows at AsOf reproduces this decision.
	EvidenceIDs []int64
	// NeedsReview is set when automated evidence newer than the latest human
	// confirmation outranks it; a human must re-review.
	NeedsReview bool
}

var ErrNoEvidence = errors.New("verdict: no stored evidence")

// Decide applies rs to ev at asOf. Unknown detectors, rows that don't match
// their detector's class or source, and inconsistent input are errors, never
// a guessed level.
func Decide(ev []evidence.Evidence, asOf time.Time, rs Ruleset) (Decision, error) {
	if asOf.IsZero() {
		return Decision{}, errors.New("verdict: as_of is required")
	}
	if err := rs.Validate(); err != nil {
		return Decision{}, err
	}
	if len(ev) == 0 {
		return Decision{}, ErrNoEvidence
	}
	if len(ev) > evidence.MaxPerVerdict {
		return Decision{}, errors.New("verdict: too much evidence for one decision")
	}

	rows := slices.Clone(ev)
	slices.SortFunc(rows, byObserved)
	ids := make([]int64, 0, len(rows))
	seen := make(map[int64]bool, len(rows))
	for _, e := range rows {
		if err := check(e, rows[0].EntityID, rs); err != nil {
			return Decision{}, err
		}
		if seen[e.ID] {
			return Decision{}, fmt.Errorf("verdict: duplicate evidence id %d", e.ID)
		}
		seen[e.ID] = true
		ids = append(ids, e.ID)
	}
	slices.Sort(ids)

	d := Decision{AsOf: asOf, RulesetVersion: rs.Version, EvidenceIDs: ids, Level: signal.Unknown}

	var human *evidence.Evidence
	auto := signal.Unknown
	var autoCat string
	var autoLatest time.Time
	anyActive, anyAuto := false, false
	for i := range rows {
		e := rows[i]
		if !e.ActiveAt(asOf) {
			continue
		}
		anyActive = true
		if e.IsConfirmation() {
			human = &rows[i] // rows are sorted, so the last one is the latest
			continue
		}
		r := rs.Detectors[e.Detector]
		if r.Source == evidence.Curated {
			continue // curated notes without a confirmed level don't decide anything
		}
		anyAuto = true
		lvl := r.MaxAlone
		if r.Informational {
			lvl = signal.Unknown
		}
		if rank(lvl) >= rank(auto) && rank(lvl) > rank(signal.Unknown) {
			auto, autoCat, autoLatest = lvl, e.Category, e.ObservedAt
		}
	}
	// Defense in depth: automated evidence never exceeds suspicious.
	if rank(auto) > rank(signal.Suspicious) {
		auto = signal.Suspicious
	}

	switch {
	case !anyActive:
		d.RuleID = RuleNoActiveEvidence
	case human != nil && rank(auto) > rank(human.ConfirmedLevel) && autoLatest.After(human.ObservedAt):
		d.RuleID, d.Level, d.Category, d.NeedsReview = RuleHumanSuperseded, auto, autoCat, true
	case human != nil:
		d.RuleID, d.Level, d.Category = RuleHumanConfirmed, human.ConfirmedLevel, human.Category
	case auto != signal.Unknown:
		d.RuleID, d.Level, d.Category = RuleAutomated, auto, autoCat
	case anyAuto:
		d.RuleID = RuleInformationalAll
	default:
		d.RuleID = RuleNoActiveEvidence
	}
	return d, nil
}

func check(e evidence.Evidence, entityID int64, rs Ruleset) error {
	if e.ID <= 0 || e.EntityID <= 0 || e.EntityID != entityID {
		return fmt.Errorf("verdict: evidence %d has a bad or mixed entity", e.ID)
	}
	if e.ObservedAt.IsZero() || (e.ExpiresAt != nil && !e.ExpiresAt.After(e.ObservedAt)) {
		return fmt.Errorf("verdict: evidence %d has bad timestamps", e.ID)
	}
	r, ok := rs.Detectors[e.Detector]
	if !ok {
		return fmt.Errorf("verdict: evidence %d from unknown detector %q", e.ID, e.Detector)
	}
	if e.Class != r.Class || e.SourceKind != r.Source {
		return fmt.Errorf("verdict: evidence %d does not match %s class/source", e.ID, e.Detector)
	}
	if e.IsConfirmation() {
		if _, err := signal.ToPublic(e.ConfirmedLevel); err != nil || e.ConfirmedBy == "" || e.SourceKind != evidence.Curated {
			return fmt.Errorf("verdict: evidence %d is not a valid human confirmation", e.ID)
		}
	}
	return nil
}

func byObserved(a, b evidence.Evidence) int {
	if c := a.ObservedAt.Compare(b.ObservedAt); c != 0 {
		return c
	}
	switch {
	case a.ID < b.ID:
		return -1
	case a.ID > b.ID:
		return 1
	}
	return 0
}

// rank orders levels for comparison only; it is not a score.
func rank(l signal.Internal) int {
	switch l {
	case signal.Benign:
		return 0
	case signal.Unknown:
		return 1
	case signal.Suspicious:
		return 2
	case signal.Malicious:
		return 3
	}
	return -1
}
