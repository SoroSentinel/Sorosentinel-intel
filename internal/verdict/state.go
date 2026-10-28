package verdict

import (
	"errors"
	"slices"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

// Status is the v1 verdict status (ARCHITECTURE_ESSENTIALS §12 HQ3).
type Status string

const (
	Active  Status = "active"
	Revoked Status = "revoked"
)

// Actor recorded for engine decisions; analysts use their own id.
const EngineActor = "engine"

// Verdict is the one current verdict per entity.
type Verdict struct {
	ID             int64 // 0 until stored
	EntityID       int64
	Level          signal.Internal
	Status         Status
	Disputed       bool
	Category       string
	RuleID         string
	DecidedBy      string
	RulesetVersion string
	AsOf           time.Time
	EvidenceIDs    []int64
}

// Event is one append-only verdict_events row. From is nil on creation.
type Event struct {
	EntityID int64
	From     *Verdict
	To       Verdict
	Actor    string
	Reason   string // internal; never serialized publicly
}

// Apply turns a decision into the next verdict. The disputed flag and a
// revoked status carry over: a recompute never clears a dispute or reinstates
// a revoked verdict; only an analyst does (SetDisputed, SetStatus).
// changed is false when nothing but as_of would differ, so no event is written
// and the stored as_of keeps replaying to the stored result.
func Apply(prev *Verdict, entityID int64, d Decision, actor string) (next Verdict, ev Event, changed bool, err error) {
	if entityID <= 0 || actor == "" || d.RuleID == "" || d.AsOf.IsZero() {
		return Verdict{}, Event{}, false, errors.New("verdict: incomplete decision")
	}
	if prev != nil && prev.EntityID != entityID {
		return Verdict{}, Event{}, false, errors.New("verdict: entity mismatch")
	}
	next = Verdict{
		EntityID:       entityID,
		Level:          d.Level,
		Status:         Active,
		Category:       d.Category,
		RuleID:         d.RuleID,
		DecidedBy:      actor,
		RulesetVersion: d.RulesetVersion,
		AsOf:           d.AsOf,
		EvidenceIDs:    slices.Clone(d.EvidenceIDs),
	}
	if prev != nil {
		next.ID = prev.ID
		next.Status = prev.Status
		next.Disputed = prev.Disputed
		if sameDecision(*prev, next) {
			return *prev, Event{}, false, nil
		}
	}
	reason := ""
	if d.NeedsReview {
		reason = "needs_review"
	}
	return next, Event{EntityID: entityID, From: prev, To: next, Actor: actor, Reason: reason}, true, nil
}

// SetDisputed records that a verdict is (or no longer is) under dispute. The
// level is unchanged; resolving a dispute is a separate analyst decision.
func SetDisputed(prev Verdict, disputed bool, actor, reason string) (Verdict, Event, error) {
	if actor == "" || actor == EngineActor {
		return Verdict{}, Event{}, errors.New("verdict: disputes are set by an analyst")
	}
	next := prev
	next.EvidenceIDs = slices.Clone(prev.EvidenceIDs)
	next.Disputed = disputed
	return next, Event{EntityID: prev.EntityID, From: &prev, To: next, Actor: actor, Reason: reason}, nil
}

// SetStatus revokes or reinstates a verdict. Revoked verdicts leave the snapshot.
func SetStatus(prev Verdict, status Status, actor, reason string) (Verdict, Event, error) {
	if actor == "" || actor == EngineActor {
		return Verdict{}, Event{}, errors.New("verdict: status is set by an analyst")
	}
	if status != Active && status != Revoked {
		return Verdict{}, Event{}, errors.New("verdict: unknown status")
	}
	next := prev
	next.EvidenceIDs = slices.Clone(prev.EvidenceIDs)
	next.Status = status
	return next, Event{EntityID: prev.EntityID, From: &prev, To: next, Actor: actor, Reason: reason}, nil
}

func sameDecision(a, b Verdict) bool {
	return a.Level == b.Level && a.Status == b.Status && a.Disputed == b.Disputed &&
		a.Category == b.Category && a.RuleID == b.RuleID && a.RulesetVersion == b.RulesetVersion &&
		slices.Equal(a.EvidenceIDs, b.EvidenceIDs)
}
