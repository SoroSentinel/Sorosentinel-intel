package verdict

import (
	"testing"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

func TestApplyCreatesActiveVerdict(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{lookalike(1, at(0), nil)}, at(1))
	v, ev, changed, err := Apply(nil, 1, d, EngineActor)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if v.Status != Active || v.Disputed || v.Level != signal.Suspicious || ev.From != nil || ev.To.Level != signal.Suspicious {
		t.Fatalf("got %+v / %+v", v, ev)
	}
}

func TestApplyUnchangedWritesNothing(t *testing.T) {
	ev := []evidence.Evidence{lookalike(1, at(0), nil)}
	v, _, _, _ := Apply(nil, 1, mustDecide(t, ev, at(1)), EngineActor)
	next, _, changed, err := Apply(&v, 1, mustDecide(t, ev, at(5)), EngineActor)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !next.AsOf.Equal(at(1)) {
		t.Fatal("unchanged recompute must keep the stored as_of so it still replays")
	}
}

func TestDisputedFlagSurvivesRecompute(t *testing.T) {
	ev := []evidence.Evidence{lookalike(1, at(0), nil)}
	v, _, _, _ := Apply(nil, 1, mustDecide(t, ev, at(1)), EngineActor)
	if _, _, err := SetDisputed(v, true, EngineActor, ""); err == nil {
		t.Fatal("engine set a dispute")
	}
	v, e, err := SetDisputed(v, true, "analyst-1", "ticket 42")
	if err != nil || !v.Disputed || e.From.Disputed || !e.To.Disputed {
		t.Fatalf("SetDisputed: %+v %+v %v", v, e, err)
	}
	if v.Level != signal.Suspicious {
		t.Fatal("dispute changed the level")
	}
	// New evidence changes the decision; the dispute flag stays.
	ev = append(ev, homeDomain(2, at(2)))
	next, _, changed, err := Apply(&v, 1, mustDecide(t, ev, at(3)), EngineActor)
	if err != nil || !changed || !next.Disputed {
		t.Fatalf("disputed lost on recompute: %+v changed=%v err=%v", next, changed, err)
	}
}

func TestRevokedSticksUntilAnalystReinstates(t *testing.T) {
	ev := []evidence.Evidence{lookalike(1, at(0), nil)}
	v, _, _, _ := Apply(nil, 1, mustDecide(t, ev, at(1)), EngineActor)
	v, _, err := SetStatus(v, Revoked, "analyst-1", "overturned")
	if err != nil || v.Status != Revoked {
		t.Fatal(err)
	}
	ev = append(ev, homeDomain(2, at(2)))
	next, _, _, _ := Apply(&v, 1, mustDecide(t, ev, at(3)), EngineActor)
	if next.Status != Revoked {
		t.Fatal("recompute reinstated a revoked verdict")
	}
	if _, _, err := SetStatus(next, "expired", "analyst-1", ""); err == nil {
		t.Fatal("unknown status accepted")
	}
	next, _, _ = SetStatus(next, Active, "analyst-1", "reinstated")
	if next.Status != Active {
		t.Fatal("reinstate failed")
	}
}

func TestNeedsReviewRecordedOnEvent(t *testing.T) {
	d := mustDecide(t, []evidence.Evidence{confirm(1, at(0), signal.Benign), lookalike(2, at(1), nil)}, at(2))
	_, e, _, _ := Apply(nil, 1, d, EngineActor)
	if e.Reason != "needs_review" {
		t.Fatalf("reason %q", e.Reason)
	}
}
