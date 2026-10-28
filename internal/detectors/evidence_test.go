package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

func valid() Evidence {
	return Evidence{
		Detector: "D-X", Class: ClassDomain, Category: "c", Entity: "testnet|domain|a.example",
		MaxLevel: MaxAutomatedLevel, Facts: []Fact{{Name: "n", Value: "v"}},
		ObservedAt: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC),
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Evidence){
		"malicious cap":  func(e *Evidence) { e.MaxLevel = signal.Malicious },
		"benign":         func(e *Evidence) { e.MaxLevel = signal.Benign },
		"empty level":    func(e *Evidence) { e.MaxLevel = "" },
		"no detector":    func(e *Evidence) { e.Detector = "" },
		"no observed_at": func(e *Evidence) { e.ObservedAt = time.Time{} },
		"no facts":       func(e *Evidence) { e.Facts = nil },
		"bad artifact":   func(e *Evidence) { e.Artifacts = []ArtifactRef{{Kind: "k", SHA256: "abc"}} },
	} {
		e := valid()
		mut(&e)
		if e.Validate() == nil {
			t.Errorf("%s: want error", name)
		}
	}
	e := valid()
	e.Artifacts = []ArtifactRef{{Kind: "k", SHA256: strings.Repeat("a", 64), FetchedAt: e.ObservedAt}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}
