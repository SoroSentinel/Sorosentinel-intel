// Package detectors holds the evidence type that every Intel detector emits.
// Detectors are pure: they take `as_of` and all fetched bytes as input and never
// read the clock or the network. They only emit evidence; the verdict engine
// decides levels, and no automated detector may support more than `suspicious`
// (AGENTS.md §3.3). Evidence is mapped to the storage types elsewhere.
package detectors

import (
	"fmt"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

// Evidence classes group independence (ARCHITECTURE §7.1).
const (
	ClassOnchainPattern = "onchain-pattern"
	ClassDomain         = "domain"
)

// MaxAutomatedLevel is the highest level automated evidence can support.
const MaxAutomatedLevel = signal.Suspicious

// Fact is one structured, verifiable observation. Values are plain strings
// taken from validated input; they are internal and reach users only through
// typed template slots.
type Fact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ArtifactRef points at a raw artifact that must be stored write-once so the
// facts can be proven later (PRD §5.1 L9).
type ArtifactRef struct {
	Kind      string    `json:"kind"`
	URL       string    `json:"url,omitempty"`
	SHA256    string    `json:"sha256"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Evidence is what a detector emits for one entity.
type Evidence struct {
	Detector   string          `json:"detector"`
	Class      string          `json:"evidence_class"`
	Category   string          `json:"category"`
	Entity     string          `json:"entity"` // canonical key (schemas/canonical-key.md)
	MaxLevel   signal.Internal `json:"max_level"`
	Facts      []Fact          `json:"facts"`
	ObservedAt time.Time       `json:"observed_at"`
	Artifacts  []ArtifactRef   `json:"artifacts,omitempty"`
}

// Validate rejects evidence that is incomplete or claims more than an
// automated source may.
func (e Evidence) Validate() error {
	switch {
	case e.Detector == "", e.Class == "", e.Category == "", e.Entity == "":
		return fmt.Errorf("detectors: evidence is missing detector, class, category or entity")
	case e.ObservedAt.IsZero():
		return fmt.Errorf("detectors: evidence has no observed_at")
	case e.MaxLevel != signal.Unknown && e.MaxLevel != signal.Suspicious:
		return fmt.Errorf("detectors: automated evidence cannot support level %q", e.MaxLevel)
	case len(e.Facts) == 0:
		return fmt.Errorf("detectors: evidence has no facts")
	}
	for _, a := range e.Artifacts {
		if a.Kind == "" || len(a.SHA256) != 64 || a.FetchedAt.IsZero() {
			return fmt.Errorf("detectors: artifact ref needs kind, sha256 and fetched_at")
		}
	}
	return nil
}

// Fact returns the value of the named fact.
func (e Evidence) Fact(name string) (string, bool) {
	for _, f := range e.Facts {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}
