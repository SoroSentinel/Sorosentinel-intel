// Package evidence defines the write-once evidence records detectors emit and
// the verdict engine reads (ARCHITECTURE §7.1, table `evidence`). Evidence is
// public data only; reporter PII never goes here.
package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

// SourceKind mirrors the source_kind enum.
type SourceKind string

const (
	Heuristic SourceKind = "heuristic"
	Scan      SourceKind = "scan"
	Community SourceKind = "community"
	Curated   SourceKind = "curated"
)

func (k SourceKind) Valid() bool {
	switch k {
	case Heuristic, Scan, Community, Curated:
		return true
	}
	return false
}

// Class groups evidence for independence: two rows of the same class are not
// independent confirmations of each other.
type Class string

const (
	ClassOnchainPattern Class = "onchain-pattern"
	ClassDomain         Class = "domain"
	ClassScan           Class = "scan"
	ClassCommunity      Class = "community"
	ClassHuman          Class = "human"
)

// Detector IDs (ARCHITECTURE §4.2).
const (
	DetectorAssetLookalike  = "D-ASSET-LOOKALIKE"
	DetectorHomeDomain      = "D-HOMEDOMAIN-MISMATCH"
	DetectorFlagsRisk       = "D-FLAGS-RISK"
	DetectorTrustlineSpam   = "D-TRUSTLINE-SPAM"
	DetectorAccountTakeover = "D-ACCOUNT-TAKEOVER-PATTERN"
	DetectorContractScan    = "D-CONTRACT-SCAN"
	DetectorCommunityReport = "D-COMMUNITY-REPORT"
	DetectorCurated         = "D-CURATED"
)

const (
	// MaxPayloadBytes caps one row's JSON payload.
	MaxPayloadBytes = 64 << 10
	// MaxPerVerdict bounds how many evidence rows one decision may consider.
	MaxPerVerdict = 10_000

	maxArtifactRefs   = 32
	maxArtifactRefLen = 512
	maxConfirmedByLen = 128
)

var (
	detectorRe = regexp.MustCompile(`^D-[A-Z0-9-]{1,48}$`)
	classRe    = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)
	categoryRe = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)
)

// New is an evidence row to append. ObservedAt and ExpiresAt are passed in by
// the caller; nothing here reads the clock.
type New struct {
	EntityID     int64
	SourceID     int16
	Detector     string
	Class        Class
	Category     string
	Payload      json.RawMessage // a JSON object
	ObservedAt   time.Time
	LedgerSeq    int64      // 0 = not ledger-derived
	ExpiresAt    *time.Time // nil = does not expire
	ArtifactRefs []string   // object-store keys of write-once raw artifacts

	// Human confirmation (D-CURATED only): the analyst-decided level and who decided.
	ConfirmedLevel signal.Internal
	ConfirmedBy    string
}

// Evidence is a stored row as the verdict engine sees it.
// JSON tags are for replay fixtures and internal tooling only; evidence is
// never serialized publicly as-is.
type Evidence struct {
	ID             int64           `json:"id"`
	EntityID       int64           `json:"entity_id"`
	SourceKind     SourceKind      `json:"source_kind"`
	Detector       string          `json:"detector"`
	Class          Class           `json:"evidence_class"`
	Category       string          `json:"category"`
	ObservedAt     time.Time       `json:"observed_at"`
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
	ConfirmedLevel signal.Internal `json:"confirmed_level,omitempty"` // empty unless a human confirmation
	ConfirmedBy    string          `json:"confirmed_by,omitempty"`
}

// IsConfirmation reports whether e is a human confirmation record.
func (e Evidence) IsConfirmation() bool { return e.ConfirmedLevel != "" }

// ActiveAt reports whether e counts at asOf: observed no later than asOf and
// not yet expired. Evidence expiring exactly at asOf no longer counts.
func (e Evidence) ActiveAt(asOf time.Time) bool {
	if e.ObservedAt.After(asOf) {
		return false
	}
	return e.ExpiresAt == nil || e.ExpiresAt.After(asOf)
}

// Validate checks a row before it is appended. The database repeats most of
// these checks; this gives callers a clear error first.
func (n New) Validate() error {
	if n.EntityID <= 0 || n.SourceID <= 0 {
		return errors.New("evidence: entity and source are required")
	}
	if !detectorRe.MatchString(n.Detector) {
		return fmt.Errorf("evidence: invalid detector %q", n.Detector)
	}
	if !classRe.MatchString(string(n.Class)) {
		return fmt.Errorf("evidence: invalid class %q", n.Class)
	}
	if !categoryRe.MatchString(n.Category) {
		return fmt.Errorf("evidence: invalid category %q", n.Category)
	}
	if len(n.Payload) == 0 || len(n.Payload) > MaxPayloadBytes {
		return errors.New("evidence: payload missing or too large")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(n.Payload, &obj); err != nil || obj == nil {
		return errors.New("evidence: payload must be a JSON object")
	}
	if n.ObservedAt.IsZero() {
		return errors.New("evidence: observed_at is required")
	}
	if n.LedgerSeq < 0 {
		return errors.New("evidence: invalid ledger_seq")
	}
	if n.ExpiresAt != nil && !n.ExpiresAt.After(n.ObservedAt) {
		return errors.New("evidence: expires_at must be after observed_at")
	}
	if len(n.ArtifactRefs) > maxArtifactRefs {
		return errors.New("evidence: too many artifact refs")
	}
	for _, r := range n.ArtifactRefs {
		if r == "" || len(r) > maxArtifactRefLen {
			return errors.New("evidence: invalid artifact ref")
		}
	}
	if (n.ConfirmedLevel == "") != (n.ConfirmedBy == "") {
		return errors.New("evidence: confirmed_level and confirmed_by go together")
	}
	if n.ConfirmedLevel != "" {
		if n.Detector != DetectorCurated {
			return errors.New("evidence: only D-CURATED rows carry a confirmation")
		}
		if _, err := signal.ToPublic(n.ConfirmedLevel); err != nil {
			return fmt.Errorf("evidence: %w", err)
		}
		if len(n.ConfirmedBy) > maxConfirmedByLen {
			return errors.New("evidence: confirmed_by too long")
		}
	}
	return nil
}
