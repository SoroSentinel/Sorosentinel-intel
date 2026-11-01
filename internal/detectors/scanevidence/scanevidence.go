// Package scanevidence turns ScanReport JSON (emitted by the sandboxed Scan
// job, conforming to schemas/jsonschema/ScanReport.json) into stored evidence
// and triggers verdict recomputation (PRD I-7, ARCHITECTURE §4.2).
//
// Invariants enforced:
//   - Strict validation: unknown fields and schema violations reject loud.
//   - Deterministic and pure: as_of is injected by caller; no wall clock calls.
//   - Level caps: informational indicators never raise a level alone (stay unknown);
//     non-informational indicators cap at suspicious (automated ceiling).
//   - Evidence before verdict: stores evidence rows before recomputing verdicts.
package scanevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

const (
	Detector = evidence.DetectorContractScan // "D-CONTRACT-SCAN"
	Class    = evidence.ClassScan            // "scan"
	Category = "contract_wasm_scan"

	SourceName = "scan.cli"
)

var (
	sha256HexRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rulesetVersionRe = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]+$`)
	indicatorCodeRe  = regexp.MustCompile(`^S-[A-Z0-9-]+$`)
	notCheckedCodeRe = regexp.MustCompile(`^NC-[A-Z0-9-]+$`)
)

// Indicator mirrors an indicator in ScanReport.json.
type Indicator struct {
	Code          string            `json:"code"`
	Informational bool              `json:"informational"`
	Facts         map[string]string `json:"facts,omitempty"`
}

// ClaimedMeta mirrors claimed_meta in ScanReport.json (untrusted author claims).
type ClaimedMeta struct {
	SpecPresent     bool   `json:"spec_present"`
	SDKVersion      string `json:"sdk_version,omitempty"`
	ProtocolVersion *int   `json:"protocol_version,omitempty"`
}

// ScanReport is the exact structure produced by sorosentinel-scan.
type ScanReport struct {
	WasmSHA256     string      `json:"wasm_sha256"`
	RulesetVersion string      `json:"ruleset_version"`
	Indicators     []Indicator `json:"indicators"`
	NotChecked     []string    `json:"not_checked"`
	ClaimedMeta    ClaimedMeta `json:"claimed_meta"`
}

// ErrInvalidReport is returned when a ScanReport fails validation.
var ErrInvalidReport = errors.New("scanevidence: invalid scan report")

// Parse validates raw JSON against the ScanReport schema constraints without
// allowing unknown fields.
func Parse(data []byte) (*ScanReport, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidReport)
	}
	if len(data) > evidence.MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrInvalidReport, evidence.MaxPayloadBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var r ScanReport
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: JSON decode failed: %v", ErrInvalidReport, err)
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validate checks the structural constraints of the report according to ScanReport.json.
func (r *ScanReport) Validate() error {
	if !sha256HexRe.MatchString(r.WasmSHA256) {
		return fmt.Errorf("%w: invalid wasm_sha256 %q", ErrInvalidReport, r.WasmSHA256)
	}
	if !rulesetVersionRe.MatchString(r.RulesetVersion) {
		return fmt.Errorf("%w: invalid ruleset_version %q", ErrInvalidReport, r.RulesetVersion)
	}
	if len(r.NotChecked) == 0 {
		return fmt.Errorf("%w: not_checked must have at least one entry", ErrInvalidReport)
	}
	for _, nc := range r.NotChecked {
		if !notCheckedCodeRe.MatchString(nc) {
			return fmt.Errorf("%w: invalid not_checked code %q", ErrInvalidReport, nc)
		}
	}
	for i, ind := range r.Indicators {
		if !indicatorCodeRe.MatchString(ind.Code) {
			return fmt.Errorf("%w: indicator[%d] invalid code %q", ErrInvalidReport, i, ind.Code)
		}
		for k, v := range ind.Facts {
			if len(v) > 512 {
				return fmt.Errorf("%w: indicator[%d] fact %q exceeds 512 bytes", ErrInvalidReport, i, k)
			}
		}
	}
	if len(r.ClaimedMeta.SDKVersion) > 64 {
		return fmt.Errorf("%w: sdk_version exceeds 64 characters", ErrInvalidReport)
	}
	if r.ClaimedMeta.ProtocolVersion != nil && *r.ClaimedMeta.ProtocolVersion < 0 {
		return fmt.Errorf("%w: protocol_version cannot be negative", ErrInvalidReport)
	}
	return nil
}

// Transform converts a validated ScanReport into a detectors.Evidence record.
// The network parameter specifies the network scope, and asOf provides the
// observation timestamp.
func Transform(r *ScanReport, network entity.Network, asOf time.Time) (*detectors.Evidence, error) {
	if asOf.IsZero() {
		return nil, errors.New("scanevidence: as_of timestamp is required")
	}
	if network != entity.Public && network != entity.Testnet {
		return nil, fmt.Errorf("scanevidence: invalid network %q", network)
	}

	entityKey, err := entity.Canonical(network, entity.WasmHash, r.WasmSHA256)
	if err != nil {
		return nil, fmt.Errorf("scanevidence: canonical key failed: %w", err)
	}

	// Automated level ceiling:
	// Informational indicators never raise a level alone (stay at unknown).
	// If any non-informational indicator exists, level becomes suspicious.
	maxLevel := signal.Unknown
	var codes []string
	for _, ind := range r.Indicators {
		codes = append(codes, ind.Code)
		if !ind.Informational {
			maxLevel = signal.Suspicious
		}
	}
	sort.Strings(codes)

	facts := []detectors.Fact{
		{Name: "wasm_sha256", Value: r.WasmSHA256},
		{Name: "ruleset_version", Value: r.RulesetVersion},
		{Name: "indicator_count", Value: strconv.Itoa(len(r.Indicators))},
		{Name: "indicators", Value: strings.Join(codes, ",")},
		{Name: "not_checked", Value: strings.Join(r.NotChecked, ",")},
		{Name: "spec_present", Value: strconv.FormatBool(r.ClaimedMeta.SpecPresent)},
	}

	if r.ClaimedMeta.SDKVersion != "" {
		facts = append(facts, detectors.Fact{Name: "claimed_sdk_version", Value: r.ClaimedMeta.SDKVersion})
	}
	if r.ClaimedMeta.ProtocolVersion != nil {
		facts = append(facts, detectors.Fact{
			Name:  "claimed_protocol_version",
			Value: strconv.Itoa(*r.ClaimedMeta.ProtocolVersion),
		})
	}

	ev := &detectors.Evidence{
		Detector:   Detector,
		Class:      string(Class),
		Category:   Category,
		Entity:     entityKey,
		MaxLevel:   maxLevel,
		Facts:      facts,
		ObservedAt: asOf,
	}

	if err := ev.Validate(); err != nil {
		return nil, fmt.Errorf("scanevidence: generated evidence failed validation: %w", err)
	}
	return ev, nil
}

// ToEvidenceNew packages a validated ScanReport into an evidence.New record for storage.
func ToEvidenceNew(r *ScanReport, rawPayload json.RawMessage, entityID int64, sourceID int16, asOf time.Time, ledgerSeq int64) (evidence.New, error) {
	if len(rawPayload) == 0 {
		var err error
		rawPayload, err = json.Marshal(r)
		if err != nil {
			return evidence.New{}, fmt.Errorf("scanevidence: marshal payload failed: %w", err)
		}
	}

	ev := evidence.New{
		EntityID:   entityID,
		SourceID:   sourceID,
		Detector:   Detector,
		Class:      Class,
		Category:   Category,
		Payload:    rawPayload,
		ObservedAt: asOf,
		LedgerSeq:  ledgerSeq,
	}
	if err := ev.Validate(); err != nil {
		return evidence.New{}, fmt.Errorf("scanevidence: invalid evidence.New: %w", err)
	}
	return ev, nil
}

// Store defines the minimum persistence operations needed to record scan evidence.
type Store interface {
	EnsureSource(ctx context.Context, name string, kind evidence.SourceKind) (int16, error)
	UpsertEntity(ctx context.Context, network entity.Network, typ entity.Type, key string, attrs json.RawMessage) (int64, error)
	AppendEvidence(ctx context.Context, n evidence.New) (int64, error)
	Recompute(ctx context.Context, entityID int64, asOf time.Time, rs verdict.Ruleset) (verdict.Verdict, bool, error)
}

// IngestResult summarizes the stored evidence and resulting verdict.
type IngestResult struct {
	WasmEntityID   int64
	EvidenceID     int64
	Verdict        verdict.Verdict
	VerdictChanged bool
}

// Ingest parses, validates, and stores a ScanReport, recomputing the WASM hash's verdict.
func Ingest(
	ctx context.Context,
	s Store,
	rawReport []byte,
	network entity.Network,
	asOf time.Time,
	ledgerSeq int64,
	rs verdict.Ruleset,
) (*IngestResult, error) {
	report, err := Parse(rawReport)
	if err != nil {
		return nil, err
	}

	sourceID, err := s.EnsureSource(ctx, SourceName, evidence.Scan)
	if err != nil {
		return nil, fmt.Errorf("scanevidence: ensure source failed: %w", err)
	}

	attrs, _ := json.Marshal(map[string]any{
		"ruleset_version": report.RulesetVersion,
		"claimed_meta":    report.ClaimedMeta,
	})

	wasmEntityID, err := s.UpsertEntity(ctx, network, entity.WasmHash, report.WasmSHA256, attrs)
	if err != nil {
		return nil, fmt.Errorf("scanevidence: upsert entity failed: %w", err)
	}

	evNew, err := ToEvidenceNew(report, rawReport, wasmEntityID, sourceID, asOf, ledgerSeq)
	if err != nil {
		return nil, err
	}

	evID, err := s.AppendEvidence(ctx, evNew)
	if err != nil {
		return nil, fmt.Errorf("scanevidence: append evidence failed: %w", err)
	}

	v, changed, err := s.Recompute(ctx, wasmEntityID, asOf, rs)
	if err != nil {
		return nil, fmt.Errorf("scanevidence: recompute verdict failed: %w", err)
	}

	return &IngestResult{
		WasmEntityID:   wasmEntityID,
		EvidenceID:     evID,
		Verdict:        v,
		VerdictChanged: changed,
	}, nil
}
