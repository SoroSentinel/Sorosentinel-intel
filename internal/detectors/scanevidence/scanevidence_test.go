package scanevidence_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/scanevidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/evidence"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

const sampleValidJSON = `{
  "wasm_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "ruleset_version": "2026.10.1",
  "indicators": [
    {
      "code": "S-UPGRADEABLE",
      "informational": true
    },
    {
      "code": "S-SEP41-DEVIATION",
      "informational": true,
      "facts": {
        "missing": "transfer"
      }
    }
  ],
  "not_checked": [
    "NC-AUTH-CHECKS",
    "NC-RUNTIME-BEHAVIOR"
  ],
  "claimed_meta": {
    "spec_present": true,
    "sdk_version": "21.0.0",
    "protocol_version": 21
  }
}`

func TestParse_Valid(t *testing.T) {
	rep, err := scanevidence.Parse([]byte(sampleValidJSON))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if rep.WasmSHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("wrong sha: %s", rep.WasmSHA256)
	}
	if len(rep.Indicators) != 2 {
		t.Errorf("expected 2 indicators, got %d", len(rep.Indicators))
	}
}

func TestParse_RejectsUnknownFields(t *testing.T) {
	badJSON := `{
		"wasm_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"ruleset_version": "2026.10.1",
		"indicators": [],
		"not_checked": ["NC-AUTH"],
		"claimed_meta": {"spec_present": true},
		"unrecognized_field": 123
	}`
	if _, err := scanevidence.Parse([]byte(badJSON)); err == nil {
		t.Fatal("expected error for unknown fields")
	}
}

func TestParse_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"empty", ""},
		{"invalid sha256", strings.Replace(sampleValidJSON, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "bad-hash", 1)},
		{"invalid ruleset", strings.Replace(sampleValidJSON, "2026.10.1", "bad-version", 1)},
		{"empty not_checked", strings.Replace(sampleValidJSON, `"NC-AUTH-CHECKS",
    "NC-RUNTIME-BEHAVIOR"`, "", 1)},
		{"invalid indicator code syntax", strings.Replace(sampleValidJSON, "S-UPGRADEABLE", "lowercase-code", 1)},
		{"unknown indicator code", strings.Replace(sampleValidJSON, "S-UPGRADEABLE", "S-UNKNOWN-FEATURE", 1)},
		{"informational flag mismatch", strings.Replace(sampleValidJSON, `"code": "S-UPGRADEABLE",
      "informational": true`, `"code": "S-UPGRADEABLE",
      "informational": false`, 1)},
		{"trailing data after json", sampleValidJSON + " trailing-garbage"},
		{"trailing json after json", sampleValidJSON + " {}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := scanevidence.Parse([]byte(tt.json)); err == nil {
				t.Errorf("case %q: expected validation error", tt.name)
			}
		})
	}
}

func TestTransform_InformationalCeiling(t *testing.T) {
	rep, err := scanevidence.Parse([]byte(sampleValidJSON))
	if err != nil {
		t.Fatal(err)
	}

	asOf := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	ev, err := scanevidence.Transform(rep, entity.Testnet, asOf)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	// All indicators are informational, so level stays Unknown
	if ev.MaxLevel != signal.Unknown {
		t.Errorf("expected level %s, got %s", signal.Unknown, ev.MaxLevel)
	}
	if ev.Entity != "testnet|wasm_hash|0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("wrong entity: %s", ev.Entity)
	}
}

func TestTransform_NonInformationalRaisesToSuspicious(t *testing.T) {
	withBadHash := strings.Replace(
		sampleValidJSON,
		`"code": "S-UPGRADEABLE",
      "informational": true`,
		`"code": "S-KNOWN-BAD-HASH",
      "informational": false`,
		1,
	)

	rep, err := scanevidence.Parse([]byte(withBadHash))
	if err != nil {
		t.Fatal(err)
	}

	asOf := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	ev, err := scanevidence.Transform(rep, entity.Public, asOf)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	// Automated indicator can support up to suspicious
	if ev.MaxLevel != signal.Suspicious {
		t.Errorf("expected level %s, got %s", signal.Suspicious, ev.MaxLevel)
	}
}

type fakeStore struct {
	sources   map[string]int16
	entities  map[string]int64
	evidences []evidence.New
	nextID    int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		sources:  make(map[string]int16),
		entities: make(map[string]int64),
	}
}

func (f *fakeStore) EnsureSource(_ context.Context, name string, _ evidence.SourceKind) (int16, error) {
	if id, ok := f.sources[name]; ok {
		return id, nil
	}
	id := int16(len(f.sources) + 1)
	f.sources[name] = id
	return id, nil
}

func (f *fakeStore) UpsertEntity(_ context.Context, network entity.Network, typ entity.Type, key string, _ json.RawMessage) (int64, error) {
	k := string(network) + ":" + string(typ) + ":" + key
	if id, ok := f.entities[k]; ok {
		return id, nil
	}
	f.nextID++
	f.entities[k] = f.nextID
	return f.nextID, nil
}

func (f *fakeStore) AppendEvidence(_ context.Context, n evidence.New) (int64, error) {
	f.nextID++
	f.evidences = append(f.evidences, n)
	return f.nextID, nil
}

func (f *fakeStore) Recompute(_ context.Context, entityID int64, asOf time.Time, _ verdict.Ruleset) (verdict.Verdict, bool, error) {
	return verdict.Verdict{
		EntityID: entityID,
		Level:    signal.Unknown,
		RuleID:   verdict.RuleInformationalAll,
		AsOf:     asOf,
	}, true, nil
}

func TestVerifyWasm(t *testing.T) {
	rep, err := scanevidence.Parse([]byte(sampleValidJSON))
	if err != nil {
		t.Fatal(err)
	}

	// Verify with expected SHA256 hex string
	if err := rep.VerifyWasmSHA256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err != nil {
		t.Errorf("expected matching sha to succeed: %v", err)
	}
	if err := rep.VerifyWasmSHA256("1111111111111111111111111111111111111111111111111111111111111111"); err == nil {
		t.Error("expected mismatching sha to fail")
	}

	// Verify with raw bytes
	testBytes := []byte("contract bytecode")
	rep.WasmSHA256 = "5ba85d87d5091881c8ec3c0d77576a4038a43fc2174bb23b2bdbbb3c1055b34f"
	if err := rep.VerifyWasmBytes(testBytes); err != nil {
		t.Errorf("expected matching bytes sha to succeed: %v", err)
	}
	if err := rep.VerifyWasmBytes([]byte("different bytecode")); err == nil {
		t.Error("expected mismatching bytes to fail")
	}
}

func TestIngest_EndToEnd(t *testing.T) {
	fs := newFakeStore()
	asOf := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	const expectedWasm = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Mismatched expected wasm fails
	_, err := scanevidence.Ingest(
		context.Background(),
		fs,
		[]byte(sampleValidJSON),
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		entity.Public,
		asOf,
		12345,
		verdict.V1,
	)
	if err == nil {
		t.Fatal("expected error on mismatched wasm_sha256")
	}

	res, err := scanevidence.Ingest(
		context.Background(),
		fs,
		[]byte(sampleValidJSON),
		expectedWasm,
		entity.Public,
		asOf,
		12345,
		verdict.V1,
	)
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	if res.WasmEntityID <= 0 {
		t.Errorf("invalid entity id: %d", res.WasmEntityID)
	}
	if res.EvidenceID <= 0 {
		t.Errorf("invalid evidence id: %d", res.EvidenceID)
	}
	if len(fs.evidences) != 1 {
		t.Fatalf("expected 1 evidence appended, got %d", len(fs.evidences))
	}

	ev := fs.evidences[0]
	if ev.Detector != evidence.DetectorContractScan {
		t.Errorf("wrong detector: %s", ev.Detector)
	}
	if ev.Class != evidence.ClassScan {
		t.Errorf("wrong class: %s", ev.Class)
	}
	if ev.LedgerSeq != 12345 {
		t.Errorf("wrong ledger seq: %d", ev.LedgerSeq)
	}
}
