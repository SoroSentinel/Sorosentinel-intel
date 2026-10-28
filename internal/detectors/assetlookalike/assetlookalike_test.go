package assetlookalike

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

// Synthetic placeholder accounts (shape-valid, not real issuers).
func acct(name string) string { return ("G" + name + strings.Repeat("A", 56))[:56] }

var asOf = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func mustRef(t *testing.T, set map[string][]string) *Reference {
	t.Helper()
	r, err := NewReference(set)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDetect(t *testing.T) {
	usdc, eur1, eur2, other := acct("USDCREF"), acct("EURONE"), acct("EURTWO"), acct("OTHER")
	ref := mustRef(t, map[string][]string{"USDC": {usdc}, "EURC": {eur2, eur1, eur1}})
	tests := []struct {
		name  string
		asset string
		want  []string // "reference_code/match"
	}{
		{"known asset", "USDC:" + usdc, nil},
		{"multi-issuer code, first issuer", "EURC:" + eur1, nil},
		{"multi-issuer code, second issuer", "EURC:" + eur2, nil},
		{"exact code, other issuer", "USDC:" + other, []string{"USDC/exact"}},
		{"case folding", "Usdc:" + other, []string{"USDC/confusable"}},
		{"affix", "USDCx:" + other, []string{"USDC/affix"}},
		{"related code from known issuer", "EURCx:" + eur1, nil},
		{"unrelated", "GOAT:" + other, nil},
		{"native", "native", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := ref.Detect(entity.Testnet, tc.asset, asOf)
			if err != nil {
				t.Fatal(err)
			}
			if got := summarize(ev); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectEvidenceShape(t *testing.T) {
	usdc, other := acct("USDCREF"), acct("OTHER")
	ref := mustRef(t, map[string][]string{"USDC": {usdc}})
	ev, err := ref.Detect(entity.Testnet, "U5DC:"+other, asOf.In(time.FixedZone("x", 3600)))
	if err != nil || len(ev) != 1 {
		t.Fatalf("got %v, %v", ev, err)
	}
	e := ev[0]
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if e.Detector != Code || e.Class != detectors.ClassOnchainPattern || e.MaxLevel != detectors.MaxAutomatedLevel {
		t.Fatalf("bad header: %+v", e)
	}
	if e.Entity != "testnet|asset|U5DC:"+other || !e.ObservedAt.Equal(asOf) || e.ObservedAt.Location() != time.UTC {
		t.Fatalf("bad entity/observed_at: %q %v", e.Entity, e.ObservedAt)
	}
	for name, want := range map[string]string{
		"reference_code": "USDC", "match": MatchConfusable, "known_assets": "USDC:" + usdc, "known_issuer_count": "1",
	} {
		if got, _ := e.Fact(name); got != want {
			t.Errorf("fact %s = %q, want %q", name, got, want)
		}
	}
}

func TestDetectNativeOnlyCode(t *testing.T) {
	ref := mustRef(t, map[string][]string{"XLM": nil})
	ev, err := ref.Detect(entity.Public, "XLM:"+acct("OTHER"), asOf)
	if err != nil || len(ev) != 1 {
		t.Fatalf("got %v, %v", ev, err)
	}
	if _, ok := ev[0].Fact("known_assets"); ok {
		t.Fatal("known_assets must be absent for an empty issuer set")
	}
}

func TestDetectMultipleReferencesOrdered(t *testing.T) {
	ref := mustRef(t, map[string][]string{"USDT": {acct("T")}, "USD": {acct("D")}, "USDC": {acct("C")}})
	ev, err := ref.Detect(entity.Public, "USDT:"+acct("OTHER"), asOf)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"USD/affix", "USDT/exact"}
	if got := summarize(ev); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDetectRejectsHostileInput(t *testing.T) {
	ref := mustRef(t, map[string][]string{"USDC": {acct("USDCREF")}})
	other := acct("OTHER")
	for name, asset := range map[string]string{
		"issuer lowercase": "USDC:" + strings.ToLower(acct("USDCREF")),
		"cyrillic code":    "UЅDC:" + other,
		"bidi override":    "US‮DC:" + other,
		"zero width":       "USD​C:" + other,
		"NUL in code":      "USD\x00C:" + other,
		"code too long":    "ABCDEFGHIJKLM:" + other,
		"empty code":       ":" + other,
		"muxed issuer":     "USDC:M" + other[1:],
		"no issuer":        "USDC",
		"huge":             strings.Repeat("A", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			ev, err := ref.Detect(entity.Public, asset, asOf)
			if !errors.Is(err, ErrInvalidInput) || ev != nil {
				t.Fatalf("got %v, %v; want ErrInvalidInput", ev, err)
			}
		})
	}
	if _, err := ref.Detect("mainnet", "USDC:"+other, asOf); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown network: %v", err)
	}
	if _, err := ref.Detect(entity.Public, "USDC:"+other, time.Time{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero as_of: %v", err)
	}
}

func TestNewReferenceRejectsBadInput(t *testing.T) {
	for name, set := range map[string]map[string][]string{
		"empty":           {},
		"bad code":        {"US DC": {acct("A")}},
		"bad native code": {"X-LM": nil},
		"bad issuer":      {"USDC": {"GABC"}},
		"lowercase iss":   {"USDC": {strings.ToLower(acct("A"))}},
	} {
		if _, err := NewReference(set); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestDeterministic(t *testing.T) {
	set := map[string][]string{"USDC": {acct("C")}, "USD": {acct("D")}, "USDT": {acct("T")}, "EURC": {acct("E")}}
	first, _ := mustRef(t, set).Detect(entity.Public, "U5DT:"+acct("OTHER"), asOf)
	for i := 0; i < 20; i++ {
		got, _ := mustRef(t, set).Detect(entity.Public, "U5DT:"+acct("OTHER"), asOf)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestSkeleton(t *testing.T) {
	for in, want := range map[string][2]string{
		"usdc": {"USDC", "USDC"}, "U5DC": {"USDC", "USDC"}, "C0IN": {"COIN", "COIN"},
		"CO1N": {"COIN", "COIN"}, "COlN": {"COIN", "COLN"}, "COLN": {"COLN", "COLN"},
		"2AR": {"ZAR", "ZAR"}, "8TC": {"BTC", "BTC"}, "xlm": {"XIM", "XLM"},
	} {
		if got := skeletons(in); got != want {
			t.Errorf("skeletons(%q) = %q, want %q", in, got, want)
		}
	}
}

// Golden-corpus-style test over synthetic labeled fixtures. Every labeled
// look-alike must be flagged with the expected match, and every clean case
// (including legitimate multi-issuer codes) must produce no evidence.
func TestCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/detectors/assetlookalike/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		AsOf      time.Time           `json:"as_of"`
		Network   entity.Network      `json:"network"`
		Reference map[string][]string `json:"reference"`
		Cases     []struct {
			Name   string `json:"name"`
			Asset  string `json:"asset"`
			Label  string `json:"label"`
			Expect []struct {
				ReferenceCode string `json:"reference_code"`
				Match         string `json:"match"`
			} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	ref := mustRef(t, c.Reference)
	var tp, fp, fn int
	for _, tc := range c.Cases {
		ev, err := ref.Detect(c.Network, tc.Asset, c.AsOf)
		switch tc.Label {
		case "invalid":
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%s: want ErrInvalidInput, got %v", tc.Name, err)
			}
			continue
		case "clean":
			if err != nil {
				t.Errorf("%s: %v", tc.Name, err)
			}
			if len(ev) > 0 {
				fp++
				t.Errorf("%s: false positive %v", tc.Name, summarize(ev))
			}
		case "lookalike":
			if err != nil {
				t.Errorf("%s: %v", tc.Name, err)
			}
			var want []string
			for _, x := range tc.Expect {
				want = append(want, x.ReferenceCode+"/"+x.Match)
			}
			if got := summarize(ev); reflect.DeepEqual(got, want) {
				tp++
			} else {
				fn++
				t.Errorf("%s: got %v, want %v", tc.Name, got, want)
			}
		default:
			t.Fatalf("%s: unknown label %q", tc.Name, tc.Label)
		}
		for _, e := range ev {
			if err := e.Validate(); err != nil {
				t.Errorf("%s: %v", tc.Name, err)
			}
		}
	}
	t.Logf("corpus: %d true positives, %d false positives, %d misses", tp, fp, fn)
}

func summarize(ev []detectors.Evidence) []string {
	var out []string
	for _, e := range ev {
		code, _ := e.Fact("reference_code")
		m, _ := e.Fact("match")
		out = append(out, code+"/"+m)
	}
	return out
}
