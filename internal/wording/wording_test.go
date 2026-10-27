package wording

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

func testConfig() Config {
	return Config{MethodologyURL: "https://sorosentinel.invalid/m", ReviewURL: "https://sorosentinel.invalid/r"}
}

func TestEmbeddedRegistryLintsClean(t *testing.T) {
	reg, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if p := reg.Lint(); len(p) > 0 {
		t.Fatalf("lint problems: %v", p)
	}
}

// The shipped template is a draft until counsel approves it, so production
// rendering must fail closed and leave only facts.
func TestEmbeddedDraftTemplateFailsClosed(t *testing.T) {
	reg, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := NewRenderer(reg, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	asset, _ := NewValue(SlotAssetKey, "USDC:GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	issuer, _ := NewValue(SlotAccount, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
	req := Request{
		TemplateID: "asset.lookalike.v1", Level: signal.Caution,
		AsOf: time.Date(2026, 10, 26, 14, 2, 0, 0, time.UTC), Method: "D-ASSET-LOOKALIKE", RulesetVersion: "2026.10.1",
		Slots: map[string]Value{"known_asset": asset, "known_issuer": issuer},
	}
	stmt, err := rnd.Render(req)
	var we *Error
	if !errors.As(err, &we) || we.Code != ErrNotApproved {
		t.Fatalf("want not_approved, got %v", err)
	}
	if stmt.Text != "" || stmt.Attribution != "" {
		t.Fatal("prose returned on failure")
	}
	if f := Facts(req); f["known_issuer"] == "" || f["as_of"] != "2026-10-26T14:02:00Z" {
		t.Fatalf("facts fallback incomplete: %v", f)
	}
}

func TestBlocklistMatching(t *testing.T) {
	reg, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	hits := []string{"Scam", "SCAMS", "scammed", "rug  pull", "rug-pull", "Rug_Pulls", "designed to", "fraudulent", "hacker", "Ponzi"}
	for _, s := range hits {
		if len(reg.BlockedTerms("x "+s+" y")) == 0 {
			t.Errorf("%q not blocked", s)
		}
	}
	misses := []string{"scampi", "hackathon", "fakery", "designer", "unsafe-ish"}
	for _, s := range misses {
		if got := reg.BlockedTerms(s); len(got) > 0 {
			t.Errorf("%q falsely blocked: %v", s, got)
		}
	}
}

func lintOne(t *testing.T, tmpl Template) []string {
	t.Helper()
	reg, err := NewRegistry([]Template{tmpl}, []Attribution{{
		ID: "a_v1", Status: StatusApproved,
		Text: "{method} {ruleset_version} {as_of}. This is an indicator, not a determination of intent or wrongdoing. {methodology_url} {review_url}",
	}}, Blocklist{Terms: []string{"scam", "designed to"}})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range reg.Lint() {
		out = append(out, p.Msg)
	}
	return out
}

func TestLintCatchesBadTemplates(t *testing.T) {
	good := Template{
		ID: "x.y.v1", SignalLevels: []signal.Public{signal.Caution},
		Text: "Asset {asset} observed {as_of}.", Slots: map[string]SlotType{"asset": SlotAssetKey},
		Attribution: "a_v1", Status: StatusDraft,
	}
	if p := lintOne(t, good); len(p) > 0 {
		t.Fatalf("good template flagged: %v", p)
	}
	cases := map[string]func(*Template){
		"blocked terms: scam":     func(t *Template) { t.Text = "This scam {asset} {as_of}" },
		"blocked terms: designed": func(t *Template) { t.Text = "Contract designed  to {asset}" },
		"not declared":            func(t *Template) { t.Text = "{asset} {other}" },
		"declared but unused":     func(t *Template) { t.Text = "nothing here" },
		"is reserved":             func(t *Template) { t.Slots = map[string]SlotType{"asset": SlotAssetKey, "as_of": SlotTimestamp} },
		"unknown type":            func(t *Template) { t.Slots = map[string]SlotType{"asset": "free_text"} },
		"not found":               func(t *Template) { t.Attribution = "missing_v1" },
		"printable ASCII":         func(t *Template) { t.Text = "Asset {asset} scаm" },
		"unknown status":          func(t *Template) { t.Status = "approved" },
		"unmatched":               func(t *Template) { t.Text = "Asset {asset" },
		"signal_levels is empty":  func(t *Template) { t.SignalLevels = nil },
		"unknown signal level":    func(t *Template) { t.SignalLevels = []signal.Public{"malicious"} },
		"id must look like":       func(t *Template) { t.ID = "Bad ID" },
	}
	for want, mutate := range cases {
		tmpl := good
		tmpl.Slots = map[string]SlotType{"asset": SlotAssetKey}
		mutate(&tmpl)
		p := lintOne(t, tmpl)
		if !strings.Contains(strings.Join(p, "|"), want) {
			t.Errorf("%s: problems %v do not mention %q", want, p, want)
		}
	}
}

func TestLintRequiresAttributionDisclaimer(t *testing.T) {
	reg, err := NewRegistry(nil, []Attribution{{ID: "a_v1", Status: StatusApproved, Text: "{method} {as_of}"}},
		Blocklist{Terms: []string{"scam"}})
	if err != nil {
		t.Fatal(err)
	}
	msgs := ""
	for _, p := range reg.Lint() {
		msgs += p.Msg + "|"
	}
	for _, want := range []string{"{methodology_url}", "{review_url}", "not a determination"} {
		if !strings.Contains(msgs, want) {
			t.Errorf("missing problem about %s: %s", want, msgs)
		}
	}
}

func TestNewRendererRejectsUnsafeConfig(t *testing.T) {
	for _, u := range []string{"", "http://x.invalid/m", "javascript:alert(1)", "https://user@x.invalid/", "https://x.invalid/‮"} {
		if _, err := NewRenderer(&Registry{}, Config{MethodologyURL: u, ReviewURL: "https://x.invalid/r"}); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
}

func TestNewValueRejectsControlCharacters(t *testing.T) {
	for _, s := range []string{"example.com\n", "exa‏mple.com", "example.com\x00", "⁦example.com"} {
		if _, err := NewValue(SlotDomain, s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
