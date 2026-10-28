package homedomain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/fetcher"
)

const (
	testdata = "../../../testdata/detectors/homedomain"
	issuer   = "GHOMEDOMAINISSUERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	asset    = "USDC:" + issuer
	domain   = "issuer.example"
	tomlURL  = "https://issuer.example/.well-known/stellar.toml"
)

var (
	asOf      = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	fetchedAt = asOf.Add(-30 * time.Second)
)

func okInput(body []byte) Input {
	return Input{
		Network: entity.Testnet, Asset: asset, HomeDomain: domain, AsOf: asOf,
		Fetch: Fetch{URL: tomlURL, FinalURL: tomlURL, Status: 200, Body: body, FetchedAt: fetchedAt},
	}
}

func fact(t *testing.T, e detectors.Evidence, name string) string {
	t.Helper()
	v, ok := e.Fact(name)
	if !ok {
		t.Fatalf("fact %q missing in %+v", name, e.Facts)
	}
	return v
}

func one(t *testing.T, in Input) detectors.Evidence {
	t.Helper()
	r, err := Detect(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Evidence) != 1 || len(r.NotChecked) != 0 {
		t.Fatalf("want one evidence, got %+v", r)
	}
	if err := r.Evidence[0].Validate(); err != nil {
		t.Fatal(err)
	}
	return r.Evidence[0]
}

func TestListed(t *testing.T) {
	body := fmt.Appendf(nil, "[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"%s\"\n", issuer)
	r, err := Detect(okInput(body))
	if err != nil || len(r.Evidence) != 0 || len(r.NotChecked) != 0 {
		t.Fatalf("got %+v, %v", r, err)
	}
}

func TestNotListedEvidence(t *testing.T) {
	body := []byte("[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"" + strings.ToLower(issuer) + "\"\n")
	in := okInput(body)
	in.HomeDomain = "Issuer.EXAMPLE."
	e := one(t, in)
	if e.Detector != Code || e.Class != detectors.ClassDomain || e.MaxLevel != detectors.MaxAutomatedLevel {
		t.Fatalf("bad header %+v", e)
	}
	if e.Entity != "testnet|asset|"+asset || !e.ObservedAt.Equal(asOf) {
		t.Fatalf("bad entity/observed_at %q %v", e.Entity, e.ObservedAt)
	}
	for name, want := range map[string]string{
		"reason": ReasonNotListed, "home_domain": domain, "toml_url": tomlURL,
		"fetched_at": "2026-10-27T11:59:30Z", "issuer_case_differs": "true",
		"code_listed_other_issuer": "false", "currency_entries": "1", "invalid_entries": "0",
	} {
		if got := fact(t, e, name); got != want {
			t.Errorf("fact %s = %q, want %q", name, got, want)
		}
	}
	sum := fact(t, e, "toml_sha256")
	if len(e.Artifacts) != 1 || e.Artifacts[0].SHA256 != sum || e.Artifacts[0].Kind != ArtifactStellarTOML ||
		!e.Artifacts[0].FetchedAt.Equal(fetchedAt) || e.Artifacts[0].URL != tomlURL {
		t.Fatalf("bad artifact %+v", e.Artifacts)
	}
}

func TestFetchFailures(t *testing.T) {
	timeout := fmt.Errorf("get: %w", context.DeadlineExceeded)
	for name, tc := range map[string]struct {
		err    error
		status int
		want   string
	}{
		"blocked":   {fetcher.ErrBlocked, 0, "blocked"},
		"too large": {fetcher.ErrTooLarge, 0, "too_large"},
		"timeout":   {timeout, 0, "timeout"},
		"dns":       {errors.New("no such host"), 0, "unreachable"},
		"http 500":  {nil, 500, "http_status"},
		"redirect":  {nil, 301, "http_status"},
	} {
		t.Run(name, func(t *testing.T) {
			in := okInput(nil)
			in.Fetch.Err, in.Fetch.Status = tc.err, tc.status
			e := one(t, in)
			if fact(t, e, "reason") != ReasonFetchFailed || fact(t, e, "fetch_error") != tc.want {
				t.Fatalf("facts %+v", e.Facts)
			}
			if len(e.Artifacts) != 0 {
				t.Fatal("no artifact expected without a body")
			}
		})
	}
}

func TestInvalidHomeDomain(t *testing.T) {
	for _, d := range []string{"exämple.com", "localhost", "issuer.example/path", "a\u202e.com", strings.Repeat("a.", 200) + "com"} {
		in := okInput(nil)
		in.HomeDomain = d
		in.Fetch = Fetch{}
		e := one(t, in)
		if fact(t, e, "fetch_error") != "invalid_domain" {
			t.Fatalf("%q: %+v", d, e.Facts)
		}
		if _, ok := e.Fact("home_domain"); ok {
			t.Fatalf("%q: untrusted domain copied into facts", d)
		}
	}
}

// An IP-shaped home_domain passes the domain shape check; the fetcher
// refuses IP literals, and that refusal is evidence, not a clean result.
func TestIPHomeDomainBlockedByFetcher(t *testing.T) {
	in := okInput(nil)
	in.HomeDomain = "127.0.0.1"
	in.Fetch = Fetch{URL: "https://127.0.0.1/.well-known/stellar.toml", Err: fetcher.ErrBlocked, FetchedAt: fetchedAt}
	e := one(t, in)
	if fact(t, e, "reason") != ReasonFetchFailed || fact(t, e, "fetch_error") != "blocked" {
		t.Fatalf("facts %+v", e.Facts)
	}
}

func TestHugeTOML(t *testing.T) {
	body := []byte("[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"" + issuer + "\"\n# " + strings.Repeat("x", MaxTOMLBytes))
	e := one(t, okInput(body))
	if fact(t, e, "reason") != ReasonUnparsable || fact(t, e, "parse_error") != "too_large" {
		t.Fatalf("facts %+v", e.Facts)
	}
	if len(e.Artifacts) != 1 {
		t.Fatal("oversized body must still be hashed")
	}
}

func TestHostileStructures(t *testing.T) {
	deep := "x = " + strings.Repeat("[", 10000) + strings.Repeat("]", 10000)
	deepTable := "x = " + strings.Repeat("{a=", 5000) + "1" + strings.Repeat("}", 5000)
	for name, body := range map[string]string{
		"deep arrays":        deep,
		"deep inline tables": deepTable,
		"unterminated array": "x = [1, 2",
		"bad escape":         `x = "\q"`,
		"short unicode":      `x = "\u12"`,
		"surrogate":          `x = "\uD800"`,
		"lone CR":            "x = 1\ry = 2",
		"bare word value":    "x = hello",
		"empty value":        "x = ",
		"header garbage":     "[[CURRENCIES]] x",
		"unclosed header":    "[[CURRENCIES]\ncode='USDC'",
		"dup table":          "[a]\n[a]",
		"multiline key":      `"""k""" = 1`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCurrencies([]byte(body)); err == nil {
				t.Fatal("want parse error")
			}
			e := one(t, okInput([]byte(body)))
			if fact(t, e, "reason") != ReasonUnparsable {
				t.Fatalf("facts %+v", e.Facts)
			}
		})
	}
}

func TestParserAcceptsValidTOML(t *testing.T) {
	for name, body := range map[string]string{
		"empty":           "",
		"comments only":   "# a\n\n   # b",
		"quoted keys":     `"a b".'c' = 1`,
		"dotted key":      "a.b.c = true",
		"arrays":          "a = [ [1,2], ['x', \"y\"], [], ]",
		"dates":           "a = 1979-05-27T07:32:00-08:00\nb = 1979-05-27\nc = 07:32:00",
		"numbers":         "a = -0x1F\nb = 1e-3\nc = inf\nd = -nan",
		"quotes at end":   "a = \"\"\"x\"\"\"\"\"\nb = '''y'''''",
		"empty inline":    "a = {}",
		"tabs":            "\ta\t=\t1\t# c",
		"sub array table": "[[CURRENCIES]]\ncode='A'\n[[CURRENCIES.x]]\n[[CURRENCIES]]\ncode='B'\n[[CURRENCIES.x]]",
	} {
		if _, err := parseCurrencies([]byte(body)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParserValues(t *testing.T) {
	got, err := parseCurrencies([]byte("[[CURRENCIES]]\ncode = \"\"\"\nUS\\\n   DC\"\"\"\nissuer = 'G\\x'\n[[CURRENCIES]]\ncode_template = \"\\u0041??\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].code != "USDC" || got[0].issuer != `G\x` || got[1].codeTemplate != "A??" {
		t.Fatalf("got %+v", got)
	}
}

func TestInvalidInput(t *testing.T) {
	cases := map[string]func(*Input){
		"zero as_of":         func(in *Input) { in.AsOf = time.Time{} },
		"bad network":        func(in *Input) { in.Network = "mainnet" },
		"native":             func(in *Input) { in.Asset = "native" },
		"lowercase issuer":   func(in *Input) { in.Asset = "USDC:" + strings.ToLower(issuer) },
		"zero fetched_at":    func(in *Input) { in.Fetch.FetchedAt = time.Time{} },
		"fetched after":      func(in *Input) { in.Fetch.FetchedAt = asOf.Add(time.Second) },
		"wrong fetch URL":    func(in *Input) { in.Fetch.URL = "https://other.example/.well-known/stellar.toml" },
		"missing fetch URL":  func(in *Input) { in.Fetch.URL = "" },
		"non-ASCII asset":    func(in *Input) { in.Asset = "USD\u0421:" + issuer },
		"bidi in asset code": func(in *Input) { in.Asset = "US\u202eDC:" + issuer },
	}
	for name, mut := range cases {
		in := okInput([]byte(""))
		mut(&in)
		if _, err := Detect(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	in := okInput(nil)
	in.HomeDomain = ""
	if _, err := Detect(in); !errors.Is(err, ErrNoHomeDomain) {
		t.Errorf("no home_domain: %v", err)
	}
}

func TestTemplateMatches(t *testing.T) {
	for _, tc := range []struct {
		tmpl, code string
		want       bool
	}{
		{"CORN????????", "CORN20180604", true},
		{"US??", "USDC", true},
		{"US??", "USD", false},
		{"US??", "usdc", false},
		{"", "", false},
	} {
		if got := templateMatches(tc.tmpl, tc.code); got != tc.want {
			t.Errorf("%q %q = %v", tc.tmpl, tc.code, got)
		}
	}
}

// Golden-corpus-style test over synthetic labeled fixtures.
func TestCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		AsOf       time.Time      `json:"as_of"`
		FetchedAt  time.Time      `json:"fetched_at"`
		Network    entity.Network `json:"network"`
		Asset      string         `json:"asset"`
		HomeDomain string         `json:"home_domain"`
		Cases      []struct {
			Name       string `json:"name"`
			TOML       string `json:"toml"`
			FetchError string `json:"fetch_error"`
			Status     int    `json:"status"`
			Expect     string `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	url, _ := fetcher.StellarTOMLURL(c.HomeDomain)
	used := map[string]bool{}
	for _, tc := range c.Cases {
		in := Input{Network: c.Network, Asset: c.Asset, HomeDomain: c.HomeDomain, AsOf: c.AsOf,
			Fetch: Fetch{URL: url, FinalURL: url, Status: 200, FetchedAt: c.FetchedAt}}
		if tc.TOML != "" {
			used[tc.TOML] = true
			if in.Fetch.Body, err = os.ReadFile(filepath.Join(testdata, tc.TOML)); err != nil {
				t.Fatal(err)
			}
		}
		if tc.FetchError != "" {
			in.Fetch.Err = errors.New(tc.FetchError)
		}
		if tc.Status != 0 {
			in.Fetch.Status = tc.Status
		}
		r, err := Detect(in)
		if err != nil {
			t.Errorf("%s: %v", tc.Name, err)
			continue
		}
		var got string
		switch {
		case len(r.NotChecked) > 0:
			got = "not_checked"
		case len(r.Evidence) == 0:
			got = "listed"
		default:
			got, _ = r.Evidence[0].Fact("reason")
			if err := r.Evidence[0].Validate(); err != nil {
				t.Errorf("%s: %v", tc.Name, err)
			}
		}
		if got != tc.Expect {
			t.Errorf("%s: got %s, want %s", tc.Name, got, tc.Expect)
		}
	}
	files, _ := filepath.Glob(filepath.Join(testdata, "*.toml"))
	for _, f := range files {
		if !used[filepath.Base(f)] {
			t.Errorf("fixture %s has no labeled case", filepath.Base(f))
		}
	}
}
