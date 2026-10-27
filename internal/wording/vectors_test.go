package wording

import (
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	root "github.com/SoroSentinel/Sorosentinel-intel/wording"
)

type renderVectors struct {
	Config struct {
		MethodologyURL string `json:"methodology_url"`
		ReviewURL      string `json:"review_url"`
	} `json:"config"`
	Attributions []Attribution `json:"attributions"`
	Templates    []Template    `json:"templates"`
	Cases        []struct {
		Name    string `json:"name"`
		Request struct {
			TemplateID     string `json:"template_id"`
			SignalLevel    string `json:"signal_level"`
			AsOf           string `json:"as_of"`
			Method         string `json:"method"`
			RulesetVersion string `json:"ruleset_version"`
			Slots          map[string]struct {
				Type  SlotType `json:"type"`
				Value string   `json:"value"`
			} `json:"slots"`
		} `json:"request"`
		Expect struct {
			Text        string            `json:"text"`
			Attribution string            `json:"attribution"`
			Facts       map[string]string `json:"facts"`
			Error       string            `json:"error"`
		} `json:"expect"`
	} `json:"cases"`
}

func TestRenderVectors(t *testing.T) {
	raw, err := root.FS.ReadFile("vectors/render.json")
	if err != nil {
		t.Fatal(err)
	}
	var v renderVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var bl Blocklist
	if err := decodeFile(root.FS, "blocklist.yaml", &bl); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(v.Templates, v.Attributions, bl)
	if err != nil {
		t.Fatal(err)
	}
	if p := reg.Lint(); len(p) > 0 {
		t.Fatalf("vector registry has lint problems: %v", p)
	}
	rnd, err := NewRenderer(reg, Config{MethodologyURL: v.Config.MethodologyURL, ReviewURL: v.Config.ReviewURL})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			stmt, err := renderCase(rnd, c.Request.TemplateID, c.Request.SignalLevel, c.Request.AsOf,
				c.Request.Method, c.Request.RulesetVersion, c.Request.Slots)
			if c.Expect.Error != "" {
				var we *Error
				if !errors.As(err, &we) || string(we.Code) != c.Expect.Error {
					t.Fatalf("want error %q, got %v (text %q)", c.Expect.Error, err, stmt.Text)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if stmt.Text != c.Expect.Text {
				t.Errorf("text:\n got %q\nwant %q", stmt.Text, c.Expect.Text)
			}
			if stmt.Attribution != c.Expect.Attribution {
				t.Errorf("attribution:\n got %q\nwant %q", stmt.Attribution, c.Expect.Attribution)
			}
			if !maps.Equal(stmt.Facts, c.Expect.Facts) {
				t.Errorf("facts = %v, want %v", stmt.Facts, c.Expect.Facts)
			}
		})
	}
}

func renderCase(rnd *Renderer, id, level, asOf, method, ruleset string, slots map[string]struct {
	Type  SlotType `json:"type"`
	Value string   `json:"value"`
}) (Statement, error) {
	req := Request{TemplateID: id, Level: signal.Public(level), Method: method, RulesetVersion: ruleset, Slots: map[string]Value{}}
	if asOf != "" {
		t, err := time.Parse(time.RFC3339, asOf)
		if err != nil {
			return Statement{}, err
		}
		req.AsOf = t
	}
	for name, s := range slots {
		val, err := NewValue(s.Type, s.Value)
		if err != nil {
			return Statement{}, err
		}
		req.Slots[name] = val
	}
	return rnd.Render(req)
}
