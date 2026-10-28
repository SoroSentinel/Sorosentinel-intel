package api

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
	"github.com/SoroSentinel/Sorosentinel-intel/schemas"
)

func slogTo(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }

// approvedRenderer is the shipped registry with the four entity templates and
// the attribution marked approved, so the statement path can be checked
// against PublicStatement.json before counsel approves the real ones.
// Test-only: production loads wording.LoadEmbedded unchanged.
func approvedRenderer(t *testing.T) *wording.Renderer {
	t.Helper()
	attr := wording.Attribution{ID: "standard_v1", Status: wording.StatusApproved,
		Text: "Method: {method}, ruleset {ruleset_version}. Observed {as_of}. " +
			"This is an indicator, not a determination of intent or wrongdoing. " +
			"Methodology: {methodology_url}. Request a review: {review_url}."}
	levels := []signal.Public{signal.Caution, signal.HighCaution}
	tmpls := []wording.Template{
		{ID: tmplLookalike, SignalLevels: levels, Attribution: attr.ID, Status: wording.StatusApproved,
			Text:  "This asset uses the same code as {known_asset} but a different issuer account. The issuer of {known_asset} is {known_issuer}. Observed {as_of}.",
			Slots: map[string]wording.SlotType{"known_asset": wording.SlotAssetKey, "known_issuer": wording.SlotAccount}},
		{ID: tmplLookalikeSimilar, SignalLevels: levels, Attribution: attr.ID, Status: wording.StatusApproved,
			Text:  "This asset's code is similar to the code of {known_asset}. Observed {as_of}.",
			Slots: map[string]wording.SlotType{"known_asset": wording.SlotAssetKey}},
		{ID: tmplHomeDomainMismatch, SignalLevels: levels, Attribution: attr.ID, Status: wording.StatusApproved,
			Text:  "Issuer account {issuer} sets its home domain to {home_domain}. The stellar.toml file does not list {asset}. Checked {as_of}.",
			Slots: map[string]wording.SlotType{"issuer": wording.SlotAccount, "home_domain": wording.SlotDomain, "asset": wording.SlotAssetKey}},
		{ID: tmplHomeDomainNoFile, SignalLevels: []signal.Public{signal.Caution}, Attribution: attr.ID, Status: wording.StatusApproved,
			Text:  "Issuer account {issuer} sets its home domain to {home_domain}; the file could not be read for {asset}. Checked {as_of}.",
			Slots: map[string]wording.SlotType{"issuer": wording.SlotAccount, "home_domain": wording.SlotDomain, "asset": wording.SlotAssetKey}},
	}
	reg, err := wording.NewRegistry(tmpls, []wording.Attribution{attr}, wording.Blocklist{Terms: []string{"scam", "malicious"}})
	if err != nil {
		t.Fatal(err)
	}
	if p := reg.Lint(); len(p) > 0 {
		t.Fatalf("test registry lint: %v", p)
	}
	rnd, err := wording.NewRenderer(reg, testRenderConfig)
	if err != nil {
		t.Fatal(err)
	}
	return rnd
}

func TestRenderedStatementsWhenTemplatesAreApproved(t *testing.T) {
	st := &fakeStore{results: map[string]store.LookupResult{"testnet|asset|" + lookAsset: lookalikeResult(t)}}
	rec := do(t, newServer(t, st, "", approvedRenderer(t)), "GET", entityPath("asset", lookAsset, "testnet"), "", nil)
	got := decode[EntitySignal](t, rec)
	if len(got.Statements) != 2 {
		t.Fatalf("statements = %+v", got.Statements)
	}
	// Newest evidence first: the home-domain row, then the look-alike row.
	if got.Statements[0].TemplateID != tmplHomeDomainMismatch || got.Statements[1].TemplateID != tmplLookalike {
		t.Errorf("template order: %s, %s", got.Statements[0].TemplateID, got.Statements[1].TemplateID)
	}
	if got.Statements[1].Method != "D-ASSET-LOOKALIKE" || !strings.Contains(got.Statements[1].Text, refIssuer) {
		t.Errorf("statement = %+v", got.Statements[1])
	}
}

// --- contract test: responses validate against schemas/jsonschema ---

func TestResponsesMatchSchemas(t *testing.T) {
	v := loadSchemas(t)
	g := gKey(5)

	similar := lookalikeResult(t)
	similar.Evidence = similar.Evidence[1:]
	similar.Evidence[0].Payload = payload(t, "asset", lookAsset, "match", "confusable", "known_assets", refAsset+","+"USDC:"+gKey(4))
	noDomain := lookalikeResult(t)
	noDomain.Evidence = noDomain.Evidence[:1]
	noDomain.Evidence[0].Payload = payload(t, "asset", lookAsset, "issuer", lookIssuer, "reason", "fetch_failed", "fetch_error", "invalid_domain")
	disputed := lookalikeResult(t)
	disputed.Verdict.Disputed = true
	garbage := lookalikeResult(t)
	garbage.Evidence[0].Payload = []byte(`{"facts":[{"name":"issuer","value":"not‮an account"}]}`)
	garbage.Evidence[1].Payload = []byte(`[1,2]`)

	for _, rnd := range []*wording.Renderer{nil, approvedRenderer(t)} {
		for name, res := range map[string]store.LookupResult{
			"known": lookalikeResult(t), "similar": similar, "no domain": noDomain,
			"disputed": disputed, "garbage payloads": garbage, "unknown": {},
		} {
			st := &fakeStore{results: map[string]store.LookupResult{"testnet|asset|" + lookAsset: res}}
			h := newServer(t, st, "", rnd)
			rec := do(t, h, "GET", entityPath("asset", lookAsset, "testnet"), "", nil)
			v.check(t, name+" (single)", "EntitySignal", rec.Body.Bytes())

			rec = do(t, h, "POST", "/v1/entities:batchGet", "application/json",
				batchBody(t, Entity{"testnet", "asset", lookAsset}, Entity{"public", "account", g}))
			var batch struct {
				Results []json.RawMessage `json:"results"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &batch); err != nil || len(batch.Results) != 2 {
				t.Fatalf("%s: batch body %s", name, rec.Body)
			}
			v.check(t, name+" (batch)", "batchGetResponse", rec.Body.Bytes())
		}
	}

	f := writeSnapshots(t, entity.Public, 3)
	rec := do(t, newServer(t, f.st, f.dir, nil), "GET", "/v1/snapshots/latest?network=public", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot status %d", rec.Code)
	}
	v.check(t, "snapshot", "Snapshot", rec.Body.Bytes())
}

// The validator itself must reject what the schemas forbid.
func TestSchemaValidatorRejects(t *testing.T) {
	v := loadSchemas(t)
	ok := `{"entity":{"network":"public","type":"account","key":"G"},"signal_level":"caution","as_of":"2026-10-28T09:30:15Z","facts":{},"statements":[]}`
	if errs := v.validate("EntitySignal", mustJSON(t, ok)); len(errs) > 0 {
		t.Fatalf("valid document rejected: %v", errs)
	}
	for name, doc := range map[string]string{
		"internal level":  strings.Replace(ok, `"caution"`, `"suspicious"`, 1),
		"extra field":     strings.Replace(ok, `"facts"`, `"level":"x","facts"`, 1),
		"missing facts":   strings.Replace(ok, `"facts":{},`, ``, 1),
		"bad timestamp":   strings.Replace(ok, `2026-10-28T09:30:15Z`, `yesterday`, 1),
		"bad network":     strings.Replace(ok, `"public"`, `"futurenet"`, 1),
		"non-string fact": strings.Replace(ok, `"facts":{}`, `"facts":{"a":1}`, 1),
	} {
		if errs := v.validate("EntitySignal", mustJSON(t, doc)); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// schemaSet is a minimal JSON Schema 2020-12 validator covering exactly the
// keywords used in schemas/jsonschema. An unsupported keyword fails the test,
// so a schema change cannot be silently skipped.
type schemaSet struct {
	byID map[string]map[string]any
}

func loadSchemas(t *testing.T) *schemaSet {
	t.Helper()
	files, err := fs.Glob(schemas.FS, "jsonschema/*.json")
	if err != nil || len(files) == 0 {
		t.Fatal("no schemas")
	}
	s := &schemaSet{byID: map[string]map[string]any{}}
	for _, f := range files {
		raw, _ := schemas.FS.ReadFile(f)
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		s.byID[doc["$id"].(string)] = doc
	}
	// The batchGet response is defined inline in the OpenAPI document.
	s.byID["batchGetResponse"] = map[string]any{
		"type": "object", "required": []any{"results"}, "additionalProperties": false,
		"properties": map[string]any{"results": map[string]any{
			"type": "array", "items": map[string]any{"$ref": "urn:sorosentinel:schema:v1:EntitySignal"}}},
	}
	return s
}

func (s *schemaSet) check(t *testing.T, name, schema string, body []byte) {
	t.Helper()
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Errorf("%s: not JSON: %v", name, err)
		return
	}
	for _, e := range s.validate(schema, doc) {
		t.Errorf("%s: %s", name, e)
	}
}

func (s *schemaSet) validate(schema string, doc any) []string {
	id := schema
	if !strings.HasPrefix(id, "urn:") && id != "batchGetResponse" {
		id = "urn:sorosentinel:schema:v1:" + schema
	}
	root, ok := s.byID[id]
	if !ok {
		return []string{"unknown schema " + schema}
	}
	var errs []string
	s.walk(root, root, doc, "$", &errs)
	return errs
}

var dateTimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

func (s *schemaSet) walk(root, sch map[string]any, doc any, at string, errs *[]string) {
	fail := func(f string, a ...any) { *errs = append(*errs, at+": "+fmt.Sprintf(f, a...)) }
	for kw, val := range sch {
		switch kw {
		case "$schema", "$id", "title", "description", "$defs", "contentEncoding":
		case "$ref":
			ref := val.(string)
			base, frag, _ := strings.Cut(ref, "#")
			target := root
			if base != "" {
				var ok bool
				if target, ok = s.byID[base]; !ok {
					fail("unresolved $ref %s", ref)
					continue
				}
			}
			next := target
			if frag != "" {
				for _, part := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
					next, _ = next[part].(map[string]any)
				}
				if next == nil {
					fail("unresolved $ref %s", ref)
					continue
				}
			}
			s.walk(target, next, doc, at, errs)
		case "type":
			if !hasType(doc, val.(string)) {
				fail("type %T, want %s", doc, val)
			}
		case "enum":
			found := false
			for _, e := range val.([]any) {
				found = found || reflect.DeepEqual(e, doc)
			}
			if !found {
				fail("%v not in enum %v", doc, val)
			}
		case "const":
			if !reflect.DeepEqual(val, doc) {
				fail("%v != const %v", doc, val)
			}
		case "required":
			if m, ok := doc.(map[string]any); ok {
				for _, r := range val.([]any) {
					if _, ok := m[r.(string)]; !ok {
						fail("missing required %s", r)
					}
				}
			}
		case "properties":
			if m, ok := doc.(map[string]any); ok {
				for k, sub := range val.(map[string]any) {
					if v, ok := m[k]; ok {
						s.walk(root, sub.(map[string]any), v, at+"."+k, errs)
					}
				}
			}
		case "additionalProperties":
			m, ok := doc.(map[string]any)
			if !ok {
				continue
			}
			props, _ := sch["properties"].(map[string]any)
			for k, v := range m {
				if _, declared := props[k]; declared {
					continue
				}
				switch ap := val.(type) {
				case bool:
					if !ap {
						fail("unexpected property %q", k)
					}
				case map[string]any:
					s.walk(root, ap, v, at+"."+k, errs)
				}
			}
		case "items":
			if a, ok := doc.([]any); ok {
				for i, v := range a {
					s.walk(root, val.(map[string]any), v, fmt.Sprintf("%s[%d]", at, i), errs)
				}
			}
		case "minItems", "maxItems":
			if a, ok := doc.([]any); ok {
				n := int(val.(float64))
				if (kw == "minItems" && len(a) < n) || (kw == "maxItems" && len(a) > n) {
					fail("%s %d violated by %d items", kw, n, len(a))
				}
			}
		case "uniqueItems":
			if a, ok := doc.([]any); ok && val.(bool) {
				seen := map[string]bool{}
				for _, v := range a {
					k := fmt.Sprint(v)
					if seen[k] {
						fail("duplicate item %v", v)
					}
					seen[k] = true
				}
			}
		case "pattern":
			if str, ok := doc.(string); ok && !regexp.MustCompile(val.(string)).MatchString(str) {
				fail("%q does not match %s", str, val)
			}
		case "minLength", "maxLength":
			if str, ok := doc.(string); ok {
				n, l := int(val.(float64)), len([]rune(str))
				if (kw == "minLength" && l < n) || (kw == "maxLength" && l > n) {
					fail("%s %d violated by length %d", kw, n, l)
				}
			}
		case "minimum":
			if f, ok := doc.(float64); ok && f < val.(float64) {
				fail("%v < minimum %v", f, val)
			}
		case "format":
			str, ok := doc.(string)
			if !ok {
				continue
			}
			switch val {
			case "date-time":
				if _, err := time.Parse(time.RFC3339Nano, str); err != nil || !dateTimeRe.MatchString(str) {
					fail("%q is not a date-time", str)
				}
			case "uri":
				if !strings.Contains(str, ":") {
					fail("%q is not a uri", str)
				}
			default:
				fail("unsupported format %v", val)
			}
		default:
			fail("validator does not support keyword %q", kw)
		}
	}
}

func hasType(doc any, typ string) bool {
	switch typ {
	case "object":
		_, ok := doc.(map[string]any)
		return ok
	case "array":
		_, ok := doc.([]any)
		return ok
	case "string":
		_, ok := doc.(string)
		return ok
	case "boolean":
		_, ok := doc.(bool)
		return ok
	case "integer":
		f, ok := doc.(float64)
		return ok && f == math.Trunc(f)
	case "null":
		return doc == nil
	}
	return false
}
