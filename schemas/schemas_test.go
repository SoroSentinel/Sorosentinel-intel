package schemas

import (
	"encoding/json"
	"io/fs"
	"path"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const draft202012 = "https://json-schema.org/draft/2020-12/schema"

// Internal verdict vocabulary must never appear in a public contract.
var internalTerms = []string{`"benign"`, `"suspicious"`, `"malicious"`, `"safe"`}

func TestSchemasWellFormed(t *testing.T) {
	files, err := fs.Glob(FS, "jsonschema/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no schemas found: %v", err)
	}
	for _, f := range files {
		raw, err := FS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s: invalid JSON: %v", f, err)
			continue
		}
		if doc["$schema"] != draft202012 {
			t.Errorf("%s: $schema must be %s", f, draft202012)
		}
		want := "urn:sorosentinel:schema:v1:" + strings.TrimSuffix(path.Base(f), ".json")
		if doc["$id"] != want {
			t.Errorf("%s: $id = %v, want %s", f, doc["$id"], want)
		}
		for _, term := range internalTerms {
			if strings.Contains(string(raw), term) {
				t.Errorf("%s: contains internal/forbidden term %s", f, term)
			}
		}
	}
}

func TestSchemasOpenAPIWellFormed(t *testing.T) {
	raw, err := FS.ReadFile("openapi/intel.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string         `yaml:"openapi"`
		Paths   map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1.") {
		t.Errorf("openapi = %q, want 3.1.x", doc.OpenAPI)
	}
	if len(doc.Paths) == 0 {
		t.Error("no paths defined")
	}
}

func TestSchemasVectorsWellFormed(t *testing.T) {
	files, _ := fs.Glob(FS, "vectors/*.json")
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}
	for _, f := range files {
		raw, _ := FS.ReadFile(f)
		if !json.Valid(raw) {
			t.Errorf("%s: invalid JSON", f)
		}
	}
}
