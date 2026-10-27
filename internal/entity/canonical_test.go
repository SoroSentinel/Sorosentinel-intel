package entity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SoroSentinel/Sorosentinel-intel/schemas"
)

type keyVectors struct {
	Cases []struct {
		Name  string `json:"name"`
		Input struct {
			Network string `json:"network"`
			Type    string `json:"type"`
			Key     string `json:"key"`
		} `json:"input"`
		Canonical string `json:"canonical"`
		Hash128   string `json:"hash128"`
		Error     string `json:"error"`
	} `json:"cases"`
}

func TestCanonicalKeyVectors(t *testing.T) {
	raw, err := schemas.FS.ReadFile("vectors/canonical_keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var v keyVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := Canonical(Network(c.Input.Network), Type(c.Input.Type), c.Input.Key)
			if c.Error != "" {
				var e *Error
				if !errors.As(err, &e) || string(e.Code) != c.Error {
					t.Fatalf("want error %q, got %q, %v", c.Error, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.Canonical {
				t.Errorf("canonical = %q, want %q", got, c.Canonical)
			}
			if h := SnapshotHash(got); h != c.Hash128 {
				t.Errorf("hash = %s, want %s", h, c.Hash128)
			}
		})
	}
}

func TestCanonicalRejectsOversizedInput(t *testing.T) {
	huge := strings.Repeat("a", 10_000) + ".com"
	if _, err := Canonical(Public, Domain, huge); err == nil {
		t.Fatal("oversized key accepted")
	}
}

func TestCanonicalRejectsEmptyKey(t *testing.T) {
	for _, typ := range []Type{Account, Asset, Contract, WasmHash, Domain} {
		if _, err := Canonical(Public, typ, ""); err == nil {
			t.Errorf("%s: empty key accepted", typ)
		}
	}
}
