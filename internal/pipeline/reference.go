package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/assetlookalike"
)

// maxReferenceFileBytes caps the reviewed reference file.
const maxReferenceFileBytes = 1 << 20

// LoadReference reads a reviewed reference-asset file
// (config/reference-assets.<network>.json): a JSON object mapping each
// reference code to its known issuers, e.g. {"USDC": ["G..."], "XLM": []}.
// Duplicate codes, unknown shapes and trailing data are errors.
func LoadReference(path string) (*assetlookalike.Reference, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxReferenceFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxReferenceFileBytes {
		return nil, errors.New("pipeline: reference file too large")
	}
	set, err := parseReference(b)
	if err != nil {
		return nil, fmt.Errorf("pipeline: reference file: %w", err)
	}
	return assetlookalike.NewReference(set)
}

func parseReference(b []byte) (map[string][]string, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	set := map[string][]string{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		code, _ := t.(string)
		if _, dup := set[code]; dup {
			return nil, fmt.Errorf("duplicate code %q", code)
		}
		var issuers []string
		if err := d.Decode(&issuers); err != nil {
			return nil, fmt.Errorf("code %q: issuers must be an array of strings", code)
		}
		if issuers == nil {
			issuers = []string{}
		}
		set[code] = issuers
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return set, nil
}
