// Package assetlookalike implements D-ASSET-LOOKALIKE (ARCHITECTURE §4.2,
// §17 EC16): an asset whose code equals, or is an ASCII confusable of, a
// reference code while its issuer is not one of that code's known issuers.
//
// Asset codes are ASCII alphanumerics, so the confusables are character
// substitutions (0/O, 1/I/l, 5/S, 2/Z, 8/B), case, and short affixes
// ("USDCx", "xUSDC", "USDC1"). Unicode homoglyphs belong to domains and are a
// separate detector. The reference set is keyed code -> {known issuers}
// because several legitimate issuers can share one code.
//
// Detect is pure: no clock, no network. It emits evidence only; levels are
// decided by the verdict engine and cap at `suspicious`.
package assetlookalike

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

const (
	Code     = "D-ASSET-LOOKALIKE"
	Category = "asset_code_lookalike"

	// maxAffix is how many extra characters an affix match allows.
	maxAffix = 2
	// minAffixBase keeps very short reference codes out of affix matching,
	// where almost any code would contain them.
	minAffixBase = 3
	// maxReferenceCodes bounds the reference set.
	maxReferenceCodes = 10000
)

// Match kinds, recorded in the "match" fact.
const (
	MatchExact      = "exact"      // same code, different issuer
	MatchConfusable = "confusable" // same skeleton (case or character substitution)
	MatchAffix      = "affix"      // reference skeleton plus up to maxAffix characters
)

// ErrInvalidInput is returned for an asset, network, reference or as_of that
// fails validation. Callers treat it as "not analyzed", never as no signal.
var ErrInvalidInput = errors.New("assetlookalike: invalid input")

type refEntry struct {
	code      string
	skeletons [2]string
	issuers   []string // sorted, unique
}

// Reference is a validated, immutable reference set.
type Reference struct {
	entries []refEntry // sorted by code
	byCode  map[string]int
}

// NewReference validates codes and issuers. An empty issuer set is allowed
// and means no issued asset with that code is known (for example XLM, which
// is native), so every issued asset with that code is a match.
func NewReference(set map[string][]string) (*Reference, error) {
	if len(set) == 0 || len(set) > maxReferenceCodes {
		return nil, fmt.Errorf("%w: reference set has %d codes", ErrInvalidInput, len(set))
	}
	r := &Reference{byCode: make(map[string]int, len(set))}
	for code, issuers := range set {
		e := refEntry{code: code, skeletons: skeletons(code)}
		seen := map[string]bool{}
		for _, iss := range issuers {
			if _, err := entity.NormalizeKey(entity.Asset, code+":"+iss); err != nil {
				return nil, fmt.Errorf("%w: reference %q issuer: %v", ErrInvalidInput, code, err)
			}
			if !seen[iss] {
				seen[iss] = true
				e.issuers = append(e.issuers, iss)
			}
		}
		if len(issuers) == 0 && !validCode(code) {
			return nil, fmt.Errorf("%w: reference code %q", ErrInvalidInput, code)
		}
		sort.Strings(e.issuers)
		r.entries = append(r.entries, e)
	}
	sort.Slice(r.entries, func(i, j int) bool { return r.entries[i].code < r.entries[j].code })
	for i, e := range r.entries {
		r.byCode[e.code] = i
	}
	return r, nil
}

// Detect checks one asset ("CODE:ISSUER") against the reference set and
// returns one evidence item per matched reference code, ordered by code.
func (r *Reference) Detect(network entity.Network, asset string, asOf time.Time) ([]detectors.Evidence, error) {
	if asOf.IsZero() {
		return nil, fmt.Errorf("%w: as_of is required", ErrInvalidInput)
	}
	key, err := entity.Canonical(network, entity.Asset, asset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if asset == "native" {
		return nil, nil
	}
	code, issuer, _ := strings.Cut(asset, ":")

	// The asset is itself a known asset: nothing to compare.
	if i, ok := r.byCode[code]; ok && r.entries[i].knows(issuer) {
		return nil, nil
	}

	sk := skeletons(code)
	var out []detectors.Evidence
	for _, e := range r.entries {
		if e.knows(issuer) {
			// Same issuer as a known asset; a related code from that issuer is not a look-alike.
			continue
		}
		kind := e.match(code, sk)
		if kind == "" {
			continue
		}
		facts := []detectors.Fact{
			{Name: "asset", Value: asset},
			{Name: "code", Value: code},
			{Name: "issuer", Value: issuer},
			{Name: "reference_code", Value: e.code},
			{Name: "match", Value: kind},
			{Name: "known_issuer_count", Value: strconv.Itoa(len(e.issuers))},
		}
		if len(e.issuers) > 0 {
			known := make([]string, len(e.issuers))
			for i, iss := range e.issuers {
				known[i] = e.code + ":" + iss
			}
			facts = append(facts, detectors.Fact{Name: "known_assets", Value: strings.Join(known, ",")})
		}
		out = append(out, detectors.Evidence{
			Detector:   Code,
			Class:      detectors.ClassOnchainPattern,
			Category:   Category,
			Entity:     key,
			MaxLevel:   detectors.MaxAutomatedLevel,
			Facts:      facts,
			ObservedAt: asOf.UTC(),
		})
	}
	return out, nil
}

func (e refEntry) knows(issuer string) bool {
	i := sort.SearchStrings(e.issuers, issuer)
	return i < len(e.issuers) && e.issuers[i] == issuer
}

func (e refEntry) match(code string, sk [2]string) string {
	if code == e.code {
		return MatchExact
	}
	for _, c := range sk {
		for _, r := range e.skeletons {
			if c == r {
				return MatchConfusable
			}
		}
	}
	for _, c := range sk {
		for _, r := range e.skeletons {
			if len(r) >= minAffixBase && len(c) > len(r) && len(c)-len(r) <= maxAffix && strings.Contains(c, r) {
				return MatchAffix
			}
		}
	}
	return ""
}

// skeletons returns the two readings of a code, which differ only in how a
// lowercase l is read (as I, or case-folded to L).
func skeletons(code string) [2]string {
	return [2]string{skeleton(code, 'I'), skeleton(code, 'L')}
}

// skeleton maps a code to a canonical form in which confusable codes are
// equal: digit 1 and i become I; lowercase l becomes lAs; 0 becomes O; 5, 2
// and 8 become S, Z and B; everything else is uppercased. Input is ASCII
// alphanumeric (validated by the caller).
func skeleton(code string, lAs byte) string {
	b := []byte(code)
	for i, c := range b {
		if c == 'l' {
			b[i] = lAs
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case '0':
			c = 'O'
		case '1':
			c = 'I'
		case '5':
			c = 'S'
		case '2':
			c = 'Z'
		case '8':
			c = 'B'
		}
		b[i] = c
	}
	return string(b)
}

func validCode(code string) bool {
	if len(code) == 0 || len(code) > 12 {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
