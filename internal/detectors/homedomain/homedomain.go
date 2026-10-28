// Package homedomain implements D-HOMEDOMAIN-MISMATCH (ARCHITECTURE §4.2,
// §17 EC17): the stellar.toml at the issuer's `home_domain` does not list the
// asset in its `[[CURRENCIES]]`, cannot be parsed, or could not be fetched.
//
// SEP-1 (v2.7.0, checked 2026-10-27 at github.com/stellar/stellar-protocol,
// ecosystem/sep-0001.md) defines: the file at
// https://DOMAIN/.well-known/stellar.toml, a 100KB maximum size, and
// `[[CURRENCIES]]` entries with `code` (<= 12 chars), `issuer` (G...),
// `code_template` (`?` is a single-character wildcard), and an alternative
// entry holding only `toml="https://DOMAIN/.well-known/CURRENCY.toml"`.
//
// Detect is pure: the caller fetches through internal/fetcher and passes the
// bytes and fetch time in. It emits evidence only; levels are decided by the
// verdict engine and cap at `suspicious`.
package homedomain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/fetcher"
)

const (
	Code     = "D-HOMEDOMAIN-MISMATCH"
	Category = "home_domain_mismatch"

	// MaxTOMLBytes is the SEP-1 size limit, checked again here so the parser
	// never sees more, whatever fetched the bytes.
	MaxTOMLBytes = fetcher.MaxBodyBytes

	ArtifactStellarTOML = "stellar_toml"
)

// Reasons, recorded in the "reason" fact.
const (
	ReasonFetchFailed = "fetch_failed"
	ReasonUnparsable  = "unparsable"
	ReasonNotListed   = "asset_not_listed"
)

// NotCheckedLinkedTOML is reported when the asset was not found and the file
// links out to per-currency TOML files, which this detector does not fetch.
// TODO: fetch linked currency files through internal/fetcher.
const NotCheckedLinkedTOML = "linked_currency_toml"

var (
	// ErrInvalidInput is returned for inputs that fail validation. Callers
	// treat it as "not analyzed", never as no signal.
	ErrInvalidInput = errors.New("homedomain: invalid input")
	// ErrNoHomeDomain means the issuer has no home_domain set; there is
	// nothing to compare, which is "not checked", not a mismatch.
	ErrNoHomeDomain = errors.New("homedomain: issuer has no home_domain")
)

// Fetch is the outcome of fetching the stellar.toml, as returned by
// fetcher.Fetcher.Get, plus the time of the attempt.
type Fetch struct {
	URL       string // requested URL; must equal fetcher.StellarTOMLURL(HomeDomain)
	FinalURL  string
	Status    int
	Body      []byte
	Err       error
	FetchedAt time.Time
}

// Input is one issuer/asset check.
type Input struct {
	Network    entity.Network
	Asset      string // CODE:ISSUER; the issuer is the account whose home_domain was read
	HomeDomain string // the issuer's on-chain home_domain, untrusted
	Fetch      Fetch  // ignored when HomeDomain is not a valid domain
	AsOf       time.Time
}

// Result holds at most one evidence item, plus what could not be checked.
// No evidence and no NotChecked entries means the file lists the asset.
type Result struct {
	Evidence   []detectors.Evidence
	NotChecked []string
}

// Detect compares the issuer's stellar.toml with the asset.
func Detect(in Input) (Result, error) {
	if in.AsOf.IsZero() {
		return Result{}, fmt.Errorf("%w: as_of is required", ErrInvalidInput)
	}
	key, err := entity.Canonical(in.Network, entity.Asset, in.Asset)
	if err != nil || in.Asset == "native" {
		return Result{}, fmt.Errorf("%w: asset %v", ErrInvalidInput, err)
	}
	if in.HomeDomain == "" {
		return Result{}, ErrNoHomeDomain
	}
	code, issuer, _ := strings.Cut(in.Asset, ":")
	ev := detectors.Evidence{
		Detector: Code,
		Class:    detectors.ClassDomain,
		Category: Category,
		Entity:   key,
		MaxLevel: detectors.MaxAutomatedLevel,
		Facts: []detectors.Fact{
			{Name: "asset", Value: in.Asset},
			{Name: "issuer", Value: issuer},
		},
		ObservedAt: in.AsOf.UTC(),
	}

	domain, derr := entity.NormalizeKey(entity.Domain, in.HomeDomain)
	if derr != nil {
		// Not fetchable at all (IDN, IP literal, bad shape). The raw value is
		// untrusted and is not copied into facts.
		ev.Facts = append(ev.Facts,
			detectors.Fact{Name: "reason", Value: ReasonFetchFailed},
			detectors.Fact{Name: "fetch_error", Value: "invalid_domain"})
		return Result{Evidence: []detectors.Evidence{ev}}, nil
	}
	wantURL, err := fetcher.StellarTOMLURL(domain)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	f := in.Fetch
	switch {
	case f.URL != wantURL:
		return Result{}, fmt.Errorf("%w: fetch URL does not match home_domain", ErrInvalidInput)
	case f.FetchedAt.IsZero(), f.FetchedAt.After(in.AsOf):
		return Result{}, fmt.Errorf("%w: fetched_at must be set and not after as_of", ErrInvalidInput)
	}
	fetchedAt := f.FetchedAt.UTC()
	ev.Facts = append(ev.Facts,
		detectors.Fact{Name: "home_domain", Value: domain},
		detectors.Fact{Name: "toml_url", Value: wantURL},
		detectors.Fact{Name: "fetched_at", Value: fetchedAt.Format(time.RFC3339)})

	if f.Err != nil || f.Status != http.StatusOK {
		ev.Facts = append(ev.Facts, detectors.Fact{Name: "reason", Value: ReasonFetchFailed})
		if f.Err != nil {
			ev.Facts = append(ev.Facts, detectors.Fact{Name: "fetch_error", Value: classifyFetchError(f.Err)})
		} else {
			ev.Facts = append(ev.Facts,
				detectors.Fact{Name: "fetch_error", Value: "http_status"},
				detectors.Fact{Name: "http_status", Value: strconv.Itoa(f.Status)})
		}
		return Result{Evidence: []detectors.Evidence{ev}}, nil
	}

	sum := sha256.Sum256(f.Body)
	digest := hex.EncodeToString(sum[:])
	ev.Facts = append(ev.Facts, detectors.Fact{Name: "toml_sha256", Value: digest})
	if f.FinalURL != "" && f.FinalURL != wantURL {
		ev.Facts = append(ev.Facts, detectors.Fact{Name: "final_url", Value: f.FinalURL})
	}
	artifactURL := wantURL
	if f.FinalURL != "" {
		artifactURL = f.FinalURL
	}
	ev.Artifacts = []detectors.ArtifactRef{{Kind: ArtifactStellarTOML, URL: artifactURL, SHA256: digest, FetchedAt: fetchedAt}}

	if len(f.Body) > MaxTOMLBytes {
		ev.Facts = append(ev.Facts,
			detectors.Fact{Name: "reason", Value: ReasonUnparsable},
			detectors.Fact{Name: "parse_error", Value: "too_large"})
		return Result{Evidence: []detectors.Evidence{ev}}, nil
	}
	entries, err := parseCurrencies(f.Body)
	if err != nil {
		ev.Facts = append(ev.Facts,
			detectors.Fact{Name: "reason", Value: ReasonUnparsable},
			detectors.Fact{Name: "parse_error", Value: "syntax"})
		return Result{Evidence: []detectors.Evidence{ev}}, nil
	}

	var invalid int
	var linked, codeOtherIssuer, issuerCaseDiffers bool
	for _, c := range entries {
		if c.link != "" {
			linked = true
		}
		if c.bad {
			invalid++
			continue
		}
		codeMatch := c.code == code || templateMatches(c.codeTemplate, code)
		switch {
		case codeMatch && c.issuer == issuer:
			return Result{}, nil // listed
		case codeMatch && strings.EqualFold(c.issuer, issuer):
			issuerCaseDiffers = true
		case codeMatch:
			codeOtherIssuer = true
		}
	}
	if linked {
		return Result{NotChecked: []string{NotCheckedLinkedTOML}}, nil
	}
	ev.Facts = append(ev.Facts,
		detectors.Fact{Name: "reason", Value: ReasonNotListed},
		detectors.Fact{Name: "currency_entries", Value: strconv.Itoa(len(entries))},
		detectors.Fact{Name: "invalid_entries", Value: strconv.Itoa(invalid)},
		detectors.Fact{Name: "code_listed_other_issuer", Value: strconv.FormatBool(codeOtherIssuer)},
		detectors.Fact{Name: "issuer_case_differs", Value: strconv.FormatBool(issuerCaseDiffers)})
	return Result{Evidence: []detectors.Evidence{ev}}, nil
}

// templateMatches applies a SEP-1 code_template, where `?` matches exactly
// one character. Templates are compared byte-wise; codes are ASCII.
func templateMatches(tmpl, code string) bool {
	if tmpl == "" || len(tmpl) != len(code) || len(tmpl) > 12 {
		return false
	}
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] != '?' && tmpl[i] != code[i] {
			return false
		}
	}
	return true
}

func classifyFetchError(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, fetcher.ErrTooLarge):
		return "too_large"
	case errors.Is(err, fetcher.ErrBlocked):
		return "blocked"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "unreachable"
}
