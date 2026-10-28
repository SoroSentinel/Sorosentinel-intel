package api

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/assetlookalike"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/detectors/homedomain"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
)

// Template ids per detector outcome (wording/templates/en).
const (
	tmplLookalike          = "asset.lookalike.v1"
	tmplLookalikeSimilar   = "asset.lookalike_similar.v1"
	tmplHomeDomainMismatch = "domain.homedomain_mismatch.v1"
	tmplHomeDomainNoFile   = "domain.homedomain_unavailable.v1"
)

// evidencePayload is the part of a stored payload (internal/pipeline) read here.
type evidencePayload struct {
	Facts []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"facts"`
}

func (p evidencePayload) fact(name string) string {
	for _, f := range p.Facts {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// statementRequests picks a template for each evidence row (newest first; one
// request per template) and fills its slots from the stored detector facts.
// Every slot value goes through wording.NewValue, so only typed, validated
// values become facts. A value that does not validate is left out and the
// renderer then fails closed on the missing slot. Unknown detectors and
// unreadable payloads contribute nothing.
func statementRequests(level signal.Public, asOf time.Time, ruleset string, ev []store.LookupEvidence) []wording.Request {
	var out []wording.Request
	seen := map[string]bool{}
	for _, e := range ev {
		var p evidencePayload
		if json.Unmarshal(e.Payload, &p) != nil {
			continue
		}
		tmpl, slots := templateFor(e.Detector, p)
		if tmpl == "" || seen[tmpl] {
			continue
		}
		seen[tmpl] = true
		req := wording.Request{
			TemplateID: tmpl, Level: level, AsOf: asOf, Method: e.Detector, RulesetVersion: ruleset,
			Slots: map[string]wording.Value{},
		}
		for name, sv := range slots {
			if v, err := wording.NewValue(sv.typ, sv.raw); err == nil {
				req.Slots[name] = v
			}
		}
		out = append(out, req)
	}
	return out
}

type slotValue struct {
	typ wording.SlotType
	raw string
}

func templateFor(detector string, p evidencePayload) (string, map[string]slotValue) {
	switch detector {
	case assetlookalike.Code:
		// known_assets lists the reference assets as CODE:ISSUER, sorted; the
		// first one names the asset this code resembles.
		known, _, _ := strings.Cut(p.fact("known_assets"), ",")
		slots := map[string]slotValue{}
		if known != "" {
			slots["known_asset"] = slotValue{wording.SlotAssetKey, known}
		}
		switch p.fact("match") {
		case assetlookalike.MatchExact:
			if _, issuer, ok := strings.Cut(known, ":"); ok {
				slots["known_issuer"] = slotValue{wording.SlotAccount, issuer}
			}
			return tmplLookalike, slots
		case assetlookalike.MatchConfusable, assetlookalike.MatchAffix:
			return tmplLookalikeSimilar, slots
		}
	case homedomain.Code:
		slots := map[string]slotValue{
			"issuer": {wording.SlotAccount, p.fact("issuer")},
			"asset":  {wording.SlotAssetKey, p.fact("asset")},
		}
		if d := p.fact("home_domain"); d != "" {
			slots["home_domain"] = slotValue{wording.SlotDomain, d}
		}
		switch p.fact("reason") {
		case homedomain.ReasonNotListed:
			return tmplHomeDomainMismatch, slots
		case homedomain.ReasonFetchFailed, homedomain.ReasonUnparsable:
			return tmplHomeDomainNoFile, slots
		}
	}
	return "", nil
}
