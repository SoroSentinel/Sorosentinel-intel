package wording

import (
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

// ErrorCode values are shared with Guard's renderer through wording/vectors.
type ErrorCode string

const (
	ErrUnknownTemplate  ErrorCode = "unknown_template"
	ErrNotApproved      ErrorCode = "not_approved"
	ErrInvalidTemplate  ErrorCode = "invalid_template"
	ErrLevelNotAllowed  ErrorCode = "level_not_allowed"
	ErrMissingSlot      ErrorCode = "missing_slot"
	ErrUnexpectedSlot   ErrorCode = "unexpected_slot"
	ErrSlotTypeMismatch ErrorCode = "slot_type_mismatch"
	ErrInvalidSlotValue ErrorCode = "invalid_slot_value"
	ErrBlockedTerm      ErrorCode = "blocked_term"
)

// Error means rendering failed closed: show structured facts, never prose.
type Error struct {
	Code   ErrorCode
	Detail string
}

func (e *Error) Error() string { return "wording: " + string(e.Code) + ": " + e.Detail }

type Config struct {
	MethodologyURL string
	ReviewURL      string
}

type Renderer struct {
	reg *Registry
	cfg Config
}

func NewRenderer(reg *Registry, cfg Config) (*Renderer, error) {
	for _, u := range []string{cfg.MethodologyURL, cfg.ReviewURL} {
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || hasUnsafeRune(u) {
			return nil, &Error{Code: ErrInvalidSlotValue, Detail: "config URLs must be plain https URLs"}
		}
	}
	return &Renderer{reg: reg, cfg: cfg}, nil
}

// Request carries everything a statement needs. AsOf is supplied by the
// caller (never read from the wall clock here) so output is reproducible.
type Request struct {
	TemplateID string
	// Level is used by entity-signal templates; Severity by finding templates.
	Level          signal.Public
	Severity       Severity
	AsOf           time.Time
	Method         string
	RulesetVersion string
	Slots          map[string]Value
}

type Statement struct {
	TemplateID     string
	SignalLevel    signal.Public
	Severity       Severity
	Text           string
	Attribution    string
	Facts          map[string]string
	AsOf           time.Time
	Method         string
	RulesetVersion string
	MethodologyURL string
	ReviewURL      string
}

var (
	methodRe  = regexp.MustCompile(`^[A-Z][A-Z0-9-]{1,63}$`)
	rulesetRe = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]+$`)
)

// Render produces a public statement, or an *Error. On error the caller must
// fall back to Facts(req) with no prose.
func (r *Renderer) Render(req Request) (Statement, error) {
	t, ok := r.reg.templates[req.TemplateID]
	if !ok {
		return Statement{}, &Error{Code: ErrUnknownTemplate, Detail: req.TemplateID}
	}
	if t.Status != StatusApproved {
		return Statement{}, &Error{Code: ErrNotApproved, Detail: "template " + t.ID + " is " + string(t.Status)}
	}
	if p := r.reg.lintTemplate(t); len(p) > 0 {
		return Statement{}, &Error{Code: ErrInvalidTemplate, Detail: strings.Join(p, "; ")}
	}
	a := r.reg.attributions[t.Attribution]
	if a.Status != StatusApproved {
		return Statement{}, &Error{Code: ErrNotApproved, Detail: "attribution " + a.ID + " is " + string(a.Status)}
	}
	if p := r.reg.lintAttribution(a); len(p) > 0 {
		return Statement{}, &Error{Code: ErrInvalidTemplate, Detail: strings.Join(p, "; ")}
	}
	if len(t.SignalLevels) > 0 {
		if !slices.Contains(t.SignalLevels, req.Level) {
			return Statement{}, &Error{Code: ErrLevelNotAllowed, Detail: string(req.Level)}
		}
	} else if !slices.Contains(t.Severities, req.Severity) {
		return Statement{}, &Error{Code: ErrLevelNotAllowed, Detail: string(req.Severity)}
	}

	asOf, err := Timestamp(req.AsOf)
	if err != nil {
		return Statement{}, &Error{Code: ErrMissingSlot, Detail: "as_of"}
	}
	if !methodRe.MatchString(req.Method) {
		return Statement{}, &Error{Code: ErrInvalidSlotValue, Detail: "method"}
	}
	if !rulesetRe.MatchString(req.RulesetVersion) {
		return Statement{}, &Error{Code: ErrInvalidSlotValue, Detail: "ruleset_version"}
	}

	declared := sortedKeys(t.Slots)
	for _, name := range declared {
		v, ok := req.Slots[name]
		if !ok {
			return Statement{}, &Error{Code: ErrMissingSlot, Detail: name}
		}
		if v.typ != t.Slots[name] {
			return Statement{}, &Error{Code: ErrSlotTypeMismatch, Detail: name}
		}
	}
	for _, name := range sortedKeys(req.Slots) {
		if _, ok := t.Slots[name]; !ok {
			return Statement{}, &Error{Code: ErrUnexpectedSlot, Detail: name}
		}
	}

	display := map[string]string{
		"as_of":           asOf.display,
		"method":          req.Method,
		"ruleset_version": req.RulesetVersion,
		"methodology_url": r.cfg.MethodologyURL,
		"review_url":      r.cfg.ReviewURL,
	}
	for name, v := range req.Slots {
		display[name] = v.display
	}
	text, err := fill(t.Text, display)
	if err != nil {
		return Statement{}, err
	}
	attr, err := fill(a.Text, display)
	if err != nil {
		return Statement{}, err
	}
	// Second layer: slot values (e.g. attacker-chosen domains) can carry blocked terms.
	if terms := r.reg.BlockedTerms(text + "\n" + attr); len(terms) > 0 {
		return Statement{}, &Error{Code: ErrBlockedTerm, Detail: strings.Join(terms, ", ")}
	}

	return Statement{
		TemplateID:     t.ID,
		SignalLevel:    req.Level,
		Severity:       req.Severity,
		Text:           text,
		Attribution:    attr,
		Facts:          Facts(req),
		AsOf:           req.AsOf.UTC(),
		Method:         req.Method,
		RulesetVersion: req.RulesetVersion,
		MethodologyURL: r.cfg.MethodologyURL,
		ReviewURL:      r.cfg.ReviewURL,
	}, nil
}

// Facts returns the structured slot values of req. It is the fail-closed
// output when Render returns an error.
func Facts(req Request) map[string]string {
	out := make(map[string]string, len(req.Slots)+1)
	for name, v := range req.Slots {
		out[name] = v.fact
	}
	if !req.AsOf.IsZero() {
		out["as_of"] = req.AsOf.UTC().Format(time.RFC3339)
	}
	return out
}

func fill(text string, values map[string]string) (string, error) {
	var b strings.Builder
	var missing string
	err := walkText(text,
		func(lit string) { b.WriteString(lit) },
		func(name string) {
			v, ok := values[name]
			if !ok && missing == "" {
				missing = name
			}
			b.WriteString(v)
		})
	if err != nil {
		return "", &Error{Code: ErrInvalidTemplate, Detail: err.Error()}
	}
	if missing != "" {
		return "", &Error{Code: ErrMissingSlot, Detail: missing}
	}
	return b.String(), nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
