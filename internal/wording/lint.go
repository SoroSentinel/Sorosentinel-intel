package wording

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Reserved slots are filled by the renderer from the request and config.
// Templates may use them but must not declare them.
var reservedSlots = map[string]bool{
	"as_of":           true,
	"method":          true,
	"ruleset_version": true,
	"methodology_url": true,
	"review_url":      true,
}

// Every attribution must carry these (PRD §5.1 L4).
var requiredAttributionSlots = []string{"as_of", "method", "methodology_url", "review_url"}

var (
	templateIDRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*\.v[0-9]+$`)
	slotNameRe   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// Problem is one lint finding.
type Problem struct {
	Where string
	Msg   string
}

func (p Problem) String() string { return p.Where + ": " + p.Msg }

// Lint checks every template and attribution. An empty result means the
// registry is fit to render (approval status is checked at render time).
func (r *Registry) Lint() []Problem {
	var out []Problem
	ids := make([]string, 0, len(r.templates))
	for id := range r.templates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, msg := range r.lintTemplate(r.templates[id]) {
			out = append(out, Problem{Where: "template " + id, Msg: msg})
		}
	}
	ids = ids[:0]
	for id := range r.attributions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, msg := range r.lintAttribution(r.attributions[id]) {
			out = append(out, Problem{Where: "attribution " + id, Msg: msg})
		}
	}
	return out
}

func (r *Registry) lintTemplate(t Template) []string {
	var p []string
	if !templateIDRe.MatchString(t.ID) {
		p = append(p, "id must look like name.part.vN")
	}
	p = append(p, lintStatus(t.Status)...)
	if len(t.SignalLevels) == 0 {
		p = append(p, "signal_levels is empty")
	}
	for _, l := range t.SignalLevels {
		if !l.Valid() {
			p = append(p, fmt.Sprintf("unknown signal level %q", l))
		}
	}
	if _, ok := r.attributions[t.Attribution]; !ok {
		p = append(p, fmt.Sprintf("attribution %q not found", t.Attribution))
	}
	for name, typ := range t.Slots {
		if reservedSlots[name] {
			p = append(p, fmt.Sprintf("slot %q is reserved and must not be declared", name))
		}
		if !slotNameRe.MatchString(name) {
			p = append(p, fmt.Sprintf("bad slot name %q", name))
		}
		if !typ.valid() {
			p = append(p, fmt.Sprintf("slot %q has unknown type %q", name, typ))
		}
	}
	used, textProblems := r.lintText(t.Text)
	p = append(p, textProblems...)
	for name := range used {
		if _, ok := t.Slots[name]; !ok && !reservedSlots[name] {
			p = append(p, fmt.Sprintf("placeholder {%s} is not declared in slots", name))
		}
	}
	for name := range t.Slots {
		if !used[name] {
			p = append(p, fmt.Sprintf("slot %q is declared but unused", name))
		}
	}
	sort.Strings(p)
	return p
}

func (r *Registry) lintAttribution(a Attribution) []string {
	p := lintStatus(a.Status)
	used, textProblems := r.lintText(a.Text)
	p = append(p, textProblems...)
	for name := range used {
		if !reservedSlots[name] {
			p = append(p, fmt.Sprintf("placeholder {%s} is not a reserved slot", name))
		}
	}
	for _, name := range requiredAttributionSlots {
		if !used[name] {
			p = append(p, fmt.Sprintf("missing required placeholder {%s}", name))
		}
	}
	if !strings.Contains(a.Text, "not a determination of intent or wrongdoing") {
		p = append(p, `missing "not a determination of intent or wrongdoing"`)
	}
	sort.Strings(p)
	return p
}

// lintText checks text shared rules: non-empty, printable ASCII only (blocks
// homoglyph evasion of the blocklist), well-formed placeholders, no blocked terms.
func (r *Registry) lintText(text string) (map[string]bool, []string) {
	var p []string
	if strings.TrimSpace(text) == "" {
		p = append(p, "text is empty")
	}
	for i := 0; i < len(text); i++ {
		if c := text[i]; c < 0x20 && c != '\n' || c >= 0x7f {
			p = append(p, "text must be printable ASCII")
			break
		}
	}
	used, err := placeholders(text)
	if err != nil {
		p = append(p, err.Error())
	}
	if terms := r.BlockedTerms(text); len(terms) > 0 {
		p = append(p, "blocked terms: "+strings.Join(terms, ", "))
	}
	return used, p
}

// LintDocument checks free-standing public prose (for example the methodology
// page) for blocked terms, reporting each hit by line.
func (r *Registry) LintDocument(name, text string) []Problem {
	var out []Problem
	for i, line := range strings.Split(text, "\n") {
		if terms := r.BlockedTerms(line); len(terms) > 0 {
			out = append(out, Problem{
				Where: fmt.Sprintf("%s:%d", name, i+1),
				Msg:   "blocked terms: " + strings.Join(terms, ", "),
			})
		}
	}
	return out
}

func lintStatus(s Status) []string {
	switch s {
	case StatusDraft, StatusApproved, StatusRetired:
		return nil
	}
	return []string{fmt.Sprintf("unknown status %q", s)}
}

// placeholders returns the set of {name} placeholders in text.
func placeholders(text string) (map[string]bool, error) {
	used := map[string]bool{}
	err := walkText(text, func(lit string) {}, func(name string) { used[name] = true })
	return used, err
}

// walkText splits text into literal runs and placeholder names.
func walkText(text string, lit func(string), slot func(string)) error {
	for len(text) > 0 {
		open := strings.IndexAny(text, "{}")
		if open < 0 {
			lit(text)
			return nil
		}
		if text[open] == '}' {
			return fmt.Errorf("unmatched '}'")
		}
		lit(text[:open])
		end := strings.IndexAny(text[open+1:], "{}")
		if end < 0 || text[open+1+end] != '}' {
			return fmt.Errorf("unmatched '{'")
		}
		name := text[open+1 : open+1+end]
		if !slotNameRe.MatchString(name) {
			return fmt.Errorf("bad placeholder {%s}", name)
		}
		slot(name)
		text = text[open+end+2:]
	}
	return nil
}
