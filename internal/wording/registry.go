// Package wording loads the template registry, lints it, and renders public
// statements. The renderer is the only code path that may produce
// user-visible text, and it fails closed (ARCHITECTURE §4.6).
package wording

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	root "github.com/SoroSentinel/Sorosentinel-intel/wording"
)

type Status string

const (
	StatusDraft    Status = "draft"
	StatusApproved Status = "counsel_approved"
	StatusRetired  Status = "retired"
)

type AppliesTo struct {
	EntityType string `yaml:"entity_type,omitempty" json:"entity_type,omitempty"`
	Detector   string `yaml:"detector,omitempty" json:"detector,omitempty"`
	Finding    string `yaml:"finding,omitempty" json:"finding,omitempty"`
}

type Template struct {
	ID           string              `yaml:"id" json:"id"`
	AppliesTo    AppliesTo           `yaml:"applies_to" json:"applies_to"`
	SignalLevels []signal.Public     `yaml:"signal_levels" json:"signal_levels"`
	Text         string              `yaml:"text" json:"text"`
	Slots        map[string]SlotType `yaml:"slots" json:"slots"`
	Attribution  string              `yaml:"attribution" json:"attribution"`
	Status       Status              `yaml:"status" json:"status"`
}

type Attribution struct {
	ID     string `yaml:"id" json:"id"`
	Text   string `yaml:"text" json:"text"`
	Status Status `yaml:"status" json:"status"`
}

type Blocklist struct {
	Terms []string `yaml:"terms" json:"terms"`
}

// Registry is an immutable set of templates, attributions and the blocklist.
type Registry struct {
	templates    map[string]Template
	attributions map[string]Attribution
	blocked      *regexp.Regexp
}

const maxFileSize = 64 << 10

// LoadEmbedded loads the registry compiled into the binary from wording/.
func LoadEmbedded() (*Registry, error) {
	return Load(root.FS)
}

// Load reads blocklist.yaml, attribution/*.yaml and templates/*/*.yaml from
// fsys. Each template file must be named after its id.
func Load(fsys fs.FS) (*Registry, error) {
	var bl Blocklist
	if err := decodeFile(fsys, "blocklist.yaml", &bl); err != nil {
		return nil, err
	}
	attrFiles, err := fs.Glob(fsys, "attribution/*.yaml")
	if err != nil {
		return nil, err
	}
	var attrs []Attribution
	for _, f := range attrFiles {
		var a Attribution
		if err := decodeFile(fsys, f, &a); err != nil {
			return nil, err
		}
		if want := strings.TrimSuffix(path.Base(f), ".yaml"); a.ID != want {
			return nil, fmt.Errorf("%s: id %q does not match file name", f, a.ID)
		}
		attrs = append(attrs, a)
	}
	tmplFiles, err := fs.Glob(fsys, "templates/*/*.yaml")
	if err != nil {
		return nil, err
	}
	var tmpls []Template
	for _, f := range tmplFiles {
		var t Template
		if err := decodeFile(fsys, f, &t); err != nil {
			return nil, err
		}
		if want := strings.TrimSuffix(path.Base(f), ".yaml"); t.ID != want {
			return nil, fmt.Errorf("%s: id %q does not match file name", f, t.ID)
		}
		tmpls = append(tmpls, t)
	}
	return NewRegistry(tmpls, attrs, bl)
}

// NewRegistry builds a registry from in-memory definitions (used by Load and
// by the shared render vectors). It rejects duplicates; content problems are
// reported by Lint and enforced again at render time.
func NewRegistry(tmpls []Template, attrs []Attribution, bl Blocklist) (*Registry, error) {
	re, err := compileBlocklist(bl.Terms)
	if err != nil {
		return nil, err
	}
	r := &Registry{
		templates:    make(map[string]Template, len(tmpls)),
		attributions: make(map[string]Attribution, len(attrs)),
		blocked:      re,
	}
	for _, t := range tmpls {
		if _, dup := r.templates[t.ID]; dup {
			return nil, fmt.Errorf("duplicate template id %q", t.ID)
		}
		r.templates[t.ID] = t
	}
	for _, a := range attrs {
		if _, dup := r.attributions[a.ID]; dup {
			return nil, fmt.Errorf("duplicate attribution id %q", a.ID)
		}
		r.attributions[a.ID] = a
	}
	return r, nil
}

// BlockedTerms returns the distinct blocklisted terms found in text, lowercased.
func (r *Registry) BlockedTerms(text string) []string {
	seen := map[string]bool{}
	for _, m := range r.blocked.FindAllString(text, -1) {
		seen[strings.ToLower(m)] = true
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func compileBlocklist(terms []string) (*regexp.Regexp, error) {
	if len(terms) == 0 {
		return nil, fmt.Errorf("blocklist is empty")
	}
	parts := make([]string, 0, len(terms))
	for _, term := range terms {
		words := strings.Fields(strings.ToLower(term))
		if len(words) == 0 {
			return nil, fmt.Errorf("blocklist has an empty term")
		}
		for i, w := range words {
			words[i] = regexp.QuoteMeta(w)
		}
		// One optional extra letter covers doubled consonants ("scammed"); errs toward blocking.
		parts = append(parts, strings.Join(words, `[\s\-_]+`)+`[a-z]?(?:s|es|ed|ly|ing|er|ers)?`)
	}
	return regexp.Compile(`(?i)\b(?:` + strings.Join(parts, "|") + `)\b`)
}

func decodeFile(fsys fs.FS, name string, v any) error {
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	if len(raw) > maxFileSize {
		return fmt.Errorf("%s: larger than %d bytes", name, maxFileSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
