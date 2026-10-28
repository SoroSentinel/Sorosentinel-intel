package homedomain

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This is a small strict reader for the subset of TOML needed to read the
// SEP-1 `[[CURRENCIES]]` list. It tokenizes all of TOML's value syntax so that
// any well-formed stellar.toml can be skipped through, but it only builds
// values for currency entries. Anything it cannot tokenize is a parse error,
// which the detector reports as `unparsable`, never as "listed".
//
// Known gaps against full TOML 1.0 (all fail toward an error, not a match):
// dotted keys that redefine a [table] are not cross-checked, and inline
// tables may span lines (TOML 1.1 behaviour).

var errSyntax = errors.New("toml: syntax error")

const (
	maxDepth      = 32
	maxCurrencies = 4096
)

type kind uint8

const (
	kString kind = iota + 1
	kArray
	kTable
	kOther // number, boolean, date-time
)

type value struct {
	kind   kind
	str    string
	items  []value
	fields map[string]value // inline tables; dotted keys joined with "."
}

// currency holds the SEP-1 fields the detector reads. A field that is
// present with a non-string type marks the entry as bad.
type currency struct {
	code, issuer, codeTemplate, link string
	bad                              bool
}

type tomlParser struct {
	b     []byte
	i     int
	depth int
}

// parseCurrencies returns the `[[CURRENCIES]]` entries of a stellar.toml, in
// file order. Both the array-of-tables form and a root-level
// `CURRENCIES = [{...}]` array are read.
func parseCurrencies(b []byte) ([]currency, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")) // UTF-8 byte order mark
	if !utf8.Valid(b) {
		return nil, errSyntax
	}
	for i, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return nil, errSyntax
		}
		if c == '\r' && (i+1 >= len(b) || b[i+1] != '\n') {
			return nil, errSyntax
		}
	}
	p := &tomlParser{b: b}

	var out []currency
	rootKeys := map[string]bool{}
	tables := map[string]bool{}      // standard [table] headers
	arrayTables := map[string]bool{} // [[table]] names
	keys := rootKeys                 // keys of the current table
	var cur *currency                // current [[CURRENCIES]] entry, if any
	atRoot := true

	for {
		p.skipBlank()
		if p.eof() {
			break
		}
		if p.peek() == '[' {
			arr := p.has("[[")
			if arr {
				p.i += 2
			} else {
				p.i++
			}
			path, err := p.keyPath()
			if err != nil {
				return nil, err
			}
			closing := "]"
			if arr {
				closing = "]]"
			}
			p.skipSpace()
			if !p.has(closing) {
				return nil, errSyntax
			}
			p.i += len(closing)
			if err := p.endOfLine(); err != nil {
				return nil, err
			}
			name := strings.Join(path, ".")
			atRoot, cur, keys = false, nil, map[string]bool{}
			if arr {
				if tables[name] || (name == "CURRENCIES" && rootKeys["CURRENCIES"]) {
					return nil, errSyntax
				}
				arrayTables[name] = true
				// Sub-tables belong to one element; the next element starts fresh.
				for t := range tables {
					if strings.HasPrefix(t, name+".") {
						delete(tables, t)
					}
				}
				for t := range arrayTables {
					if strings.HasPrefix(t, name+".") {
						delete(arrayTables, t)
					}
				}
				if name == "CURRENCIES" {
					if len(out) >= maxCurrencies {
						return nil, errSyntax
					}
					out = append(out, currency{})
					cur = &out[len(out)-1]
				}
			} else {
				if tables[name] || arrayTables[name] || (len(path) == 1 && rootKeys[name]) {
					return nil, errSyntax
				}
				tables[name] = true
			}
			continue
		}

		path, err := p.keyPath()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.eof() || p.peek() != '=' {
			return nil, errSyntax
		}
		p.i++
		p.skipSpace()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if err := p.endOfLine(); err != nil {
			return nil, err
		}
		k := strings.Join(path, ".")
		if keys[k] {
			return nil, errSyntax
		}
		keys[k] = true
		switch {
		case atRoot && k == "CURRENCIES":
			if arrayTables["CURRENCIES"] || tables["CURRENCIES"] {
				return nil, errSyntax
			}
			if v.kind != kArray {
				// Valid TOML, wrong SEP-1 type: one unusable entry.
				out = append(out, currency{bad: true})
				continue
			}
			for _, it := range v.items {
				if len(out) >= maxCurrencies {
					return nil, errSyntax
				}
				c := currency{bad: it.kind != kTable}
				for fk, fv := range it.fields {
					c.set(fk, fv)
				}
				out = append(out, c)
			}
		case cur != nil:
			cur.set(k, v)
		}
	}
	return out, nil
}

func (c *currency) set(key string, v value) {
	var dst *string
	switch key {
	case "code":
		dst = &c.code
	case "issuer":
		dst = &c.issuer
	case "code_template":
		dst = &c.codeTemplate
	case "toml":
		dst = &c.link
	default:
		return
	}
	if v.kind != kString {
		c.bad = true
		return
	}
	*dst = v.str
}

func (p *tomlParser) eof() bool         { return p.i >= len(p.b) }
func (p *tomlParser) peek() byte        { return p.b[p.i] }
func (p *tomlParser) has(s string) bool { return strings.HasPrefix(string(p.b[p.i:]), s) }

func (p *tomlParser) skipSpace() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.i++
	}
}

func (p *tomlParser) skipComment() {
	if !p.eof() && p.peek() == '#' {
		for !p.eof() && p.peek() != '\n' {
			p.i++
		}
	}
}

// skipBlank skips whitespace, comments and newlines.
func (p *tomlParser) skipBlank() {
	for {
		p.skipSpace()
		p.skipComment()
		if p.eof() {
			return
		}
		switch {
		case p.peek() == '\n':
			p.i++
		case p.has("\r\n"):
			p.i += 2
		default:
			return
		}
	}
}

// endOfLine requires only whitespace and an optional comment before the
// next newline or the end of input.
func (p *tomlParser) endOfLine() error {
	p.skipSpace()
	p.skipComment()
	switch {
	case p.eof():
	case p.peek() == '\n':
		p.i++
	case p.has("\r\n"):
		p.i += 2
	default:
		return errSyntax
	}
	return nil
}

func isBare(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// keyPath reads a possibly dotted key: bare, "basic" or 'literal' segments.
func (p *tomlParser) keyPath() ([]string, error) {
	var path []string
	for {
		p.skipSpace()
		if p.eof() {
			return nil, errSyntax
		}
		var seg string
		var err error
		switch c := p.peek(); {
		case c == '"':
			if p.has(`"""`) {
				return nil, errSyntax
			}
			seg, err = p.basicString()
		case c == '\'':
			if p.has("'''") {
				return nil, errSyntax
			}
			seg, err = p.literalString()
		case isBare(c):
			start := p.i
			for !p.eof() && isBare(p.peek()) {
				p.i++
			}
			seg = string(p.b[start:p.i])
		default:
			return nil, errSyntax
		}
		if err != nil {
			return nil, err
		}
		path = append(path, seg)
		p.skipSpace()
		if p.eof() || p.peek() != '.' {
			return path, nil
		}
		p.i++
	}
}

func (p *tomlParser) value() (value, error) {
	if p.eof() {
		return value{}, errSyntax
	}
	switch c := p.peek(); {
	case p.has(`"""`):
		s, err := p.multiBasic()
		return value{kind: kString, str: s}, err
	case p.has("'''"):
		s, err := p.multiLiteral()
		return value{kind: kString, str: s}, err
	case c == '"':
		s, err := p.basicString()
		return value{kind: kString, str: s}, err
	case c == '\'':
		s, err := p.literalString()
		return value{kind: kString, str: s}, err
	case c == '[':
		return p.array()
	case c == '{':
		return p.inlineTable()
	default:
		return p.bare()
	}
}

func (p *tomlParser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return errSyntax
	}
	return nil
}

func (p *tomlParser) array() (value, error) {
	if err := p.enter(); err != nil {
		return value{}, err
	}
	defer func() { p.depth-- }()
	p.i++ // [
	v := value{kind: kArray}
	for {
		p.skipBlank()
		if p.eof() {
			return value{}, errSyntax
		}
		if p.peek() == ']' {
			p.i++
			return v, nil
		}
		it, err := p.value()
		if err != nil {
			return value{}, err
		}
		v.items = append(v.items, it)
		p.skipBlank()
		if p.eof() {
			return value{}, errSyntax
		}
		switch p.peek() {
		case ',':
			p.i++
		case ']':
			p.i++
			return v, nil
		default:
			return value{}, errSyntax
		}
	}
}

func (p *tomlParser) inlineTable() (value, error) {
	if err := p.enter(); err != nil {
		return value{}, err
	}
	defer func() { p.depth-- }()
	p.i++ // {
	v := value{kind: kTable, fields: map[string]value{}}
	p.skipBlank()
	if !p.eof() && p.peek() == '}' {
		p.i++
		return v, nil
	}
	for {
		p.skipBlank()
		path, err := p.keyPath()
		if err != nil {
			return value{}, err
		}
		p.skipSpace()
		if p.eof() || p.peek() != '=' {
			return value{}, errSyntax
		}
		p.i++
		p.skipSpace()
		fv, err := p.value()
		if err != nil {
			return value{}, err
		}
		k := strings.Join(path, ".")
		if _, dup := v.fields[k]; dup {
			return value{}, errSyntax
		}
		v.fields[k] = fv
		p.skipBlank()
		if p.eof() {
			return value{}, errSyntax
		}
		switch p.peek() {
		case ',':
			p.i++
		case '}':
			p.i++
			return v, nil
		default:
			return value{}, errSyntax
		}
	}
}

func isBareValue(c byte) bool {
	return isBare(c) || c == '+' || c == '.' || c == ':'
}

// bare reads a number, boolean or date-time. It checks shape loosely; exact
// numeric and date grammar does not matter for the fields the detector reads.
func (p *tomlParser) bare() (value, error) {
	start := p.i
	for !p.eof() && isBareValue(p.peek()) {
		p.i++
		// "1979-05-27 07:32:00Z": a date followed by a space and a time.
		if p.i-start == 10 && p.i+1 < len(p.b) && p.b[p.i] == ' ' && isDigit(p.b[p.i+1]) && isDate(p.b[start:p.i]) {
			p.i++
		}
	}
	tok := string(p.b[start:p.i])
	if tok == "" {
		return value{}, errSyntax
	}
	switch tok {
	case "true", "false", "inf", "+inf", "-inf", "nan", "+nan", "-nan":
		return value{kind: kOther}, nil
	}
	if c := tok[0]; !isDigit(c) && c != '+' && c != '-' {
		return value{}, errSyntax
	}
	return value{kind: kOther}, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isDate(b []byte) bool {
	if len(b) != 10 || b[4] != '-' || b[7] != '-' {
		return false
	}
	for _, i := range []int{0, 1, 2, 3, 5, 6, 8, 9} {
		if !isDigit(b[i]) {
			return false
		}
	}
	return true
}

func (p *tomlParser) literalString() (string, error) {
	p.i++ // '
	start := p.i
	for !p.eof() {
		switch p.peek() {
		case '\'':
			s := string(p.b[start:p.i])
			p.i++
			return s, nil
		case '\n', '\r':
			return "", errSyntax
		}
		p.i++
	}
	return "", errSyntax
}

func (p *tomlParser) multiLiteral() (string, error) {
	p.i += 3
	p.skipOneNewline()
	start := p.i
	for !p.eof() {
		if p.has("'''") {
			end := p.i
			p.i += 3
			// Up to two extra quotes before the delimiter belong to the content.
			for n := 0; n < 2 && !p.eof() && p.peek() == '\''; n++ {
				p.i++
				end++
			}
			return string(p.b[start:end]), nil
		}
		p.i++
	}
	return "", errSyntax
}

func (p *tomlParser) skipOneNewline() {
	switch {
	case !p.eof() && p.peek() == '\n':
		p.i++
	case p.has("\r\n"):
		p.i += 2
	}
}

func (p *tomlParser) basicString() (string, error) {
	p.i++ // "
	var sb strings.Builder
	for !p.eof() {
		c := p.peek()
		switch c {
		case '"':
			p.i++
			return sb.String(), nil
		case '\n', '\r':
			return "", errSyntax
		case '\\':
			if err := p.escape(&sb); err != nil {
				return "", err
			}
			continue
		}
		sb.WriteByte(c)
		p.i++
	}
	return "", errSyntax
}

func (p *tomlParser) multiBasic() (string, error) {
	p.i += 3
	p.skipOneNewline()
	var sb strings.Builder
	for !p.eof() {
		if p.has(`"""`) {
			p.i += 3
			for n := 0; n < 2 && !p.eof() && p.peek() == '"'; n++ {
				sb.WriteByte('"')
				p.i++
			}
			return sb.String(), nil
		}
		c := p.peek()
		if c == '\\' {
			// Line-ending backslash trims the newline and following whitespace.
			j := p.i + 1
			for j < len(p.b) && (p.b[j] == ' ' || p.b[j] == '\t') {
				j++
			}
			if j < len(p.b) && (p.b[j] == '\n' || p.b[j] == '\r') {
				p.i = j
				for !p.eof() && strings.IndexByte(" \t\r\n", p.peek()) >= 0 {
					p.i++
				}
				continue
			}
			if err := p.escape(&sb); err != nil {
				return "", err
			}
			continue
		}
		sb.WriteByte(c)
		p.i++
	}
	return "", errSyntax
}

// escape decodes one escape sequence starting at a backslash.
func (p *tomlParser) escape(sb *strings.Builder) error {
	p.i++ // backslash
	if p.eof() {
		return errSyntax
	}
	c := p.peek()
	p.i++
	switch c {
	case 'b':
		sb.WriteByte('\b')
	case 't':
		sb.WriteByte('\t')
	case 'n':
		sb.WriteByte('\n')
	case 'f':
		sb.WriteByte('\f')
	case 'r':
		sb.WriteByte('\r')
	case 'e':
		sb.WriteByte(0x1b)
	case '"':
		sb.WriteByte('"')
	case '\\':
		sb.WriteByte('\\')
	case 'x', 'u', 'U':
		n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
		if p.i+n > len(p.b) {
			return errSyntax
		}
		r, err := strconv.ParseUint(string(p.b[p.i:p.i+n]), 16, 32)
		if err != nil || !utf8.ValidRune(rune(r)) {
			return errSyntax
		}
		p.i += n
		sb.WriteRune(rune(r))
	default:
		return errSyntax
	}
	return nil
}
