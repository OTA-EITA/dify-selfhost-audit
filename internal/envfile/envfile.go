// Package envfile parses dotenv files the way Docker Compose reads them
// (KEY=VALUE lines, comments, optional quotes, optional "export " prefix).
package envfile

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/OTA-EITA/dify-selfhost-audit/internal/interp"
)

// Entry is one assignment read from an env file.
type Entry struct {
	Key   string
	Value string
	File  string
	Line  int
}

// Env is an ordered set of variables where a later assignment wins.
type Env struct {
	entries map[string]Entry
	order   []string
}

// New returns an empty Env.
func New() *Env {
	return &Env{entries: map[string]Entry{}}
}

// Set stores an entry, replacing any earlier value for the same key.
func (e *Env) Set(en Entry) {
	if _, ok := e.entries[en.Key]; !ok {
		e.order = append(e.order, en.Key)
	}
	e.entries[en.Key] = en
}

// Get returns the entry for key.
func (e *Env) Get(key string) (Entry, bool) {
	en, ok := e.entries[key]
	return en, ok
}

// Lookup returns only the value, for use with interp.
func (e *Env) Lookup(key string) (string, bool) {
	en, ok := e.entries[key]
	return en.Value, ok
}

// Keys returns the keys in first-seen order.
func (e *Env) Keys() []string {
	return append([]string(nil), e.order...)
}

// Merge copies every entry of other into e (other wins).
func (e *Env) Merge(other *Env) {
	for _, k := range other.order {
		e.Set(other.entries[k])
	}
}

// Clone returns a copy of e.
func (e *Env) Clone() *Env {
	c := New()
	c.Merge(e)
	return c
}

// ParseFile reads path. Values are interpolated against variables defined
// earlier in the same file and in base (base may be nil), like Compose does.
func ParseFile(path string, base *Env) (*Env, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, path, base)
}

// Parse reads dotenv content from r. name is used for locations.
func Parse(r io.Reader, name string, base *Env) (*Env, error) {
	out := New()
	scope := New()
	if base != nil {
		scope.Merge(base)
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		start := lineNo
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			// A bare name means "take it from the shell"; we never read the
			// shell, so it is ignored.
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		if !validKey(key) {
			return nil, fmt.Errorf("%s:%d: invalid variable name %q", name, start, key)
		}
		raw := strings.TrimLeft(trimmed[eq+1:], " \t")

		var value string
		switch {
		case strings.HasPrefix(raw, `"`) || strings.HasPrefix(raw, `'`):
			q := raw[0]
			body := raw[1:]
			// Quoted values may span lines.
			for !hasClosingQuote(body, q) {
				if !sc.Scan() {
					return nil, fmt.Errorf("%s:%d: unterminated quoted value for %s", name, start, key)
				}
				lineNo++
				body += "\n" + strings.TrimRight(sc.Text(), "\r")
			}
			end := closingQuote(body, q)
			inner := body[:end]
			if q == '"' {
				inner = unescapeDouble(inner)
				v, _, err := interp.Interpolate(inner, scope.Lookup)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: %v", name, start, err)
				}
				value = v
			} else {
				value = inner
			}
		default:
			if i := inlineComment(raw); i >= 0 {
				raw = raw[:i]
			}
			raw = strings.TrimRight(raw, " \t")
			v, _, err := interp.Interpolate(raw, scope.Lookup)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", name, start, err)
			}
			value = v
		}
		en := Entry{Key: key, Value: value, File: name, Line: start}
		out.Set(en)
		scope.Set(en)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	return out, nil
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i, c := range k {
		switch {
		case c == '_' || c == '.' || c == '-':
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func closingQuote(s string, q byte) int {
	for i := 0; i < len(s); i++ {
		if q == '"' && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == q {
			return i
		}
	}
	return -1
}

func hasClosingQuote(s string, q byte) bool { return closingQuote(s, q) >= 0 }

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '"', '\\':
				b.WriteByte(s[i+1])
			default:
				b.WriteByte('\\')
				b.WriteByte(s[i+1])
			}
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// inlineComment returns the index of a " #" comment in an unquoted value.
func inlineComment(s string) int {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return i
		}
	}
	return -1
}
