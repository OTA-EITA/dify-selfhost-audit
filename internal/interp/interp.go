// Package interp implements Docker Compose variable interpolation:
// $VAR, ${VAR}, ${VAR:-d}, ${VAR-d}, ${VAR:?e}, ${VAR?e}, ${VAR:+r}, ${VAR+r},
// nested expressions inside defaults, and $$ as a literal dollar sign.
package interp

import (
	"fmt"
	"strings"
)

// LookupFunc returns a variable's value and whether it is set.
type LookupFunc func(name string) (string, bool)

// Use records one variable reference met while interpolating.
type Use struct {
	Name string
	// Set is true when the variable was defined (possibly empty).
	Set bool
	// Value is the variable's value when Set.
	Value string
	// Fallback is true when the expression's default or alternate text
	// was used instead of the variable's own value.
	Fallback bool
}

// Interpolate expands s. Only the top-level references are reported in uses,
// in order; references inside a default that was used are reported too.
func Interpolate(s string, lookup LookupFunc) (string, []Use, error) {
	var b strings.Builder
	var uses []Use
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			b.WriteByte('$')
			continue
		}
		n := s[i+1]
		switch {
		case n == '$':
			b.WriteByte('$')
			i++
		case n == '{':
			end := matchBrace(s, i+1)
			if end < 0 {
				return "", nil, fmt.Errorf("unterminated ${ in %q", s)
			}
			v, u, err := expand(s[i+2:end], lookup)
			if err != nil {
				return "", nil, err
			}
			b.WriteString(v)
			uses = append(uses, u...)
			i = end
		case isNameStart(n):
			j := i + 1
			for j < len(s) && isNameChar(s[j]) {
				j++
			}
			name := s[i+1 : j]
			v, ok := lookup(name)
			b.WriteString(v)
			uses = append(uses, Use{Name: name, Set: ok, Value: v})
			i = j - 1
		default:
			b.WriteByte('$')
		}
	}
	return b.String(), uses, nil
}

// matchBrace returns the index of the '}' closing the '{' at open.
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '$':
			if i+1 < len(s) && s[i+1] == '$' {
				i++
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func expand(expr string, lookup LookupFunc) (string, []Use, error) {
	j := 0
	for j < len(expr) && isNameChar(expr[j]) {
		j++
	}
	name := expr[:j]
	if name == "" || !isNameStart(name[0]) {
		return "", nil, fmt.Errorf("invalid variable expression ${%s}", expr)
	}
	val, set := lookup(name)
	rest := expr[j:]
	u := Use{Name: name, Set: set, Value: val}
	if rest == "" {
		return val, []Use{u}, nil
	}

	var op string
	switch {
	case strings.HasPrefix(rest, ":-"), strings.HasPrefix(rest, ":?"), strings.HasPrefix(rest, ":+"):
		op = rest[:2]
	case strings.HasPrefix(rest, "-"), strings.HasPrefix(rest, "?"), strings.HasPrefix(rest, "+"):
		op = rest[:1]
	default:
		return "", nil, fmt.Errorf("invalid variable expression ${%s}", expr)
	}
	arg := rest[len(op):]
	nonEmpty := set && val != ""

	sub := func() (string, []Use, error) {
		v, inner, err := Interpolate(arg, lookup)
		if err != nil {
			return "", nil, err
		}
		u.Fallback = true
		return v, append([]Use{u}, inner...), nil
	}

	switch op {
	case ":-":
		if nonEmpty {
			return val, []Use{u}, nil
		}
		return sub()
	case "-":
		if set {
			return val, []Use{u}, nil
		}
		return sub()
	case ":?", "?":
		ok := nonEmpty
		if op == "?" {
			ok = set
		}
		if ok {
			return val, []Use{u}, nil
		}
		msg, _, err := Interpolate(arg, lookup)
		if err != nil {
			return "", nil, err
		}
		if msg == "" {
			msg = "required variable is missing a value"
		}
		return "", nil, fmt.Errorf("%s: %s", name, msg)
	case ":+":
		if nonEmpty {
			return sub()
		}
		return "", []Use{u}, nil
	case "+":
		if set {
			return sub()
		}
		return "", []Use{u}, nil
	}
	return "", nil, fmt.Errorf("unreachable")
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}
