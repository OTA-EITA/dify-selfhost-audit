package interp

import "testing"

func lookup(m map[string]string) LookupFunc {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestInterpolate(t *testing.T) {
	env := lookup(map[string]string{"SET": "v", "EMPTY": "", "INNER": "in"})
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"$SET", "v"},
		{"${SET}", "v"},
		{"$$SET", "$SET"},
		{"a$$", "a$"},
		{"${MISSING:-def}", "def"},
		{"${EMPTY:-def}", "def"},
		{"${EMPTY-def}", ""},
		{"${MISSING-def}", "def"},
		{"${SET:+alt}", "alt"},
		{"${EMPTY:+alt}", ""},
		{"${EMPTY+alt}", "alt"},
		{"${MISSING:-${INNER:-x}}", "in"},
		{"${MISSING:-${ALSO_MISSING:-deep}}", "deep"},
		{"redis://:${PW:-difyai123456}@redis:6379/2", "redis://:difyai123456@redis:6379/2"},
		{"${A:-lYkiYYT6owG+71oLerGzA7GXCgOT++6ovaezWAjpCjf+Sjc3ZtU+qUEi}", "lYkiYYT6owG+71oLerGzA7GXCgOT++6ovaezWAjpCjf+Sjc3ZtU+qUEi"},
		{"$1 cost", "$1 cost"},
	}
	for _, c := range cases {
		got, _, err := Interpolate(c.in, env)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUses(t *testing.T) {
	env := lookup(map[string]string{"SET": "v"})
	_, uses, _ := Interpolate("${SET:-x}", env)
	if len(uses) != 1 || !uses[0].Set || uses[0].Fallback {
		t.Fatalf("uses = %+v", uses)
	}
	_, uses, _ = Interpolate("${NOPE:-x}", env)
	if len(uses) != 1 || uses[0].Set || !uses[0].Fallback {
		t.Fatalf("uses = %+v", uses)
	}
}

func TestErrors(t *testing.T) {
	env := lookup(map[string]string{"EMPTY": ""})
	for _, in := range []string{"${NOPE:?must set}", "${EMPTY:?}", "${NOPE?x}", "${unterminated", "${:-x}", "${A*b}"} {
		if _, _, err := Interpolate(in, env); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
	if v, _, err := Interpolate("${EMPTY?x}", env); err != nil || v != "" {
		t.Errorf("${EMPTY?x} = %q, %v", v, err)
	}
}
