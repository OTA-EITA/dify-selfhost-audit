package envfile

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	src := `# comment
A=1
export B = two
C="quoted # not a comment"
D='single ${A}'
E=unquoted # trailing comment
F=x#y
G="multi
line"
H=
I=${VECTOR_STORE:-weaviate},${A},collab
J="esc \"q\" \n"
K
`
	e, err := Parse(strings.NewReader(src), "t.env", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"A": "1", "B": "two", "C": "quoted # not a comment", "D": "single ${A}",
		"E": "unquoted", "F": "x#y", "G": "multi\nline", "H": "", "I": "weaviate,1,collab",
		"J": "esc \"q\" \n",
	}
	for k, v := range want {
		got, ok := e.Lookup(k)
		if !ok || got != v {
			t.Errorf("%s = %q (set=%v), want %q", k, got, ok, v)
		}
	}
	if _, ok := e.Lookup("K"); ok {
		t.Error("bare K should be ignored")
	}
	if en, _ := e.Get("E"); en.Line != 6 || en.File != "t.env" {
		t.Errorf("E location = %s:%d", en.File, en.Line)
	}
	if en, _ := e.Get("H"); en.Line != 10 {
		t.Errorf("H line = %d, want 10 (after a two-line value)", en.Line)
	}
}

func TestLaterWins(t *testing.T) {
	a, _ := Parse(strings.NewReader("X=1\nY=1\n"), "a", nil)
	b, _ := Parse(strings.NewReader("X=2\n"), "b", a)
	m := New()
	m.Merge(a)
	m.Merge(b)
	if v, _ := m.Lookup("X"); v != "2" {
		t.Errorf("X = %q", v)
	}
	if en, _ := m.Get("X"); en.File != "b" {
		t.Errorf("X from %s", en.File)
	}
}

func TestBaseInterpolation(t *testing.T) {
	base, _ := Parse(strings.NewReader("PW=s3cret\n"), "a", nil)
	e, err := Parse(strings.NewReader("URL=redis://:${PW}@redis\n"), "b", base)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := e.Lookup("URL"); v != "redis://:s3cret@redis" {
		t.Errorf("URL = %q", v)
	}
}

func TestErrors(t *testing.T) {
	for _, src := range []string{"1BAD=x\n", "A=\"open\n", "A=${B:?required}\n"} {
		if _, err := Parse(strings.NewReader(src), "t", nil); err == nil {
			t.Errorf("%q: expected error", src)
		}
	}
}
