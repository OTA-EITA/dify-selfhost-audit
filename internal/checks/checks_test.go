package checks

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/OTA-EITA/dify-selfhost-audit/internal/compose"
	"github.com/OTA-EITA/dify-selfhost-audit/internal/envfile"
)

func load(t *testing.T, dir string, allProfiles bool) Result {
	t.Helper()
	env, err := envfile.ParseFile(filepath.Join("..", "..", "testdata", dir, ".env"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := compose.Load(filepath.Join("..", "..", "testdata", dir, "docker-compose.yaml"), env)
	if err != nil {
		t.Fatal(err)
	}
	return Run(Input{Env: env, Project: p, AllProfiles: allProfiles})
}

func ids(res Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.RuleID+"/"+f.Severity.String()+"/"+f.Service)
	}
	sort.Strings(out)
	return out
}

func envOnly(t *testing.T, src string) Result {
	t.Helper()
	env, err := envfile.Parse(strings.NewReader(src), "t.env", nil)
	if err != nil {
		t.Fatal(err)
	}
	return Run(Input{Env: env})
}

func has(res Result, id string) bool {
	for _, f := range res.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestDefaultFixture(t *testing.T) {
	got := strings.Join(ids(load(t, "default", false)), "\n")
	want := strings.Join([]string{
		"DSA002/INFO/api",
		"DSA004/MEDIUM/api",
		"DSA005/MEDIUM/sandbox",
		"DSA007/MEDIUM/plugin_daemon",
		"DSA008/MEDIUM/api",
		"DSA009/MEDIUM/api",
		"DSA010/MEDIUM/api",
		"DSA010/MEDIUM/api",
		"DSA011/MEDIUM/weaviate",
		"DSA012/MEDIUM/weaviate",
		"DSA014/MEDIUM/agent_backend",
		"DSA015/MEDIUM/agent_backend",
		"DSA018/MEDIUM/api",
		"DSA019/LOW/api",
		"DSA020/LOW/nginx",
		"DSA101/INFO/nginx",
		"DSA101/MEDIUM/plugin_daemon",
	}, "\n")
	if got != want {
		t.Errorf("findings:\n%s\nwant:\n%s", got, want)
	}
}

func TestDefaultFixtureAllProfiles(t *testing.T) {
	res := load(t, "default", true)
	for _, id := range []string{"DSA102", "DSA013"} {
		if !has(res, id) {
			t.Errorf("missing %s with --all-profiles", id)
		}
	}
	if len(res.Skipped) != 0 {
		t.Errorf("skipped = %v", res.Skipped)
	}
	if res := load(t, "default", false); len(res.Skipped) != 1 || res.Skipped[0] != "opengauss" {
		t.Errorf("skipped = %v", res.Skipped)
	}
}

func TestHardenedFixture(t *testing.T) {
	res := load(t, "hardened", false)
	if len(res.Findings) != 0 {
		t.Errorf("unexpected findings: %v", ids(res))
	}
}

func TestLocationsPointAtEnvFile(t *testing.T) {
	for _, f := range load(t, "default", false).Findings {
		if f.RuleID == "DSA005" && (!strings.HasSuffix(f.File, ".env") || f.Line != 17) {
			t.Errorf("DSA005 at %s:%d, want .env:17", f.File, f.Line)
		}
		if f.RuleID == "DSA101" && f.Service == "plugin_daemon" && !strings.HasSuffix(f.File, "docker-compose.yaml") {
			t.Errorf("DSA101 at %s", f.File)
		}
	}
}

func TestSecretKey(t *testing.T) {
	if r := envOnly(t, "SECRET_KEY="+LegacySecretKey+"\n"); !has(r, "DSA001") || r.Findings[0].Severity != High {
		t.Error("legacy key should be HIGH DSA001")
	}
	if r := envOnly(t, "SECRET_KEY=\n"); !has(r, "DSA002") {
		t.Error("empty key should be DSA002")
	}
	if r := envOnly(t, ""); !has(r, "DSA002") {
		t.Error("unset key should be DSA002")
	}
	if r := envOnly(t, "SECRET_KEY=changeme\n"); !has(r, "DSA003") {
		t.Error("placeholder should be DSA003")
	}
	if r := envOnly(t, "SECRET_KEY=short\n"); !has(r, "DSA003") {
		t.Error("short key should be DSA003")
	}
	r := envOnly(t, "SECRET_KEY=0123456789abcdefghijklmnopqrstuvwxyzABCD\n")
	if has(r, "DSA001") || has(r, "DSA002") || has(r, "DSA003") {
		t.Error("strong key flagged")
	}
}

func TestEnvOnlyUsesComposeFallbacks(t *testing.T) {
	// Variables missing from .env fall back to the compose defaults, which
	// are the published values.
	r := envOnly(t, "SECRET_KEY=0123456789abcdefghijklmnopqrstuvwxyzABCD\nINIT_PASSWORD=x\n")
	for _, id := range []string{"DSA005", "DSA007", "DSA008", "DSA009", "DSA010", "DSA011", "DSA014", "DSA015", "DSA016", "DSA019", "DSA020"} {
		if !has(r, id) {
			t.Errorf("missing %s", id)
		}
	}
	for _, id := range []string{"DSA012", "DSA018", "DSA021", "DSA024", "DSA101"} {
		if has(r, id) {
			t.Errorf("unexpected %s", id)
		}
	}
}

func TestSSRF(t *testing.T) {
	if r := envOnly(t, "SSRF_PROXY_HTTP_URL=http://ssrf_proxy:3128\n"); !has(r, "DSA016") {
		t.Error("only HTTP set should still flag")
	}
	if r := envOnly(t, "SSRF_PROXY_ALL_URL=http://ssrf_proxy:3128\n"); has(r, "DSA016") {
		t.Error("ALL_URL should satisfy")
	}
	r := envOnly(t, "SSRF_PROXY_HTTP_URL=a\nSSRF_PROXY_HTTPS_URL=b\nSSRF_PROXY_ALLOW_PRIVATE_IPS=172.21.0.5/32\n")
	if has(r, "DSA016") || !has(r, "DSA017") {
		t.Errorf("got %v", ids(r))
	}
	for _, f := range r.Findings {
		if f.RuleID == "DSA017" && strings.Contains(f.Message, "Overlaps") {
			t.Error("a /32 is not a wide range")
		}
	}
	r = envOnly(t, "SSRF_PROXY_ALLOW_PRIVATE_IPS=10.0.0.0/8,169.254.169.254\n")
	for _, f := range r.Findings {
		if f.RuleID == "DSA017" && !strings.Contains(f.Message, "10.0.0.0/8, 169.254.169.254") {
			t.Errorf("message = %s", f.Message)
		}
	}
}

func TestFlags(t *testing.T) {
	r := envOnly(t, "DEBUG=true\nENABLE_REQUEST_LOGGING=True\nALLOW_EMBED=1\nFORCE_VERIFYING_SIGNATURE=false\nPLUGIN_PPROF_ENABLED=yes\nNGINX_HTTPS_ENABLED=true\nWEB_API_CORS_ALLOW_ORIGINS=https://a\nCONSOLE_CORS_ALLOW_ORIGINS=https://a,*\n")
	for _, id := range []string{"DSA018", "DSA021", "DSA022", "DSA023", "DSA024", "DSA025"} {
		if !has(r, id) {
			t.Errorf("missing %s", id)
		}
	}
	if has(r, "DSA019") || has(r, "DSA020") {
		t.Errorf("unexpected: %v", ids(r))
	}
}

func TestSandboxMismatch(t *testing.T) {
	r := envOnly(t, "SANDBOX_API_KEY=aaaaaaaaaaaa\nCODE_EXECUTION_API_KEY=bbbbbbbbbbbb\n")
	if has(r, "DSA005") || !has(r, "DSA006") {
		t.Errorf("got %v", ids(r))
	}
}

func TestVectorStoreNotWeaviate(t *testing.T) {
	r := envOnly(t, "VECTOR_STORE=qdrant\nWEAVIATE_AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=true\n")
	if has(r, "DSA011") || has(r, "DSA012") {
		t.Errorf("weaviate rules should not fire: %v", ids(r))
	}
}

func TestBrokenCompose(t *testing.T) {
	p, err := compose.Load(filepath.Join("..", "..", "testdata", "broken", "docker-compose.yaml"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Run(Input{Project: p})
	for _, id := range []string{"DSA005", "DSA101", "DSA103", "DSA104", "DSA105"} {
		if !has(r, id) {
			t.Errorf("missing %s in %v", id, ids(r))
		}
	}
}

func TestRulesCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] {
			t.Errorf("duplicate %s", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Remediation == "" {
			t.Errorf("%s incomplete", r.ID)
		}
		for _, ref := range r.Refs {
			if !strings.HasPrefix(ref, "https://github.com/langgenius/") {
				t.Errorf("%s: unexpected ref %s", r.ID, ref)
			}
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"info": Info, "LOW": Low, "Medium": Medium, "high": High, "none": High + 1} {
		if got, err := ParseSeverity(in); err != nil || got != want {
			t.Errorf("%s = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("expected error")
	}
}

func TestMask(t *testing.T) {
	if Mask("") != `""` || Mask("abc") != "***" || Mask("abcdefghij") != "abcd**** (10 chars)" {
		t.Error("mask")
	}
}
