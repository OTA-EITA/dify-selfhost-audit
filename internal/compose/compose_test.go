package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OTA-EITA/dify-selfhost-audit/internal/envfile"
)

func TestParsePort(t *testing.T) {
	cases := []struct {
		raw          string
		ip, pub, tgt string
		all          bool
	}{
		{"80", "", "", "80", true},
		{"8080:80", "", "8080", "80", true},
		{"127.0.0.1:8080:80", "127.0.0.1", "8080", "80", false},
		{"0.0.0.0:5003:5003", "0.0.0.0", "5003", "5003", true},
		{"[::1]:80:80", "[::1]", "80", "80", false},
		{"[::]:80:80/tcp", "[::]", "80", "80", true},
		{"::1:80:80", "::1", "80", "80", false},
		{"8000-8010:8000-8010/udp", "", "8000-8010", "8000-8010", true},
	}
	for _, c := range cases {
		p := ParsePort(c.raw, 1)
		if p.HostIP != c.ip || p.Published != c.pub || p.Target != c.tgt || p.AllInterfaces() != c.all {
			t.Errorf("%s -> %+v all=%v", c.raw, p, p.AllInterfaces())
		}
	}
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "envs/a.env", "FROM_A=a\nOVERRIDE=from-a\n")
	write(t, dir, ".env", "OVERRIDE=from-dotenv\nKEY=real\nCOMPOSE_PROFILES=p1\n")
	cf := write(t, dir, "docker-compose.yaml", `
x-base: &base
  env_file:
    - path: ./envs/a.env
      required: false
    - path: ./envs/missing.env
      required: false
    - ./.env
  networks: [net]
services:
  app:
    <<: *base
    environment:
      FROM_ENV: ${KEY:-fallback}
      DEFAULTED: ${NOT_SET:-dflt}
      LITERAL: "$$HOME"
      SHELL_ONLY:
    ports:
      - "127.0.0.1:${P:-8080}:80"
      - target: 9000
        published: "9000"
        host_ip: 0.0.0.0
    privileged: "true"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - type: bind
        source: ./data
        target: /data
  gated:
    image: x
    profiles: [p2]
  listenv:
    image: x
    environment:
      - A=1
      - B=${KEY}
networks:
  net:
    internal: true
`)
	projEnv, err := envfile.ParseFile(filepath.Join(dir, ".env"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load(cf, projEnv)
	if err != nil {
		t.Fatal(err)
	}
	app := p.Service("app")
	if app == nil {
		t.Fatal("no app")
	}
	checks := map[string]string{
		"FROM_A": "a", "OVERRIDE": "from-dotenv", "KEY": "real",
		"FROM_ENV": "real", "DEFAULTED": "dflt", "LITERAL": "$HOME",
	}
	for k, v := range checks {
		if got := app.Env[k].Value; got != v {
			t.Errorf("app %s = %q, want %q", k, got, v)
		}
	}
	if _, ok := app.Env["SHELL_ONLY"]; ok {
		t.Error("SHELL_ONLY should be ignored")
	}
	if o := app.Env["DEFAULTED"].Origin; o != "compose default" {
		t.Errorf("DEFAULTED origin = %q", o)
	}
	if v := app.Env["FROM_ENV"]; !strings.HasSuffix(v.File, ".env") || v.Line != 2 {
		t.Errorf("FROM_ENV located at %s:%d, want .env:2", v.File, v.Line)
	}
	if len(app.Ports) != 2 || app.Ports[0].AllInterfaces() || !app.Ports[1].AllInterfaces() {
		t.Errorf("ports = %+v", app.Ports)
	}
	if !app.Privileged {
		t.Error("privileged not detected")
	}
	if len(app.Mounts) != 2 || app.Mounts[0].Source != "/var/run/docker.sock" || app.Mounts[1].Source != "./data" {
		t.Errorf("mounts = %+v", app.Mounts)
	}
	if !app.NetworksDeclared || len(app.Networks) != 1 || app.Networks[0].Name != "net" {
		t.Errorf("networks = %+v", app.Networks)
	}
	if !p.Networks["net"].Internal {
		t.Error("net should be internal")
	}
	if p.Service("gated").Active(p.Profiles) {
		t.Error("gated should be inactive")
	}
	if !p.Service("app").Active(p.Profiles) {
		t.Error("app should be active")
	}
	if v := p.Service("listenv").Env["B"].Value; v != "real" {
		t.Errorf("listenv B = %q", v)
	}
}

func TestMissingDotEnvUsesProjectEnv(t *testing.T) {
	dir := t.TempDir()
	cf := write(t, dir, "docker-compose.yaml", "services:\n  api:\n    env_file:\n      - ./.env\n")
	envPath := write(t, dir, ".env.example", "SECRET_KEY=abc\n")
	projEnv, _ := envfile.ParseFile(envPath, nil)
	p, err := Load(cf, projEnv)
	if err != nil {
		t.Fatal(err)
	}
	if v := p.Service("api").Env["SECRET_KEY"]; v.Value != "abc" || v.Line != 1 {
		t.Errorf("SECRET_KEY = %+v", v)
	}
	if len(p.Notes) != 1 {
		t.Errorf("notes = %v", p.Notes)
	}
}

func TestMergeOverride(t *testing.T) {
	dir := t.TempDir()
	cf := write(t, dir, "c.yaml", `
x-a: &a
  image: from-anchor
  privileged: true
services:
  s:
    <<: *a
    image: explicit
`)
	p, err := Load(cf, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Service("s")
	if s.Image != "explicit" || !s.Privileged {
		t.Errorf("s = %+v", s)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bad.yaml":   "services: [\n",
		"nosvc.yaml": "networks: {}\n",
		"list.yaml":  "- a\n",
	} {
		if _, err := Load(write(t, dir, name, body), nil); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
