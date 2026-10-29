package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runArgs(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

const (
	defCompose  = "../../testdata/default/docker-compose.yaml"
	defEnv      = "../../testdata/default/.env"
	hardCompose = "../../testdata/hardened/docker-compose.yaml"
)

func TestExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"--compose", defCompose}, 0}, // default --fail-on high; no HIGH findings
		{[]string{"--compose", defCompose, "--fail-on", "medium"}, 1},
		{[]string{"--compose", defCompose, "--all-profiles"}, 1}, // privileged opengauss is HIGH
		{[]string{"--compose", defCompose, "--fail-on", "none", "--all-profiles"}, 0},
		{[]string{"--compose", hardCompose, "--fail-on", "info"}, 0},
		{[]string{"--compose", "nope.yaml"}, 2},
		{[]string{"--env", "nope.env"}, 2},
		{[]string{"--compose", defCompose, "--format", "xml"}, 2},
		{[]string{"--compose", defCompose, "--fail-on", "critical"}, 2},
		{[]string{"stray"}, 2},
	}
	for _, c := range cases {
		if got, _, errOut := runArgs(c.args...); got != c.want {
			t.Errorf("%v: exit %d, want %d (stderr: %s)", c.args, got, c.want, errOut)
		}
	}
}

func TestDefaultEnvNextToCompose(t *testing.T) {
	_, out, _ := runArgs("--compose", defCompose)
	if !strings.Contains(out, "DSA005") || !strings.Contains(out, "testdata/default/.env:17") {
		t.Errorf("expected .env next to compose to be read:\n%s", out)
	}
}

func TestJSON(t *testing.T) {
	code, out, _ := runArgs("--compose", defCompose, "--env", defEnv, "--format", "json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Profiles []string `json:"active_profiles"`
		Findings []struct {
			RuleID, Severity, File string
			Line                   int
			References             []string
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) == 0 || doc.Findings[0].Severity != "MEDIUM" || len(doc.Findings[0].References) == 0 {
		t.Errorf("findings = %+v", doc.Findings)
	}
	if strings.Join(doc.Profiles, ",") != "collaboration,postgresql,weaviate" {
		t.Errorf("profiles = %v", doc.Profiles)
	}
	if strings.Contains(out, "lYkiYYT6owG+71oLerGzA7GXCgOT") {
		t.Error("secret value printed unmasked")
	}
}

func TestSARIF(t *testing.T) {
	_, out, _ := runArgs("--compose", defCompose, "--format", "sarif")
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						Region struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) < 25 {
		t.Fatalf("bad sarif header")
	}
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.Region.StartLine == 0 {
			t.Errorf("%s has no line", r.RuleID)
		}
	}
}

func TestEnvOnly(t *testing.T) {
	code, out, _ := runArgs("--env", defEnv, "--fail-on", "low")
	if code != 1 || !strings.Contains(out, "compose-level checks") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestListRules(t *testing.T) {
	code, out, _ := runArgs("--list-rules")
	if code != 0 || !strings.Contains(out, "DSA105") {
		t.Errorf("exit %d\n%s", code, out)
	}
}
