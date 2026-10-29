// Command dify-selfhost-audit reads a self-hosted Dify docker/.env and
// docker-compose.yaml and reports insecure defaults. It only reads files; it
// never contacts Docker or the network.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/OTA-EITA/dify-selfhost-audit/internal/checks"
	"github.com/OTA-EITA/dify-selfhost-audit/internal/compose"
	"github.com/OTA-EITA/dify-selfhost-audit/internal/envfile"
	"github.com/OTA-EITA/dify-selfhost-audit/internal/report"
)

var version = "dev"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("dify-selfhost-audit", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var envFiles multi
	fl.Var(&envFiles, "env", "env file to read (repeatable; later files win). Default: .env next to the compose file, or ./.env")
	composePath := fl.String("compose", "", "docker-compose.yaml to read. Default: ./docker-compose.yaml if it exists")
	format := fl.String("format", "table", "output format: table, json or sarif")
	failOn := fl.String("fail-on", "high", "exit 1 when a finding is at or above this severity: info, low, medium, high, none")
	allProfiles := fl.Bool("all-profiles", false, "also check services whose compose profile is not active")
	listRules := fl.Bool("list-rules", false, "print the rule catalogue and exit")
	showVersion := fl.Bool("version", false, "print version and exit")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "Usage: dify-selfhost-audit [--compose docker-compose.yaml] [--env .env ...] [flags]\n\n")
		fl.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 nothing at or above --fail-on, 1 findings at or above --fail-on, 2 usage or parse error.\n")
	}
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fl.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fl.Arg(0))
		fl.Usage()
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if *listRules {
		for _, r := range checks.Rules {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", r.ID, r.Severity, r.Title)
		}
		return 0
	}
	threshold, err := checks.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if *composePath == "" && len(envFiles) == 0 {
		if exists("docker-compose.yaml") {
			*composePath = "docker-compose.yaml"
		} else if exists("docker-compose.yml") {
			*composePath = "docker-compose.yml"
		}
	}
	if len(envFiles) == 0 {
		dir := "."
		if *composePath != "" {
			dir = filepath.Dir(*composePath)
		}
		if p := filepath.Join(dir, ".env"); exists(p) {
			envFiles = append(envFiles, p)
		}
	}
	if *composePath == "" && len(envFiles) == 0 {
		fmt.Fprintln(stderr, "nothing to check: pass --compose and/or --env (no ./docker-compose.yaml or ./.env found)")
		return 2
	}

	env := envfile.New()
	for _, p := range envFiles {
		e, err := envfile.ParseFile(p, env)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		env.Merge(e)
	}

	meta := report.Meta{Tool: "dify-selfhost-audit", Version: version, EnvFiles: envFiles}
	in := checks.Input{Env: env, AllProfiles: *allProfiles}
	if *composePath != "" {
		p, err := compose.Load(*composePath, env)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		in.Project = p
		meta.ComposeFile = *composePath
		meta.Profiles = p.SortedProfiles()
		meta.Notes = p.Notes
	} else {
		meta.Notes = append(meta.Notes, "no compose file given: compose-level checks (DSA013, DSA101-DSA105) skipped; unset variables are assumed to take the 1.17.1 compose fallbacks")
	}

	res := checks.Run(in)
	if err := report.Write(stdout, *format, res, meta); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	for _, f := range res.Findings {
		if f.Severity >= threshold {
			return 1
		}
	}
	return 0
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}
