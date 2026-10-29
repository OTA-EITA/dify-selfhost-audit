// Package report writes findings as a text table, JSON or SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/OTA-EITA/dify-selfhost-audit/internal/checks"
)

// Meta is context printed alongside the findings.
type Meta struct {
	Tool        string
	Version     string
	EnvFiles    []string
	ComposeFile string
	Profiles    []string
	Notes       []string
}

// Write renders res in format ("table", "json" or "sarif").
func Write(w io.Writer, format string, res checks.Result, meta Meta) error {
	switch format {
	case "table", "":
		return table(w, res, meta)
	case "json":
		return jsonOut(w, res, meta)
	case "sarif":
		return sarif(w, res, meta)
	}
	return fmt.Errorf("unknown format %q (want table, json or sarif)", format)
}

func loc(f checks.Finding) string {
	if f.File == "" {
		return "(not set; default applies)"
	}
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

func table(w io.Writer, res checks.Result, meta Meta) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tID\tSERVICE\tLOCATION\tFINDING")
	for _, f := range res.Findings {
		svc := f.Service
		if svc == "" {
			svc = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, svc, loc(f), f.Title)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	counts := map[checks.Severity]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "\n%d findings: %d high, %d medium, %d low, %d info\n",
		len(res.Findings), counts[checks.High], counts[checks.Medium], counts[checks.Low], counts[checks.Info])
	if len(meta.Profiles) > 0 {
		fmt.Fprintf(w, "Active profiles: %s\n", strings.Join(meta.Profiles, ", "))
	}
	if len(res.Skipped) > 0 {
		fmt.Fprintf(w, "Not evaluated (profile not active, use --all-profiles): %s\n", strings.Join(res.Skipped, ", "))
	}
	for _, n := range meta.Notes {
		fmt.Fprintf(w, "Note: %s\n", n)
	}
	if len(res.Findings) > 0 {
		fmt.Fprintln(w, "\nDetails:")
		for _, f := range res.Findings {
			fmt.Fprintf(w, "  [%s] %s %s\n    %s\n", f.RuleID, f.Severity, loc(f), f.Message)
			if r := checks.RuleByID(f.RuleID); r != nil {
				fmt.Fprintf(w, "    Fix: %s\n", r.Remediation)
			}
		}
	}
	return nil
}

type jsonFinding struct {
	RuleID      string   `json:"rule_id"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Message     string   `json:"message"`
	Service     string   `json:"service,omitempty"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

func jsonOut(w io.Writer, res checks.Result, meta Meta) error {
	out := struct {
		Tool        string        `json:"tool"`
		Version     string        `json:"version"`
		EnvFiles    []string      `json:"env_files"`
		ComposeFile string        `json:"compose_file,omitempty"`
		Profiles    []string      `json:"active_profiles,omitempty"`
		Skipped     []string      `json:"skipped_services,omitempty"`
		Notes       []string      `json:"notes,omitempty"`
		Findings    []jsonFinding `json:"findings"`
	}{meta.Tool, meta.Version, meta.EnvFiles, meta.ComposeFile, meta.Profiles, res.Skipped, meta.Notes, []jsonFinding{}}
	for _, f := range res.Findings {
		jf := jsonFinding{RuleID: f.RuleID, Severity: f.Severity.String(), Title: f.Title, Message: f.Message,
			Service: f.Service, File: f.File, Line: f.Line}
		if r := checks.RuleByID(f.RuleID); r != nil {
			jf.Remediation, jf.References = r.Remediation, r.Refs
		}
		out.Findings = append(out.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// SARIF 2.1.0, the subset GitHub code scanning reads.
func sarif(w io.Writer, res checks.Result, meta Meta) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription msg               `json:"shortDescription"`
		Help             msg               `json:"help"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]any    `json:"properties"`
		DefaultConfig    map[string]string `json:"defaultConfiguration"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type physical struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *region `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations,omitempty"`
	}

	var rules []rule
	for _, r := range checks.Rules {
		help := r.Remediation
		if len(r.Refs) > 0 {
			help += "\n\nSources:\n" + strings.Join(r.Refs, "\n")
		}
		rr := rule{
			ID: r.ID, Name: r.ID, ShortDescription: msg{r.Title}, Help: msg{help},
			Properties:    map[string]any{"security-severity": securitySeverity(r.Severity), "tags": []string{"security", "dify"}},
			DefaultConfig: map[string]string{"level": level(r.Severity)},
		}
		if len(r.Refs) > 0 {
			rr.HelpURI = r.Refs[0]
		}
		rules = append(rules, rr)
	}
	results := []result{}
	for _, f := range res.Findings {
		r := result{RuleID: f.RuleID, Level: level(f.Severity), Message: msg{f.Title + ": " + f.Message}}
		if f.File != "" {
			var pl physical
			pl.ArtifactLocation.URI = filepath.ToSlash(f.File)
			if f.Line > 0 {
				pl.Region = &region{StartLine: f.Line}
			}
			r.Locations = []location{{PhysicalLocation: pl}}
		}
		results = append(results, r)
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": meta.Tool, "version": meta.Version,
				"informationUri": "https://github.com/OTA-EITA/dify-selfhost-audit",
				"rules":          rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func level(s checks.Severity) string {
	switch s {
	case checks.High:
		return "error"
	case checks.Medium:
		return "warning"
	}
	return "note"
}

func securitySeverity(s checks.Severity) string {
	switch s {
	case checks.High:
		return "8.0"
	case checks.Medium:
		return "5.5"
	case checks.Low:
		return "3.0"
	}
	return "0.0"
}
