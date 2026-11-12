package crosswalk_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/controls"
	"github.com/opensecurity-dev/assessment-spec/crosswalk"
	"github.com/opensecurity-dev/assessment-spec/evidence"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

var update = flag.Bool("update", false, "rewrite golden coverage")

const exampleDir = "../examples/example-co"

func valid() crosswalk.Crosswalk {
	return crosswalk.Crosswalk{
		Framework: "example-framework",
		Source:    "operator",
		License:   "MIT",
		Mappings:  []crosswalk.Mapping{{Criterion: "EX-1", Controls: []string{"AC-2", "SC-7(5)"}}},
	}
}

func TestValidate(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid crosswalk: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*crosswalk.Crosswalk)
		want   string
	}{
		{"schema version", func(c *crosswalk.Crosswalk) { c.SchemaVersion = "crosswalk/v2" }, "unsupported schemaVersion"},
		{"framework case", func(c *crosswalk.Crosswalk) { c.Framework = "ISO-27001" }, "framework"},
		{"no source", func(c *crosswalk.Crosswalk) { c.Source = " " }, "source is empty"},
		{"no license", func(c *crosswalk.Crosswalk) { c.License = "" }, "license is empty"},
		{"no mappings", func(c *crosswalk.Crosswalk) { c.Mappings = nil }, "no mappings"},
		{"empty criterion", func(c *crosswalk.Crosswalk) { c.Mappings[0].Criterion = "" }, "empty criterion"},
		{"padded criterion", func(c *crosswalk.Crosswalk) { c.Mappings[0].Criterion = " EX-1" }, "surrounding spaces"},
		{"duplicate criterion", func(c *crosswalk.Crosswalk) {
			c.Mappings = append(c.Mappings, crosswalk.Mapping{Criterion: "EX-1", Controls: []string{"AC-3"}})
		}, "mapped twice"},
		{"no controls", func(c *crosswalk.Crosswalk) { c.Mappings[0].Controls = nil }, "maps to no controls"},
		{"bad control", func(c *crosswalk.Crosswalk) { c.Mappings[0].Controls = []string{"ac-2"} }, "not a control ID"},
		{"duplicate control", func(c *crosswalk.Crosswalk) { c.Mappings[0].Controls = []string{"AC-2", "AC-2"} }, "lists AC-2 twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			c.Mappings = []crosswalk.Mapping{{Criterion: "EX-1", Controls: []string{"AC-2", "SC-7(5)"}}}
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestCoverageRules(t *testing.T) {
	c := crosswalk.Crosswalk{
		Framework: "f",
		Source:    "operator",
		License:   "MIT",
		Mappings: []crosswalk.Mapping{
			{Criterion: "all-implemented", Controls: []string{"AC-1", "AC-2"}},
			{Criterion: "weakest", Controls: []string{"AC-1", "AC-3"}},
			{Criterion: "na-yields", Controls: []string{"AC-4", "AC-1"}},
			{Criterion: "all-na", Controls: []string{"AC-4"}},
			{Criterion: "outside", Controls: []string{"AC-1", "AC-9"}},
		},
	}
	r := &controls.Resolution{System: "s", Audience: audience.Public, Controls: []controls.Resolved{
		{Control: "AC-1", Status: controls.StatusImplemented},
		{Control: "AC-2", Status: controls.StatusImplemented},
		{Control: "AC-3", Status: controls.StatusPlanned},
		{Control: "AC-4", Status: controls.StatusNotApplicable},
	}}
	cov, err := c.Coverage(r)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]controls.Status{
		"all-implemented": controls.StatusImplemented,
		"weakest":         controls.StatusPlanned,
		"na-yields":       controls.StatusImplemented,
		"all-na":          controls.StatusNotApplicable,
		"outside":         controls.StatusUnassessed,
	}
	for _, cr := range cov.Criteria {
		if cr.Status != want[cr.Criterion] {
			t.Errorf("%s: got %s, want %s", cr.Criterion, cr.Status, want[cr.Criterion])
		}
	}
	last := cov.Criteria[len(cov.Criteria)-1].Controls[1]
	if !last.OutsideBaseline || last.Status != controls.StatusUnassessed {
		t.Errorf("AC-9 outside the resolution: got %+v", last)
	}
	if cov.Summary[controls.StatusImplemented] != 2 || cov.Summary[controls.StatusUnassessed] != 1 {
		t.Errorf("summary: %v", cov.Summary)
	}
	if _, err := c.Coverage(nil); err == nil {
		t.Error("nil resolution: want an error")
	}
	c.License = ""
	if _, err := c.Coverage(r); err == nil {
		t.Error("invalid crosswalk: want an error")
	}
}

func TestExampleCoverage(t *testing.T) {
	cw, err := crosswalk.Load(filepath.Join(exampleDir, "crosswalks", "example-framework.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.Load(filepath.Join(exampleDir, "scope.json"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := evidence.LoadSet(filepath.Join(exampleDir, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := controls.Load(filepath.Join(exampleDir, "controls.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(exampleDir, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var base struct {
		Controls []string `json:"controls"`
	}
	if err := json.Unmarshal(b, &base); err != nil {
		t.Fatal(err)
	}
	for _, sys := range []string{"notes", "ledger"} {
		v, err := s.NewView(set, sys, audience.Public)
		if err != nil {
			t.Fatal(err)
		}
		r, err := controls.Resolve(s, doc, v, base.Controls)
		if err != nil {
			t.Fatal(err)
		}
		cov, err := cw.Coverage(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.MarshalIndent(cov, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, '\n')
		path := filepath.Join(exampleDir, "coverage", sys+".example-framework.json")
		if *update {
			if err := os.WriteFile(path, got, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s coverage differs from %s; run go test ./crosswalk -update and review the diff", sys, path)
		}
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(`{"framework":"f","source":"s","license":"MIT","mappings":[],"text":"criterion prose"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := crosswalk.Load(path); err == nil {
		t.Fatal("want an error for an unknown field")
	}
}
