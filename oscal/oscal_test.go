package oscal_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseunicorns/go-oscal/src/pkg/validation"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/controls"
	"github.com/opensecurity-dev/assessment-spec/evidence"
	"github.com/opensecurity-dev/assessment-spec/oscal"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

var update = flag.Bool("update", false, "rewrite golden OSCAL exports")

const exampleDir = "../examples/example-co"

var opts = oscal.Options{
	Source:       "https://example.test/profiles/sp800-53-low/profile.json",
	LastModified: time.Date(2026, 2, 1, 6, 0, 0, 0, time.UTC),
	Version:      "0.1.0",
}

type example struct {
	scope *scope.Scope
	set   *evidence.Set
	doc   *controls.Document
}

func load(t *testing.T) example {
	t.Helper()
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
	return example{s, set, doc}
}

func (e example) export(t *testing.T, system string, aud audience.Audience) []byte {
	t.Helper()
	v, err := e.scope.NewView(e.set, system, aud)
	if err != nil {
		t.Fatal(err)
	}
	cd, err := oscal.ComponentDefinition(e.scope, e.doc, v, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := oscal.Marshal(cd)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExportsAreValidOSCAL(t *testing.T) {
	e := load(t)
	for _, sys := range []string{"notes", "ledger"} {
		for _, aud := range audience.All {
			b := e.export(t, sys, aud)
			v, err := validation.NewValidator(b)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Validate(); err != nil {
				res, rerr := v.GetValidationResult()
				if rerr != nil {
					t.Fatal(rerr)
				}
				t.Errorf("%s %s: %v\n%+v", sys, aud, err, res.Errors)
			}
		}
	}
}

func TestGolden(t *testing.T) {
	e := load(t)
	for _, c := range []struct {
		system string
		aud    audience.Audience
	}{{"notes", audience.Public}, {"ledger", audience.Internal}} {
		got := e.export(t, c.system, c.aud)
		path := filepath.Join(exampleDir, "oscal", c.system+"."+string(c.aud)+".component-definition.json")
		if *update {
			if err := os.WriteFile(path, got, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path) //nolint:gosec // a fixed test fixture path
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs; run go test ./... -update in oscal and review the diff", path)
		}
	}
}

func TestAudienceRules(t *testing.T) {
	e := load(t)
	public := string(e.export(t, "notes", audience.Public))
	internal := string(e.export(t, "notes", audience.Internal))
	// The platform's SC-8 statement names both systems' hosts.
	if strings.Contains(public, "ledger.example.test") {
		t.Error("public notes export names the ledger system")
	}
	if !strings.Contains(internal, "ledger.example.test") {
		t.Error("internal notes export should carry the platform's full SC-8 statement")
	}
	if !strings.Contains(public, `"value": "names-other-systems"`) {
		t.Error("public export should mark withheld prose")
	}
	for _, rec := range e.doc.Records {
		for _, f := range rec.Findings {
			if strings.Contains(internal, f) {
				t.Errorf("finding %s exported", f)
			}
		}
	}
	if strings.Contains(public, "Ledger") {
		t.Error("public notes export names the ledger system")
	}
}

func TestStableUUIDs(t *testing.T) {
	e := load(t)
	var a, b struct {
		ComponentDefinition struct {
			UUID       string `json:"uuid"`
			Components []struct {
				UUID string `json:"uuid"`
			} `json:"components"`
		} `json:"component-definition"`
	}
	if err := json.Unmarshal(e.export(t, "notes", audience.Public), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(e.export(t, "ledger", audience.Public), &b); err != nil {
		t.Fatal(err)
	}
	if a.ComponentDefinition.UUID == b.ComponentDefinition.UUID {
		t.Error("two systems' documents share a UUID")
	}
	// Both systems run on the same platform: the platform component keeps
	// its UUID across systems' documents.
	if a.ComponentDefinition.Components[1].UUID != b.ComponentDefinition.Components[1].UUID {
		t.Error("the shared platform's component UUID differs between systems")
	}
}

func TestControlID(t *testing.T) {
	for in, want := range map[string]string{"AC-2": "ac-2", "SC-7(5)": "sc-7.5", "PT-10": "pt-10"} {
		if got := oscal.ControlID(in); got != want {
			t.Errorf("ControlID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOptionsRequired(t *testing.T) {
	e := load(t)
	v, err := e.scope.NewView(e.set, "notes", audience.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oscal.ComponentDefinition(e.scope, e.doc, v, oscal.Options{}); err == nil ||
		!strings.Contains(err.Error(), "source") || !strings.Contains(err.Error(), "last-modified") || !strings.Contains(err.Error(), "version") {
		t.Errorf("empty options: got %v", err)
	}
}

func TestEffectiveStatus(t *testing.T) {
	e := load(t)
	var doc struct {
		ComponentDefinition struct {
			Components []struct {
				ControlImplementations []struct {
					ImplementedRequirements []struct {
						ControlID string `json:"control-id"`
						Props     []struct {
							Name, Value string
						} `json:"props"`
					} `json:"implemented-requirements"`
				} `json:"control-implementations"`
			} `json:"components"`
		} `json:"component-definition"`
	}
	if err := json.Unmarshal(e.export(t, "notes", audience.Public), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]string{}
	for _, r := range doc.ComponentDefinition.Components[0].ControlImplementations[0].ImplementedRequirements {
		got[r.ControlID] = map[string]string{}
		for _, p := range r.Props {
			got[r.ControlID][p.Name] = p.Value
		}
	}
	// Notes implements its part of RA-5; the platform's part is partial.
	if got["ra-5"][oscal.PropImplementationStatus] != "implemented" || got["ra-5"][oscal.PropEffectiveStatus] != "partial" {
		t.Errorf("ra-5: %v", got["ra-5"])
	}
	// PT-2 is an added control, which resolution also covers.
	for _, id := range []string{"ia-2", "pt-2", "pt-3"} {
		if _, ok := got[id][oscal.PropEffectiveStatus]; ok {
			t.Errorf("%s: a system-specific record needs no effective status: %v", id, got[id])
		}
	}
}
