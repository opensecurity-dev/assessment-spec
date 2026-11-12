package controls_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/controls"
	"github.com/opensecurity-dev/assessment-spec/evidence"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

var update = flag.Bool("update", false, "rewrite golden resolutions")

const exampleDir = "../examples/example-co"

type example struct {
	scope    *scope.Scope
	set      *evidence.Set
	doc      *controls.Document
	baseline []string
}

func loadExample(t *testing.T) example {
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
	return example{scope: s, set: set, doc: doc, baseline: base.Controls}
}

func (e example) resolve(t *testing.T, system string, aud audience.Audience) *controls.Resolution {
	t.Helper()
	v, err := e.scope.NewView(e.set, system, aud)
	if err != nil {
		t.Fatal(err)
	}
	r, err := controls.Resolve(e.scope, e.doc, v, e.baseline)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(t *testing.T, r *controls.Resolution, control string) controls.Resolved {
	t.Helper()
	for _, c := range r.Controls {
		if c.Control == control {
			return c
		}
	}
	t.Fatalf("%s/%s has no %s", r.System, r.Audience, control)
	return controls.Resolved{}
}

func TestExampleResolutionsGolden(t *testing.T) {
	e := loadExample(t)
	for _, sys := range e.scope.Systems {
		for _, aud := range audience.All {
			got, err := json.MarshalIndent(e.resolve(t, sys.ID, aud), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join(exampleDir, "resolutions", sys.ID+"."+string(aud)+".json")
			if *update {
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(golden) //nolint:gosec // a fixed test fixture path
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("%s differs from the computed resolution; run go test ./controls -update after a deliberate change\n%s", golden, got)
			}
		}
	}
}

func TestInheritance(t *testing.T) {
	e := loadExample(t)
	notes := e.resolve(t, "notes", audience.Internal)
	ledger := e.resolve(t, "ledger", audience.Internal)
	cases := []struct {
		r       *controls.Resolution
		control string
		status  controls.Status
		via     []string
	}{
		// Provider record reached through the platform, with no platform record.
		{notes, "PE-3", controls.StatusImplemented, []string{"provider:example-cloud"}},
		// Explicit inheritance chain: platform inherits from provider.
		{ledger, "CP-9", controls.StatusImplemented, []string{"platform:shared-hosting", "provider:example-cloud"}},
		// Hybrid takes the weaker of the system's implemented and the platform's partial.
		{notes, "RA-5", controls.StatusPartial, []string{"system:notes", "platform:shared-hosting"}},
		// No system record: the platform's status.
		{ledger, "RA-5", controls.StatusPartial, []string{"platform:shared-hosting"}},
		{ledger, "AC-2", controls.StatusImplemented, []string{"platform:shared-hosting"}},
		{notes, "AC-2", controls.StatusPartial, []string{"system:notes", "platform:shared-hosting"}},
		// A system record wins.
		{ledger, "IA-2", controls.StatusPlanned, []string{"system:ledger"}},
		// Nothing records it.
		{notes, "AU-2", controls.StatusUnassessed, []string{}},
		{notes, "PT-5", controls.StatusUnassessed, []string{}},
	}
	for _, c := range cases {
		got := find(t, c.r, c.control)
		if got.Status != c.status || !slices.Equal(got.Via, c.via) {
			t.Errorf("%s %s = %s via %v, want %s via %v", c.r.System, c.control, got.Status, got.Via, c.status, c.via)
		}
	}
	for _, c := range ledger.Controls {
		if strings.HasPrefix(c.Control, "PT-") {
			t.Errorf("ledger has %s, which only notes adds", c.Control)
		}
	}
}

// TestPlatformRecordWrittenOnce: changing a platform record changes every
// system on the platform.
func TestPlatformRecordWrittenOnce(t *testing.T) {
	e := loadExample(t)
	for i := range e.doc.Records {
		r := &e.doc.Records[i]
		if r.Control == "SI-2" && r.Scope == "shared-hosting" {
			r.Status, r.Gap = controls.StatusPlanned, "Automatic updates are being re-enabled."
		}
	}
	for _, sys := range []string{"notes", "ledger"} {
		if got := find(t, e.resolve(t, sys, audience.Internal), "SI-2").Status; got != controls.StatusPlanned {
			t.Errorf("%s SI-2 = %s, want planned", sys, got)
		}
	}
}

func TestExternalResolutionsNameNoOtherSystem(t *testing.T) {
	e := loadExample(t)
	for _, sys := range e.scope.Systems {
		for _, aud := range []audience.Audience{audience.Public, audience.NDA} {
			r := e.resolve(t, sys.ID, aud)
			for _, c := range r.Controls {
				if len(c.Findings) > 0 {
					t.Errorf("%s/%s %s shows findings to an external audience", sys.ID, aud, c.Control)
				}
				for _, st := range c.Statements {
					for _, id := range e.scope.DetectMentions([]byte(st.Text)) {
						if id != sys.ID {
							t.Errorf("%s/%s %s prose names %s: %q", sys.ID, aud, c.Control, id, st.Text)
						}
					}
				}
			}
		}
	}
}

func TestAudienceFiltering(t *testing.T) {
	e := loadExample(t)
	pub := find(t, e.resolve(t, "ledger", audience.Public), "RA-5")
	nda := find(t, e.resolve(t, "ledger", audience.NDA), "RA-5")
	internal := find(t, e.resolve(t, "ledger", audience.Internal), "RA-5")
	if len(pub.Statements) != 0 || !hasWithheld(pub, "prose", controls.ReasonVisibility) {
		t.Errorf("public RA-5 should withhold NDA prose: %+v", pub)
	}
	if len(nda.Statements) != 2 {
		t.Errorf("NDA RA-5 statements = %+v, want the statement and the gap", nda.Statements)
	}
	if !slices.Equal(internal.Findings, []string{"FIND-0007"}) {
		t.Errorf("internal RA-5 findings = %v", internal.Findings)
	}
	sc8 := find(t, e.resolve(t, "notes", audience.Public), "SC-8")
	if len(sc8.Statements) != 0 || !hasWithheld(sc8, "prose", controls.ReasonNamesOtherSystem) {
		t.Errorf("public SC-8 prose names ledger and should be withheld: %+v", sc8)
	}
	if got := find(t, e.resolve(t, "notes", audience.Internal), "SC-8"); len(got.Statements) != 1 {
		t.Errorf("internal SC-8 should keep its prose: %+v", got)
	}
	sc7 := find(t, e.resolve(t, "notes", audience.Public), "SC-7")
	if !slices.Equal(sc7.Evidence, []string{"platform-benchmark.manifest.json"}) || !hasWithheld(sc7, "evidence", scope.ReasonNamesOtherSystems) {
		t.Errorf("public SC-7 should keep the benchmark and withhold the proxy config: %+v", sc7)
	}
}

func hasWithheld(c controls.Resolved, kind, reason string) bool {
	for _, w := range c.Withheld {
		if w.Kind == kind && w.Reason == reason {
			return true
		}
	}
	return false
}

func TestVerificationIsWeakest(t *testing.T) {
	e := loadExample(t)
	r := e.resolve(t, "notes", audience.Internal)
	if got := find(t, r, "SI-2").Verification; got != controls.VerificationVerified {
		t.Errorf("SI-2 verification = %s, want verified", got)
	}
	if got := find(t, r, "CP-9").Verification; got != controls.VerificationReviewed {
		t.Errorf("CP-9 verification = %s, want reviewed", got)
	}
	if got := find(t, r, "RA-5").Verification; got != controls.VerificationUnverified {
		t.Errorf("RA-5 verification = %s, want unverified", got)
	}
}

func TestNotApplicableYields(t *testing.T) {
	e := loadExample(t)
	e.doc.Records = append(e.doc.Records, controls.Implementation{
		Control: "AU-2", Scope: "shared-hosting", Status: controls.StatusNotApplicable,
		Origination: controls.OriginSpecific, Justification: "Illustrative.",
	}, controls.Implementation{
		Control: "AU-2", Scope: "notes", Status: controls.StatusPartial, Origination: controls.OriginHybrid,
		InheritsFrom: []string{"shared-hosting"}, Gap: "Illustrative.",
	})
	if got := find(t, e.resolve(t, "notes", audience.Internal), "AU-2").Status; got != controls.StatusPartial {
		t.Errorf("hybrid partial with a not-applicable source = %s, want partial", got)
	}
	if got := find(t, e.resolve(t, "ledger", audience.Internal), "AU-2").Status; got != controls.StatusNotApplicable {
		t.Errorf("inherited not-applicable = %s", got)
	}
}

func TestValidate(t *testing.T) {
	e := loadExample(t)
	if err := e.doc.Validate(e.scope); err != nil {
		t.Fatalf("example: %v", err)
	}
	ok := controls.Implementation{Control: "AC-3", Scope: "notes", Status: controls.StatusImplemented, Origination: controls.OriginSpecific}
	cases := map[string]struct {
		mutate func(*controls.Implementation)
		want   string
	}{
		"control id":          {func(r *controls.Implementation) { r.Control = "ac-3" }, "not a control ID"},
		"unknown scope":       {func(r *controls.Implementation) { r.Scope = "billing" }, "not a system, platform or provider"},
		"no origination":      {func(r *controls.Implementation) { r.Origination = "" }, "unknown origination"},
		"no status":           {func(r *controls.Implementation) { r.Status = "" }, "missing status"},
		"derived status":      {func(r *controls.Implementation) { r.Status = controls.StatusUnassessed }, "missing status"},
		"partial no gap":      {func(r *controls.Implementation) { r.Status = controls.StatusPartial }, "needs a gap"},
		"na no justification": {func(r *controls.Implementation) { r.Status = controls.StatusNotApplicable }, "needs a justification"},
		"specific inherits":   {func(r *controls.Implementation) { r.InheritsFrom = []string{"shared-hosting"} }, "inherits from nothing"},
		"inherited status": {func(r *controls.Implementation) {
			r.Origination, r.InheritsFrom = controls.OriginInherited, []string{"shared-hosting"}
		}, "sets none"},
		"inherited no source": {func(r *controls.Implementation) { r.Origination, r.Status = controls.OriginInherited, "" }, "needs inheritsFrom"},
		"hybrid no source":    {func(r *controls.Implementation) { r.Origination = controls.OriginHybrid }, "needs inheritsFrom"},
		"foreign source": {func(r *controls.Implementation) {
			r.Origination, r.InheritsFrom = controls.OriginHybrid, []string{"ledger"}
		}, `cannot inherit from "ledger"`},
		"provider inherits": {func(r *controls.Implementation) {
			r.Scope, r.Origination, r.InheritsFrom = "example-cloud", controls.OriginHybrid, []string{"example-cdn"}
		}, "allowed: none"},
		"visibility": {func(r *controls.Implementation) { r.Visibility = "partners" }, "unknown visibility"},
		"attestation": {func(r *controls.Implementation) {
			r.Attestations = []controls.Attestation{{By: "", At: "yesterday", Verification: "checked"}}
		}, "has no by"},
		"evidence path": {func(r *controls.Implementation) {
			r.Evidence = []controls.EvidenceRef{{Manifest: "../x.manifest.json"}}
		}, "must be a file name"},
		"duplicate": {func(r *controls.Implementation) { r.Control = "IA-2" }, "duplicate record"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := ok
			c.mutate(&r)
			d := &controls.Document{Records: append(slices.Clone(e.doc.Records), r)}
			err := d.Validate(e.scope)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestResolveRejectsBadBaseline(t *testing.T) {
	e := loadExample(t)
	v, err := e.scope.NewView(e.set, "notes", audience.Internal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controls.Resolve(e.scope, e.doc, v, []string{"AC 2"}); err == nil {
		t.Fatal("expected an error for a malformed baseline control")
	}
}

func TestControlOrder(t *testing.T) {
	e := loadExample(t)
	v, err := e.scope.NewView(e.set, "notes", audience.Internal)
	if err != nil {
		t.Fatal(err)
	}
	r, err := controls.Resolve(e.scope, e.doc, v, []string{"SC-7(5)", "AC-2", "SC-7", "AC-2", "SC-12", "AC-17"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range r.Controls {
		got = append(got, c.Control)
	}
	want := []string{"AC-2", "AC-17", "PT-2", "PT-3", "PT-5", "SC-7", "SC-7(5)", "SC-12"}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestWeaker(t *testing.T) {
	cases := []struct{ a, b, want controls.Status }{
		{controls.StatusImplemented, controls.StatusPartial, controls.StatusPartial},
		{controls.StatusPlanned, controls.StatusAlternative, controls.StatusPlanned},
		{controls.StatusNotApplicable, controls.StatusPlanned, controls.StatusPlanned},
		{controls.StatusImplemented, controls.StatusNotApplicable, controls.StatusImplemented},
		{controls.StatusNotApplicable, controls.StatusNotApplicable, controls.StatusNotApplicable},
		{controls.StatusUnassessed, controls.StatusImplemented, controls.StatusUnassessed},
	}
	for _, c := range cases {
		if got := controls.Weaker(c.a, c.b); got != c.want {
			t.Errorf("Weaker(%s, %s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestProseWithheld(t *testing.T) {
	e := loadExample(t)
	rec := controls.Implementation{Statement: "Serves notes.example.test and ledger.example.test.", Visibility: audience.Public}
	if got := controls.ProseWithheld(e.scope, rec, audience.Public, "notes"); got != controls.ReasonNamesOtherSystem {
		t.Errorf("names ledger: got %q", got)
	}
	if got := controls.ProseWithheld(e.scope, rec, audience.Internal, "notes"); got != "" {
		t.Errorf("internal: got %q", got)
	}
	rec.Statement = "Serves notes.example.test."
	if got := controls.ProseWithheld(e.scope, rec, audience.Public, "notes"); got != "" {
		t.Errorf("names only itself: got %q", got)
	}
	rec.Visibility = audience.NDA
	if got := controls.ProseWithheld(e.scope, rec, audience.Public, "notes"); got != controls.ReasonVisibility {
		t.Errorf("nda record to public: got %q", got)
	}
}

func TestLoadBaseline(t *testing.T) {
	base, err := controls.LoadBaseline(filepath.Join(exampleDir, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Controls) != 10 || base.Controls[0] != "AC-2" {
		t.Errorf("got %v", base.Controls)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"empty":   `{"controls":[]}`,
		"bad-id":  `{"controls":["AC-2","ac-3"]}`,
		"unknown": `{"controls":["AC-2"],"profile":"low"}`,
	} {
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := controls.LoadBaseline(path); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestSortControlIDs(t *testing.T) {
	ids := []string{"SC-7(5)", "AC-10", "SC-7", "AC-2(1)", "AC-2"}
	controls.SortControlIDs(ids)
	want := []string{"AC-2", "AC-2(1)", "AC-10", "SC-7", "SC-7(5)"}
	if !slices.Equal(ids, want) {
		t.Errorf("got %v, want %v", ids, want)
	}
}
