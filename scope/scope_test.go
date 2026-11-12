package scope_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/evidence"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

var update = flag.Bool("update", false, "rewrite golden views")

const exampleDir = "../examples/example-co"

func loadExample(t *testing.T) (*scope.Scope, *evidence.Set) {
	t.Helper()
	s, err := scope.Load(filepath.Join(exampleDir, "scope.json"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := evidence.LoadSet(filepath.Join(exampleDir, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	return s, set
}

func TestExampleIsValid(t *testing.T) {
	s, set := loadExample(t)
	if err := s.CheckEvidence(set); err != nil {
		t.Fatal(err)
	}
	if errs := set.VerifyHashes(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if got := s.SystemsOn("shared-hosting"); !slices.Equal(got, []string{"notes", "ledger"}) {
		t.Fatalf("SystemsOn = %v", got)
	}
	if got := s.ProvidersOf("notes"); !slices.Equal(got, []string{"example-cloud", "example-cdn", "example-git"}) {
		t.Fatalf("ProvidersOf = %v", got)
	}
}

// TestExampleViews compares each system's view for each audience with its
// golden file. Run with -update to rewrite them after a deliberate change.
func TestExampleViews(t *testing.T) {
	s, set := loadExample(t)
	for _, sys := range s.Systems {
		for _, aud := range audience.All {
			v, err := s.NewView(set, sys.ID, aud)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join(exampleDir, "views", sys.ID+"."+string(aud)+".json")
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
				t.Errorf("%s differs from the computed view; run go test ./scope -update after a deliberate change\n%s", golden, got)
			}
		}
	}
}

// TestExternalViewsNameNoOtherSystem is the property the views exist for:
// nothing a system's external audience sees names another system.
func TestExternalViewsNameNoOtherSystem(t *testing.T) {
	s, set := loadExample(t)
	for _, sys := range s.Systems {
		for _, aud := range []audience.Audience{audience.Public, audience.NDA} {
			v, err := s.NewView(set, sys.ID, aud)
			if err != nil {
				t.Fatal(err)
			}
			for _, it := range v.Included {
				if it.Artifact.Manifest.Target.Platform != "" && it.Artifact.Manifest.Mentions == nil {
					t.Errorf("%s/%s includes %s, a platform artifact with undeclared mentions", sys.ID, aud, it.Manifest)
				}
				for _, m := range it.Artifact.Manifest.Mentions {
					if m != sys.ID {
						t.Errorf("%s/%s includes %s, which names %s", sys.ID, aud, it.Manifest, m)
					}
				}
				body, err := os.ReadFile(it.Artifact.ArtifactPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, other := range s.Systems {
					if other.ID != sys.ID && strings.Contains(string(body), other.ID) {
						t.Errorf("%s/%s includes %s, whose content contains %q", sys.ID, aud, it.Manifest, other.ID)
					}
				}
			}
		}
	}
}

func TestInternalViewWithholdsNothing(t *testing.T) {
	s, set := loadExample(t)
	v, err := s.NewView(set, "ledger", audience.Internal)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Withheld) != 0 || len(v.Included) != 5 {
		t.Fatalf("internal view: %d included, %d withheld; want 5 and 0", len(v.Included), len(v.Withheld))
	}
}

func TestNewViewErrors(t *testing.T) {
	s, set := loadExample(t)
	if _, err := s.NewView(set, "billing", audience.Public); err == nil {
		t.Error("expected an error for an unknown system")
	}
	if _, err := s.NewView(set, "notes", "partners"); err == nil {
		t.Error("expected an error for an unknown audience")
	}
	bad := &evidence.Set{Artifacts: []evidence.Artifact{{
		ManifestPath: "x.manifest.json",
		Manifest:     evidence.Manifest{Tool: "x", GeneratedAt: "2026-01-01T00:00:00Z", ArtifactPath: "x", Target: &evidence.Target{Platform: "elsewhere"}},
	}}}
	if _, err := s.NewView(bad, "notes", audience.Public); err == nil {
		t.Error("expected an error for evidence that fails CheckEvidence")
	}
}

func TestCheckEvidence(t *testing.T) {
	s, _ := loadExample(t)
	art := func(tgt *evidence.Target, mentions ...string) *evidence.Set {
		return &evidence.Set{Artifacts: []evidence.Artifact{{
			ManifestPath: "a.manifest.json",
			Manifest:     evidence.Manifest{Tool: "t", GeneratedAt: "2026-01-01T00:00:00Z", ArtifactPath: "a", Target: tgt, Mentions: mentions},
		}}}
	}
	cases := map[string]struct {
		set  *evidence.Set
		want string
	}{
		"unknown system":      {art(&evidence.Target{System: "billing"}), `unknown system "billing"`},
		"unknown platform":    {art(&evidence.Target{Platform: "edge"}), `unknown platform "edge"`},
		"unknown component":   {art(&evidence.Target{System: "notes", Components: []string{"cache"}}), `unknown component "cache"`},
		"foreign component":   {art(&evidence.Target{System: "notes", Components: []string{"ledger-db"}}), `belongs to "ledger"`},
		"platform component":  {art(&evidence.Target{System: "notes", Components: []string{"db-server"}}), `belongs to "shared-hosting"`},
		"unknown mention":     {art(&evidence.Target{Platform: "shared-hosting"}, "billing"), `mentions unknown system "billing"`},
		"mention of platform": {art(nil, "shared-hosting"), `mentions unknown system "shared-hosting"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := s.CheckEvidence(c.set)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %s", err, c.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	valid := func() *scope.Scope {
		return &scope.Scope{
			Organization: scope.Organization{ID: "acme", Name: "Acme"},
			Providers:    []scope.Provider{{ID: "cloud", Name: "Cloud", Kind: scope.ProviderIaaS}},
			Platforms: []scope.Platform{{ID: "hosting", Name: "Hosting", Providers: []string{"cloud"},
				Components: []scope.Component{{ID: "vm", Kind: scope.ComponentHost}}}},
			Systems: []scope.System{{ID: "app", Name: "App", Platforms: []string{"hosting"}, Baseline: scope.BaselineLow,
				AddedControls: []string{"PT-2", "SC-7(5)"}, Components: []scope.Component{{ID: "app-svc", Kind: scope.ComponentService}}}},
		}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid scope: %v", err)
	}
	cases := map[string]struct {
		mutate func(*scope.Scope)
		want   string
	}{
		"version":            {func(s *scope.Scope) { s.SchemaVersion = "scope/v2" }, "schemaVersion"},
		"no systems":         {func(s *scope.Scope) { s.Systems = nil }, "no systems"},
		"bad org id":         {func(s *scope.Scope) { s.Organization.ID = "Acme Inc" }, "organization ID"},
		"empty name":         {func(s *scope.Scope) { s.Systems[0].Name = "" }, "empty name"},
		"duplicate id":       {func(s *scope.Scope) { s.Systems[0].ID = "hosting" }, "already used by a platform"},
		"duplicate comp":     {func(s *scope.Scope) { s.Systems[0].Components[0].ID = "vm" }, `component ID "vm"`},
		"provider kind":      {func(s *scope.Scope) { s.Providers[0].Kind = "mainframe" }, "unknown kind"},
		"component kind":     {func(s *scope.Scope) { s.Platforms[0].Components[0].Kind = "rack" }, "unknown kind"},
		"baseline":           {func(s *scope.Scope) { s.Systems[0].Baseline = "medium" }, "unknown baseline"},
		"control id":         {func(s *scope.Scope) { s.Systems[0].AddedControls = []string{"pt-2"} }, "not a control ID"},
		"missing platform":   {func(s *scope.Scope) { s.Systems[0].Platforms = []string{"edge"} }, `platform "edge" is not declared`},
		"provider as plat":   {func(s *scope.Scope) { s.Systems[0].Platforms = []string{"cloud"} }, "is a provider, not a platform"},
		"platform provider":  {func(s *scope.Scope) { s.Platforms[0].Providers = []string{"app"} }, "is a system, not a provider"},
		"undeclared provide": {func(s *scope.Scope) { s.Systems[0].Providers = []string{"cdn"} }, `provider "cdn" is not declared`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := valid()
			c.mutate(s)
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.json")
	doc := `{"organization":{"id":"a","name":"A"},"systems":[{"id":"s","name":"S","platformIds":["x"]}]}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scope.Load(p); err == nil || !strings.Contains(err.Error(), "platformIds") {
		t.Fatalf("got %v, want an unknown-field error", err)
	}
}
