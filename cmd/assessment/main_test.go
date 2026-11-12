package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ex = "../../examples/example-co"

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func golden(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a fixed test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func common(system, aud string) []string {
	return []string{
		"--scope", filepath.Join(ex, "scope.json"),
		"--evidence", filepath.Join(ex, "evidence"),
		"--system", system,
		"--audience", aud,
	}
}

func withControls(args []string) []string {
	return append(args,
		"--controls", filepath.Join(ex, "controls.json"),
		"--baseline", filepath.Join(ex, "baseline.json"))
}

func TestValidateExample(t *testing.T) {
	out, err := run(t, "validate",
		"--scope", filepath.Join(ex, "scope.json"),
		"--evidence", filepath.Join(ex, "evidence"),
		"--controls", filepath.Join(ex, "controls.json"),
		"--crosswalk", filepath.Join(ex, "crosswalks", "example-framework.json"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"scope: ok (2 systems)", "evidence: 7 artifacts", "controls: 15 records", "crosswalk example-framework: 6 criteria"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestValidateReportsUndeclaredMention(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "scan.txt")
	if err := os.WriteFile(artifact, []byte("checked ledger.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"tool":"probe","generatedAt":"2026-02-01T06:00:00Z","artifactPath":"scan.txt","target":{"system":"notes"}}`
	if err := os.WriteFile(filepath.Join(dir, "scan.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, "validate", "--scope", filepath.Join(ex, "scope.json"), "--evidence", dir)
	if err == nil || !strings.Contains(err.Error(), "ledger") {
		t.Fatalf("got %v, want an undeclared mention of ledger", err)
	}
}

func TestView(t *testing.T) {
	for _, c := range []struct{ system, aud string }{{"notes", "public"}, {"ledger", "nda"}, {"notes", "internal"}} {
		out, err := run(t, append([]string{"view"}, common(c.system, c.aud)...)...)
		if err != nil {
			t.Fatal(err)
		}
		if want := golden(t, filepath.Join(ex, "views", c.system+"."+c.aud+".json")); out != want {
			t.Errorf("view %s %s differs from the golden view:\n%s", c.system, c.aud, out)
		}
	}
}

func TestResolve(t *testing.T) {
	for _, c := range []struct{ system, aud string }{{"notes", "public"}, {"ledger", "internal"}} {
		out, err := run(t, append([]string{"resolve"}, withControls(common(c.system, c.aud))...)...)
		if err != nil {
			t.Fatal(err)
		}
		if want := golden(t, filepath.Join(ex, "resolutions", c.system+"."+c.aud+".json")); out != want {
			t.Errorf("resolve %s %s differs from the golden resolution:\n%s", c.system, c.aud, out)
		}
	}
}

func TestCoverage(t *testing.T) {
	args := append([]string{"coverage"}, withControls(common("ledger", "public"))...)
	out, err := run(t, append(args, "--crosswalk", filepath.Join(ex, "crosswalks", "example-framework.json"))...)
	if err != nil {
		t.Fatal(err)
	}
	if want := golden(t, filepath.Join(ex, "coverage", "ledger.example-framework.json")); out != want {
		t.Errorf("coverage differs from the golden coverage:\n%s", out)
	}
}

func TestFreshness(t *testing.T) {
	ev := filepath.Join(ex, "evidence")
	out, err := run(t, "freshness", "--evidence", ev, "--now", "2026-02-01T12:00:00Z", "--db-max-age", "0")
	if err != nil {
		t.Fatalf("fresh evidence: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"status": "fresh"`) {
		t.Errorf("want fresh tools:\n%s", out)
	}
	out, err = run(t, "freshness", "--evidence", ev, "--now", "2026-02-05T00:00:00Z", "--require", "zap")
	if !errors.Is(err, errFailed) {
		t.Fatalf("stale evidence and a missing tool: got %v", err)
	}
	for _, want := range []string{`"status": "stale"`, `"tool": "zap"`, `"status": "missing"`} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %s:\n%s", want, out)
		}
	}
	if _, err := run(t, "freshness", "--evidence", ev, "--now", "yesterday"); err == nil {
		t.Error("bad --now: want an error")
	}
}

func TestBadInputs(t *testing.T) {
	cases := map[string][]string{
		"unknown audience": append([]string{"view"}, common("notes", "everyone")...),
		"unknown system":   append([]string{"view"}, common("chat", "public")...),
		"missing flag":     {"resolve", "--scope", filepath.Join(ex, "scope.json")},
		"missing scope":    {"validate", "--scope", filepath.Join(ex, "absent.json")},
	}
	for name, args := range cases {
		if _, err := run(t, args...); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
