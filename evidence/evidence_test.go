package evidence_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opensecurity-dev/assessment-spec/evidence"
)

const helloSHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" // sha256("hello")

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateMinimalManifest(t *testing.T) {
	m := evidence.Manifest{Tool: "trivy", GeneratedAt: "2026-01-02T03:04:05Z", ArtifactPath: "trivy.json"}
	if err := m.Validate(); err != nil {
		t.Fatalf("minimal manifest: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	ok := evidence.Manifest{Tool: "syft", GeneratedAt: "2026-01-02T03:04:05Z", ArtifactPath: "sbom.cdx.json"}
	cases := map[string]func(*evidence.Manifest){
		"empty tool":        func(m *evidence.Manifest) { m.Tool = " " },
		"bad time":          func(m *evidence.Manifest) { m.GeneratedAt = "yesterday" },
		"bad database time": func(m *evidence.Manifest) { m.DatabaseUpdatedAt = "2026-01-02" },
		"absolute path":     func(m *evidence.Manifest) { m.ArtifactPath = "/etc/passwd" },
		"escaping path":     func(m *evidence.Manifest) { m.ArtifactPath = "a/../../x" },
		"backslash path":    func(m *evidence.Manifest) { m.ArtifactPath = `..\x` },
		"upper-case hash":   func(m *evidence.Manifest) { m.SHA256 = strings.ToUpper(helloSHA) },
		"unknown kind":      func(m *evidence.Manifest) { m.Kind = "photo" },
		"future version":    func(m *evidence.Manifest) { m.SchemaVersion = "evidence-manifest/v2" },
		"target with both": func(m *evidence.Manifest) {
			m.Target = &evidence.Target{System: "notes", Platform: "shared-hosting"}
		},
		"target with neither": func(m *evidence.Manifest) { m.Target = &evidence.Target{Revision: "abc"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := ok
			mutate(&m)
			if err := m.Validate(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestLoadSetAndVerifyHashes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.json", "hello")
	write(t, dir, "b.json", "tampered")
	write(t, dir, "a.manifest.json", `{"tool":"govulncheck","generatedAt":"2026-01-02T03:04:05Z","artifactPath":"a.json","sha256":"`+helloSHA+`"}`)
	write(t, dir, "b.manifest.json", `{"tool":"syft","generatedAt":"2026-01-02T03:04:05Z","artifactPath":"b.json","sha256":"`+helloSHA+`"}`)
	write(t, dir, "notes.txt", "ignored")

	set, err := evidence.LoadSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(set.Tools(), ","); got != "govulncheck,syft" {
		t.Fatalf("tools = %s", got)
	}
	errs := set.VerifyHashes()
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "syft") {
		t.Fatalf("VerifyHashes = %v; want one syft mismatch", errs)
	}
}

func TestLoadSetRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.manifest.json", `{"tool":"x","generatedAt":"2026-01-02T03:04:05Z","artifactPath":"a","toolVersoin":"1"}`)
	if _, err := evidence.LoadSet(dir); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestFreshness(t *testing.T) {
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	m := func(tool, gen, db string) evidence.Artifact {
		return evidence.Artifact{Manifest: evidence.Manifest{Tool: tool, GeneratedAt: gen, DatabaseUpdatedAt: db, ArtifactPath: tool + ".json"}}
	}
	set := &evidence.Set{Artifacts: []evidence.Artifact{
		m("fresh", "2026-01-09T12:00:00Z", "2026-01-09T00:00:00Z"),
		m("aging", "2026-01-08T12:00:00Z", ""),
		m("old", "2026-01-07T00:00:00Z", ""),
		m("old", "2026-01-09T20:00:00Z", ""), // the newest artifact counts
		m("olddb", "2026-01-09T12:00:00Z", "2025-12-01T00:00:00Z"),
	}}
	r, err := set.Freshness(now, evidence.DefaultPolicy(), "fresh", "absent")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]evidence.Status{
		"absent": evidence.StatusMissing,
		"aging":  evidence.StatusWarn,
		"fresh":  evidence.StatusFresh,
		"old":    evidence.StatusFresh,
		"olddb":  evidence.StatusStale,
	}
	if len(r.Tools) != len(want) {
		t.Fatalf("got %d tools, want %d: %+v", len(r.Tools), len(want), r.Tools)
	}
	for _, ts := range r.Tools {
		if ts.Status != want[ts.Tool] {
			t.Errorf("%s: status %s (%s), want %s", ts.Tool, ts.Status, ts.Reason, want[ts.Tool])
		}
	}
	if r.OK() || len(r.Failing()) != 2 {
		t.Fatalf("Failing = %+v; want absent and olddb", r.Failing())
	}
}

func TestFreshnessPerToolOverride(t *testing.T) {
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	set := &evidence.Set{Artifacts: []evidence.Artifact{{Manifest: evidence.Manifest{Tool: "host-scan", GeneratedAt: "2026-01-05T00:00:00Z", ArtifactPath: "r.xml"}}}}
	p := evidence.DefaultPolicy()
	p.Tools = map[string]evidence.Thresholds{"host-scan": {WarnAfter: 7 * 24 * time.Hour, FailAfter: 31 * 24 * time.Hour}}
	r, err := set.Freshness(now, p)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() || r.Tools[0].Status != evidence.StatusFresh {
		t.Fatalf("got %+v; want fresh under the override", r.Tools)
	}
}

func TestFreshnessRejectsInvalidManifest(t *testing.T) {
	set := &evidence.Set{Artifacts: []evidence.Artifact{{Manifest: evidence.Manifest{Tool: "x", GeneratedAt: "soon", ArtifactPath: "a"}}}}
	if _, err := set.Freshness(time.Now(), evidence.DefaultPolicy()); err == nil {
		t.Fatal("expected an error")
	}
}
