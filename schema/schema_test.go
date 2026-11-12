package schema_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/opensecurity-dev/assessment-spec/schema"
)

func TestEmbeddedSchemasAreCurrent(t *testing.T) {
	embedded := map[string][]byte{
		schema.EvidenceManifestFile: schema.EvidenceManifest,
		schema.ScopeFile:            schema.Scope,
	}
	if len(embedded) != len(schema.All) {
		t.Fatalf("%d embedded schemas, %d generators", len(embedded), len(schema.All))
	}
	for file, gen := range schema.All {
		got, err := gen()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, embedded[file]) {
			t.Errorf("%s is stale; run go generate ./schema", file)
		}
	}
}

func required(t *testing.T, doc []byte, def string) []string {
	t.Helper()
	var s struct {
		Defs map[string]struct {
			Required []string `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(doc, &s); err != nil {
		t.Fatal(err)
	}
	d, ok := s.Defs[def]
	if !ok {
		t.Fatalf("schema lacks $defs.%s", def)
	}
	r := slices.Clone(d.Required)
	slices.Sort(r)
	return r
}

func TestRequiredFields(t *testing.T) {
	cases := []struct {
		doc  []byte
		def  string
		want []string
	}{
		{schema.EvidenceManifest, "Manifest", []string{"artifactPath", "generatedAt", "tool"}},
		{schema.Scope, "Scope", []string{"organization", "systems"}},
		{schema.Scope, "System", []string{"id", "name"}},
		{schema.Scope, "Platform", []string{"id", "name"}},
		{schema.Scope, "Provider", []string{"id", "kind", "name"}},
		{schema.Scope, "Component", []string{"id", "kind"}},
	}
	for _, c := range cases {
		if got := required(t, c.doc, c.def); !slices.Equal(got, c.want) {
			t.Errorf("%s required = %v, want %v", c.def, got, c.want)
		}
	}
}
