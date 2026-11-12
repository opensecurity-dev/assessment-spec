package schema_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/opensecurity-dev/assessment-spec/schema"
)

func TestEvidenceManifestSchemaIsCurrent(t *testing.T) {
	got, err := schema.GenerateEvidenceManifest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, schema.EvidenceManifest) {
		t.Fatal("evidence-manifest.schema.json is stale; run go generate ./schema")
	}
}

func TestEvidenceManifestRequiredFields(t *testing.T) {
	var s struct {
		Defs map[string]struct {
			Required []string `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schema.EvidenceManifest, &s); err != nil {
		t.Fatal(err)
	}
	m, ok := s.Defs["Manifest"]
	if !ok {
		t.Fatal("schema lacks $defs.Manifest")
	}
	slices.Sort(m.Required)
	if want := []string{"artifactPath", "generatedAt", "tool"}; !slices.Equal(m.Required, want) {
		t.Fatalf("required = %v, want %v", m.Required, want)
	}
}
