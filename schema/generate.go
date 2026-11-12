package schema

import (
	"encoding/json"
	"fmt"

	"github.com/invopop/jsonschema"

	"github.com/opensecurity-dev/assessment-spec/evidence"
)

// BaseID is the prefix of every schema's $id.
const BaseID = "https://github.com/opensecurity-dev/assessment-spec/schema/"

// EvidenceManifestFile is the evidence manifest schema's file name.
const EvidenceManifestFile = "evidence-manifest.schema.json"

// GenerateEvidenceManifest builds the evidence manifest schema from the Go
// types. It reads field comments from ../evidence, so it runs from this
// directory, as go generate and go test do.
func GenerateEvidenceManifest() ([]byte, error) {
	r := &jsonschema.Reflector{RequiredFromJSONSchemaTags: false}
	if err := r.AddGoComments("github.com/opensecurity-dev/assessment-spec/schema", "../evidence"); err != nil {
		return nil, fmt.Errorf("schema: read Go comments: %w", err)
	}
	s := r.Reflect(&evidence.Manifest{})
	s.ID = BaseID + EvidenceManifestFile
	s.Title = "Evidence manifest"
	s.Description = "Metadata a collector writes once beside each evidence artifact: provenance, freshness inputs, scope and integrity."
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("schema: encode: %w", err)
	}
	return append(b, '\n'), nil
}
