package schema

import (
	"encoding/json"
	"fmt"

	"github.com/invopop/jsonschema"

	"github.com/opensecurity-dev/assessment-spec/controls"
	"github.com/opensecurity-dev/assessment-spec/crosswalk"
	"github.com/opensecurity-dev/assessment-spec/evidence"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

// BaseID is the prefix of every schema's $id.
const BaseID = "https://github.com/opensecurity-dev/assessment-spec/schema/"

// Schema file names.
const (
	EvidenceManifestFile = "evidence-manifest.schema.json"
	ScopeFile            = "scope.schema.json"
	ControlsFile         = "controls.schema.json"
	CrosswalkFile        = "crosswalk.schema.json"
)

// GenerateEvidenceManifest builds the evidence manifest schema from the Go
// types. Like every generator here, it reads field comments from the source
// packages, so it runs from this directory, as go generate and go test do.
func GenerateEvidenceManifest() ([]byte, error) {
	return generate(&evidence.Manifest{}, "../evidence", EvidenceManifestFile,
		"Evidence manifest",
		"Metadata a collector writes once beside each evidence artifact: provenance, freshness inputs, scope and integrity.")
}

// GenerateScope builds the scope document schema from the Go types.
func GenerateScope() ([]byte, error) {
	return generate(&scope.Scope{}, "../scope", ScopeFile,
		"Scope",
		"An organization's external providers, shared platforms and separately marketed systems, and which systems run on which platforms.")
}

// GenerateControls builds the controls document schema from the Go types.
func GenerateControls() ([]byte, error) {
	return generate(&controls.Document{}, "../controls", ControlsFile,
		"Controls",
		"Control implementation records for systems, shared platforms and providers, with origination, inheritance, prose, evidence references and attestations.")
}

// GenerateCrosswalk builds the crosswalk schema from the Go types.
func GenerateCrosswalk() ([]byte, error) {
	return generate(&crosswalk.Crosswalk{}, "../crosswalk", CrosswalkFile,
		"Crosswalk",
		"A framework's criterion identifiers mapped to NIST SP 800-53 control IDs, with the mapping's source and licence. Identifiers only.")
}

// All maps each schema file name to its generator.
var All = map[string]func() ([]byte, error){
	EvidenceManifestFile: GenerateEvidenceManifest,
	ScopeFile:            GenerateScope,
	ControlsFile:         GenerateControls,
	CrosswalkFile:        GenerateCrosswalk,
}

func generate(v any, srcDir, file, title, description string) ([]byte, error) {
	r := &jsonschema.Reflector{RequiredFromJSONSchemaTags: false}
	if err := r.AddGoComments("github.com/opensecurity-dev/assessment-spec/schema", srcDir); err != nil {
		return nil, fmt.Errorf("schema: read Go comments for %s: %w", file, err)
	}
	s := r.Reflect(v)
	s.ID = jsonschema.ID(BaseID + file)
	s.Title = title
	s.Description = description
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("schema: encode %s: %w", file, err)
	}
	return append(b, '\n'), nil
}
