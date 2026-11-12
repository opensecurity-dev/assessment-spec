// Package schema holds the JSON Schemas for the assessment-spec documents,
// generated from the Go types. Run `go generate ./schema` after changing them.
package schema

import _ "embed"

//go:generate go run ./gen

// EvidenceManifest is the generated schema for evidence.Manifest.
//
//go:embed evidence-manifest.schema.json
var EvidenceManifest []byte

// Scope is the generated schema for scope.Scope.
//
//go:embed scope.schema.json
var Scope []byte

// Controls is the generated schema for controls.Document.
//
//go:embed controls.schema.json
var Controls []byte
