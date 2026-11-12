// Package evidence defines the evidence manifest: the record a collector
// writes beside each artifact it produces, and that a compliance engine reads.
// It also loads sets of manifests, verifies artifact hashes and evaluates
// freshness.
package evidence

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// SchemaVersion is the manifest version this package writes and reads.
const SchemaVersion = "evidence-manifest/v1"

// ManifestSuffix identifies an evidence manifest in an evidence directory.
const ManifestSuffix = ".manifest.json"

// Kind classifies an artifact.
type Kind string

// Artifact kinds.
const (
	KindSBOM           Kind = "sbom"
	KindVEX            Kind = "vex"
	KindFindings       Kind = "findings"
	KindScanReport     Kind = "scan-report"
	KindConfigSnapshot Kind = "config-snapshot"
	KindBenchmark      Kind = "benchmark"
	KindAttestation    Kind = "attestation"
	KindOther          Kind = "other"
)

// Valid reports whether k is empty or a defined kind.
func (k Kind) Valid() bool {
	switch k {
	case "", KindSBOM, KindVEX, KindFindings, KindScanReport, KindConfigSnapshot, KindBenchmark, KindAttestation, KindOther:
		return true
	}
	return false
}

// Manifest is the metadata a collector writes once beside each evidence
// artifact. Only Tool, GeneratedAt and ArtifactPath are required, so manifests
// that carry only those (and SHA256) remain valid. A manifest never holds
// credentials, which is why it has no command-line field.
type Manifest struct {
	// SchemaVersion is the manifest format version, "evidence-manifest/v1".
	// Optional; when absent, version 1 is assumed.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// Tool is the program that produced the artifact, such as "govulncheck".
	Tool string `json:"tool"`
	// ToolVersion is the tool's version string.
	ToolVersion string `json:"toolVersion,omitempty"`
	// GeneratedAt is when the artifact was produced, in RFC 3339.
	GeneratedAt string `json:"generatedAt"`
	// DatabaseUpdatedAt is when the tool's vulnerability database or rule set
	// was last updated, in RFC 3339, for tools that have one.
	DatabaseUpdatedAt string `json:"databaseUpdatedAt,omitempty"`
	// ArtifactPath is the artifact file, relative to the manifest's directory.
	ArtifactPath string `json:"artifactPath"`
	// SHA256 is the lowercase hex SHA-256 of the artifact.
	SHA256 string `json:"sha256,omitempty"`
	// Kind classifies the artifact.
	Kind Kind `json:"kind,omitempty" jsonschema:"enum=sbom,enum=vex,enum=findings,enum=scan-report,enum=config-snapshot,enum=benchmark,enum=attestation,enum=other"`
	// MediaType is the artifact's media type, such as
	// "application/vnd.cyclonedx+json".
	MediaType string `json:"mediaType,omitempty"`
	// Target is what the artifact is about.
	Target *Target `json:"target,omitempty"`
	// Mentions lists the IDs of systems whose names appear in the artifact's
	// content, so views can withhold it from other systems' audiences. An
	// empty list declares that it names none; an absent field declares
	// nothing, and a platform artifact without it is withheld from external
	// audiences.
	Mentions []string `json:"mentions,omitzero"`
	// Controls lists control IDs the artifact supports, as a hint; a
	// compliance engine decides what it supports.
	Controls []string `json:"controls,omitempty"`
}

// Target identifies what an artifact is about. Exactly one of System and
// Platform is set when a target is given.
type Target struct {
	// System is the ID of a system (a product) in the scope document.
	System string `json:"system,omitempty"`
	// Platform is the ID of a shared platform in the scope document.
	Platform string `json:"platform,omitempty"`
	// Components lists component IDs within the system or platform.
	Components []string `json:"components,omitempty"`
	// Revision is the source revision or release the artifact describes.
	Revision string `json:"revision,omitempty"`
	// Environment is the deployment environment, such as "staging" or "prod".
	Environment string `json:"environment,omitempty"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// GeneratedTime parses GeneratedAt.
func (m Manifest) GeneratedTime() (time.Time, error) {
	return parseTime(m.Tool, "generatedAt", m.GeneratedAt)
}

// DatabaseTime parses DatabaseUpdatedAt. ok is false when it is not set.
func (m Manifest) DatabaseTime() (t time.Time, ok bool, err error) {
	if m.DatabaseUpdatedAt == "" {
		return time.Time{}, false, nil
	}
	t, err = parseTime(m.Tool, "databaseUpdatedAt", m.DatabaseUpdatedAt)
	return t, err == nil, err
}

// Validate checks required fields, formats, the schema version and that the
// artifact path stays inside the manifest's directory. It returns every
// problem found, joined.
func (m Manifest) Validate() error {
	var errs []error
	if m.SchemaVersion != "" && m.SchemaVersion != SchemaVersion {
		errs = append(errs, fmt.Errorf("evidence: tool %q manifest has unsupported schemaVersion %q", m.Tool, m.SchemaVersion))
	}
	if strings.TrimSpace(m.Tool) == "" {
		errs = append(errs, errors.New("evidence: manifest has empty tool"))
	}
	if err := checkArtifactPath(m.ArtifactPath); err != nil {
		errs = append(errs, fmt.Errorf("evidence: tool %q: %w", m.Tool, err))
	}
	if _, err := m.GeneratedTime(); err != nil {
		errs = append(errs, err)
	}
	if _, _, err := m.DatabaseTime(); err != nil {
		errs = append(errs, err)
	}
	if m.SHA256 != "" && !sha256Hex.MatchString(m.SHA256) {
		errs = append(errs, fmt.Errorf("evidence: tool %q sha256 must be 64 lowercase hex characters", m.Tool))
	}
	if !m.Kind.Valid() {
		errs = append(errs, fmt.Errorf("evidence: tool %q has unknown kind %q", m.Tool, m.Kind))
	}
	if t := m.Target; t != nil && (t.System == "") == (t.Platform == "") {
		errs = append(errs, fmt.Errorf("evidence: tool %q target must name exactly one of system and platform", m.Tool))
	}
	return errors.Join(errs...)
}

// checkArtifactPath rejects empty, absolute and escaping paths, so a manifest
// cannot point a reader outside its evidence directory.
func checkArtifactPath(p string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("empty artifactPath")
	}
	if path.IsAbs(p) || filepath.IsAbs(p) || strings.Contains(p, `\`) {
		return fmt.Errorf("artifactPath %q must be a relative, slash-separated path", p)
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("artifactPath %q leaves the manifest's directory", p)
	}
	return nil
}

func parseTime(tool, field, v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("evidence: tool %q has unparseable %s %q: %w", tool, field, v, err)
	}
	return t, nil
}
