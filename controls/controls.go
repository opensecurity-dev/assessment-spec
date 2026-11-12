// Package controls defines control implementation records and resolves them
// into each system's effective control status. A control is recorded once on
// the scope that implements it (a system, a shared platform or a provider);
// systems inherit platform and provider records by reference, never by copy.
package controls

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/opensecurity-dev/assessment-spec/audience"
)

// SchemaVersion is the controls document version this package reads and
// writes.
const SchemaVersion = "controls/v1"

// Status is how far a control is implemented. The words follow OSCAL's
// implementation-status values.
type Status string

// Statuses. Unassessed is never written in a record; it is what resolution
// reports for a control nothing records.
const (
	StatusImplemented   Status = "implemented"
	StatusPartial       Status = "partial"
	StatusPlanned       Status = "planned"
	StatusAlternative   Status = "alternative"
	StatusNotApplicable Status = "not-applicable"
	StatusUnassessed    Status = "unassessed"
)

// Origination says where a control's implementation comes from.
type Origination string

// Originations.
const (
	// OriginSpecific: the record's own scope implements the control.
	OriginSpecific Origination = "system-specific"
	// OriginInherited: the control is implemented entirely by the scopes in
	// InheritsFrom; the record has no status of its own.
	OriginInherited Origination = "inherited"
	// OriginHybrid: the record's scope and the scopes in InheritsFrom each
	// implement part; the effective status is the weaker of the two.
	OriginHybrid Origination = "hybrid"
)

// Verification is how much a record has been checked, with the same levels
// as security-docs-spec claims.
type Verification string

// Verification levels, from the weakest.
const (
	VerificationUnverified Verification = "unverified"
	VerificationReviewed   Verification = "reviewed"
	VerificationVerified   Verification = "verified"
)

// Document is one organization's control implementation records.
type Document struct {
	// SchemaVersion is the document format version, "controls/v1". Optional;
	// when absent, version 1 is assumed.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// Records are the implementation records, at most one per control and
	// scope.
	Records []Implementation `json:"records"`
}

// Implementation records how one scope implements one control.
type Implementation struct {
	// Control is a NIST SP 800-53 control ID, such as "AC-2" or "SC-7(5)".
	Control string `json:"control"`
	// Scope is the ID of the system, platform or provider the record is for.
	Scope string `json:"scope"`
	// Status is the implementation status. Required, except for inherited
	// records, whose status comes from the scopes they inherit from.
	Status Status `json:"status,omitempty" jsonschema:"enum=implemented,enum=partial,enum=planned,enum=alternative,enum=not-applicable"`
	// Origination says where the implementation comes from.
	Origination Origination `json:"origination" jsonschema:"enum=system-specific,enum=inherited,enum=hybrid"`
	// InheritsFrom lists the platform or provider IDs an inherited or hybrid
	// record relies on: a system's platforms or providers, or a platform's
	// providers.
	InheritsFrom []string `json:"inheritsFrom,omitempty"`
	// Statement says how the control is met, as reviewed prose.
	Statement string `json:"statement,omitempty"`
	// Gap says what is missing. Required when the status is partial or
	// planned.
	Gap string `json:"gap,omitempty"`
	// Justification says why the control does not apply. Required when the
	// status is not-applicable.
	Justification string `json:"justification,omitempty"`
	// Evidence references evidence manifests by file name.
	Evidence []EvidenceRef `json:"evidence,omitempty"`
	// Findings lists findingspec finding IDs that bear on the control.
	Findings []string `json:"findings,omitempty"`
	// Attestations records who approved the record.
	Attestations []Attestation `json:"attestations,omitempty"`
	// Visibility is the widest audience that may read the record's prose.
	// Defaults to internal; a reviewer raises it.
	Visibility audience.Audience `json:"visibility,omitempty" jsonschema:"enum=public,enum=nda,enum=internal"`
}

// EvidenceRef points at an evidence manifest.
type EvidenceRef struct {
	// Manifest is the manifest's file name in its evidence set.
	Manifest string `json:"manifest"`
	// SHA256 optionally pins the artifact's hash.
	SHA256 string `json:"sha256,omitempty"`
}

// Attestation is a person's approval of a record.
type Attestation struct {
	// By names the person.
	By string `json:"by"`
	// Role is the person's role, such as "operator" or "security owner".
	Role string `json:"role,omitempty"`
	// At is when they approved it, as an RFC 3339 date or time.
	At string `json:"at"`
	// Verification is how far they checked it.
	Verification Verification `json:"verification" jsonschema:"enum=unverified,enum=reviewed,enum=verified"`
}

// EffectiveVisibility returns the record's visibility, defaulting to
// internal.
func (r Implementation) EffectiveVisibility() audience.Audience {
	if r.Visibility == "" {
		return audience.Internal
	}
	return r.Visibility
}

// EffectiveVerification returns the strongest verification among the
// record's attestations, or unverified when it has none.
func (r Implementation) EffectiveVerification() Verification {
	best := VerificationUnverified
	for _, a := range r.Attestations {
		if verificationRank(a.Verification) > verificationRank(best) {
			best = a.Verification
		}
	}
	return best
}

func verificationRank(v Verification) int {
	switch v {
	case VerificationReviewed:
		return 1
	case VerificationVerified:
		return 2
	}
	return 0
}

// Load reads a controls document. Unknown fields are rejected. Validate it
// against a scope with Document.Validate.
func Load(path string) (*Document, error) {
	f, err := os.Open(path) //nolint:gosec // reading the caller's controls document is the purpose
	if err != nil {
		return nil, fmt.Errorf("controls: opening %q: %w", path, err)
	}
	defer closeOrPanic(f)
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("controls: parsing %q: %w", path, err)
	}
	return &d, nil
}

func closeOrPanic(f *os.File) {
	if err := f.Close(); err != nil {
		panic(fmt.Sprintf("controls: closing %q: %v", f.Name(), err))
	}
}
