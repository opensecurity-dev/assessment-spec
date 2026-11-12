// Package scope defines the scope document: an organization, the external
// providers it relies on, the shared platforms it operates, and the systems
// (separately marketed products) that run on them. It validates the document
// and its references, and builds per-system, per-audience views of evidence.
package scope

import (
	"encoding/json"
	"fmt"
	"os"
)

// SchemaVersion is the scope document version this package reads and writes.
const SchemaVersion = "scope/v1"

// Scope is one organization's scope document.
type Scope struct {
	// SchemaVersion is the document format version, "scope/v1". Optional;
	// when absent, version 1 is assumed.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// Organization is the organization that operates the platforms and systems.
	Organization Organization `json:"organization"`
	// Providers are external services the platforms and systems build on, and
	// from which they inherit controls.
	Providers []Provider `json:"providers,omitempty"`
	// Platforms are shared infrastructure the organization operates. A
	// platform is never assessed alone; its controls are inherited by the
	// systems that run on it.
	Platforms []Platform `json:"platforms,omitempty"`
	// Systems are what an audience buys or uses. Each gets its own
	// assessment, documents and audience.
	Systems []System `json:"systems"`
}

// Organization identifies the operator.
type Organization struct {
	// ID is a lowercase identifier, such as "example-co".
	ID string `json:"id"`
	// Name is the organization's display name.
	Name string `json:"name"`
}

// ProviderKind classifies an external provider.
type ProviderKind string

// Provider kinds.
const (
	ProviderIaaS     ProviderKind = "iaas"
	ProviderPaaS     ProviderKind = "paas"
	ProviderSaaS     ProviderKind = "saas"
	ProviderCDN      ProviderKind = "cdn"
	ProviderCodeHost ProviderKind = "code-host"
	ProviderOther    ProviderKind = "other"
)

// Provider is an external service whose controls are inherited.
type Provider struct {
	// ID is a lowercase identifier, unique across providers, platforms and
	// systems.
	ID string `json:"id"`
	// Name is the provider's display name.
	Name string `json:"name"`
	// Kind classifies the provider.
	Kind ProviderKind `json:"kind" jsonschema:"enum=iaas,enum=paas,enum=saas,enum=cdn,enum=code-host,enum=other"`
	// Attestations describes the provider's own reports or certifications
	// that the inherited controls rest on, such as "SOC 2 Type II report,
	// under NDA".
	Attestations []string `json:"attestations,omitempty"`
}

// ComponentKind classifies a component.
type ComponentKind string

// Component kinds.
const (
	ComponentService  ComponentKind = "service"
	ComponentDatabase ComponentKind = "database"
	ComponentHost     ComponentKind = "host"
	ComponentNetwork  ComponentKind = "network"
	ComponentStorage  ComponentKind = "storage"
	ComponentPipeline ComponentKind = "pipeline"
	ComponentOther    ComponentKind = "other"
)

// Component is a part of a platform or system that evidence can target.
type Component struct {
	// ID is a lowercase identifier, unique across the scope document.
	ID string `json:"id"`
	// Name is an optional display name.
	Name string `json:"name,omitempty"`
	// Kind classifies the component.
	Kind ComponentKind `json:"kind" jsonschema:"enum=service,enum=database,enum=host,enum=network,enum=storage,enum=pipeline,enum=other"`
}

// Platform is shared infrastructure operated by the organization.
type Platform struct {
	// ID is a lowercase identifier, unique across providers, platforms and
	// systems.
	ID string `json:"id"`
	// Name is the platform's display name, for internal use.
	Name string `json:"name"`
	// Description says what the platform provides.
	Description string `json:"description,omitempty"`
	// Providers lists the IDs of providers the platform builds on.
	Providers []string `json:"providers,omitempty"`
	// Components lists the platform's parts.
	Components []Component `json:"components,omitempty"`
}

// Baseline is a NIST SP 800-53 Rev 5 control baseline.
type Baseline string

// Baselines.
const (
	BaselineLow      Baseline = "low"
	BaselineModerate Baseline = "moderate"
	BaselineHigh     Baseline = "high"
)

// System is a separately marketed product.
type System struct {
	// ID is a lowercase identifier, unique across providers, platforms and
	// systems.
	ID string `json:"id"`
	// Name is the product's display name.
	Name string `json:"name"`
	// Description says what the product does.
	Description string `json:"description,omitempty"`
	// Platforms lists the IDs of the shared platforms the system runs on.
	Platforms []string `json:"platforms,omitempty"`
	// Providers lists the IDs of providers the system uses directly, beyond
	// those of its platforms.
	Providers []string `json:"providers,omitempty"`
	// Components lists the parts the system owns.
	Components []Component `json:"components,omitempty"`
	// Baseline is the control baseline the system is assessed against.
	Baseline Baseline `json:"baseline,omitempty" jsonschema:"enum=low,enum=moderate,enum=high"`
	// AddedControls lists control IDs added to the baseline for this system,
	// such as the PT family for a system that handles children's data.
	AddedControls []string `json:"addedControls,omitempty"`
	// Disclosure says how the system's external documents describe what it
	// shares with other systems.
	Disclosure *Disclosure `json:"disclosure,omitempty"`
}

// Disclosure holds the wording a system's external documents use for shared
// infrastructure.
type Disclosure struct {
	// SharedPlatformStatement describes the shared platform without naming
	// any other system. Sharing is material to an assessment, so it is stated.
	SharedPlatformStatement string `json:"sharedPlatformStatement,omitempty"`
}

// Load reads and validates a scope document. Unknown fields are rejected.
func Load(path string) (*Scope, error) {
	f, err := os.Open(path) //nolint:gosec // reading the caller's scope document is the purpose
	if err != nil {
		return nil, fmt.Errorf("scope: opening %q: %w", path, err)
	}
	defer closeOrPanic(f)
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var s Scope
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scope: parsing %q: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("scope: %q: %w", path, err)
	}
	return &s, nil
}

// System returns the system with id.
func (s *Scope) System(id string) (*System, bool) {
	for i := range s.Systems {
		if s.Systems[i].ID == id {
			return &s.Systems[i], true
		}
	}
	return nil, false
}

// Platform returns the platform with id.
func (s *Scope) Platform(id string) (*Platform, bool) {
	for i := range s.Platforms {
		if s.Platforms[i].ID == id {
			return &s.Platforms[i], true
		}
	}
	return nil, false
}

// SystemsOn returns the IDs of the systems that run on platform id, in
// document order.
func (s *Scope) SystemsOn(platformID string) []string {
	var out []string
	for _, sys := range s.Systems {
		for _, p := range sys.Platforms {
			if p == platformID {
				out = append(out, sys.ID)
				break
			}
		}
	}
	return out
}

// ProvidersOf returns the IDs of the providers a system relies on, directly
// or through its platforms, without duplicates, in first-seen order.
func (s *Scope) ProvidersOf(systemID string) []string {
	sys, ok := s.System(systemID)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(ids []string) {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	for _, pid := range sys.Platforms {
		if p, ok := s.Platform(pid); ok {
			add(p.Providers)
		}
	}
	add(sys.Providers)
	return out
}

func closeOrPanic(f *os.File) {
	if err := f.Close(); err != nil {
		panic(fmt.Sprintf("scope: closing %q: %v", f.Name(), err))
	}
}
