package scope

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opensecurity-dev/assessment-spec/evidence"
)

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	controlPattern = regexp.MustCompile(`^[A-Z]{2}-[0-9]+(\([0-9]+\))?$`)
)

// Validate checks identifiers, uniqueness, enumerations and references, and
// returns every problem found, joined. Providers, platforms and systems share
// one identifier namespace, as do all components, so a manifest's target and
// mentions are unambiguous.
func (s *Scope) Validate() error {
	v := &validator{ids: map[string]string{}, components: map[string]string{}}
	if s.SchemaVersion != "" && s.SchemaVersion != SchemaVersion {
		v.addf("unsupported schemaVersion %q", s.SchemaVersion)
	}
	v.id("organization", s.Organization.ID)
	if strings.TrimSpace(s.Organization.Name) == "" {
		v.addf("organization has empty name")
	}
	if len(s.Systems) == 0 {
		v.addf("scope declares no systems")
	}

	for _, p := range s.Providers {
		v.entity("provider", p.ID, p.Name)
		if !validProviderKind(p.Kind) {
			v.addf("provider %q has unknown kind %q", p.ID, p.Kind)
		}
	}
	for _, p := range s.Platforms {
		v.entity("platform", p.ID, p.Name)
		v.componentsOf("platform", p.ID, p.Components)
	}
	for _, sys := range s.Systems {
		v.entity("system", sys.ID, sys.Name)
		v.componentsOf("system", sys.ID, sys.Components)
		switch sys.Baseline {
		case "", BaselineLow, BaselineModerate, BaselineHigh:
		default:
			v.addf("system %q has unknown baseline %q", sys.ID, sys.Baseline)
		}
		for _, c := range sys.AddedControls {
			if !controlPattern.MatchString(c) {
				v.addf("system %q added control %q is not a control ID such as AC-2 or SC-7(5)", sys.ID, c)
			}
		}
	}

	// References, checked after every ID is known.
	for _, p := range s.Platforms {
		v.refs("platform "+quote(p.ID)+" provider", p.Providers, "provider")
	}
	for _, sys := range s.Systems {
		v.refs("system "+quote(sys.ID)+" platform", sys.Platforms, "platform")
		v.refs("system "+quote(sys.ID)+" provider", sys.Providers, "provider")
	}
	return errors.Join(v.errs...)
}

// CheckEvidence checks every manifest's target and mentions against the
// scope: the target names a known system or platform, its components belong
// to it, and each mention is a known system.
func (s *Scope) CheckEvidence(set *evidence.Set) error {
	owner := map[string]string{} // component ID -> owning system or platform ID
	for _, p := range s.Platforms {
		for _, c := range p.Components {
			owner[c.ID] = p.ID
		}
	}
	for _, sys := range s.Systems {
		for _, c := range sys.Components {
			owner[c.ID] = sys.ID
		}
	}
	var errs []error
	for _, a := range set.Artifacts {
		m := a.Manifest
		where := fmt.Sprintf("evidence %q (tool %q)", a.ManifestPath, m.Tool)
		if t := m.Target; t != nil {
			targetID := t.System
			if t.System != "" {
				if _, ok := s.System(t.System); !ok {
					errs = append(errs, fmt.Errorf("%s targets unknown system %q", where, t.System))
				}
			} else {
				targetID = t.Platform
				if _, ok := s.Platform(t.Platform); !ok {
					errs = append(errs, fmt.Errorf("%s targets unknown platform %q", where, t.Platform))
				}
			}
			for _, c := range t.Components {
				if got, ok := owner[c]; !ok {
					errs = append(errs, fmt.Errorf("%s names unknown component %q", where, c))
				} else if got != targetID {
					errs = append(errs, fmt.Errorf("%s names component %q, which belongs to %q, not its target %q", where, c, got, targetID))
				}
			}
		}
		for _, id := range m.Mentions {
			if _, ok := s.System(id); !ok {
				errs = append(errs, fmt.Errorf("%s mentions unknown system %q", where, id))
			}
		}
	}
	return errors.Join(errs...)
}

type validator struct {
	ids        map[string]string // entity ID -> kind
	components map[string]string // component ID -> owner
	errs       []error
}

func (v *validator) addf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("scope: "+format, args...))
}

func (v *validator) id(kind, id string) bool {
	if !idPattern.MatchString(id) {
		v.addf("%s ID %q must be lowercase letters, digits and hyphens", kind, id)
		return false
	}
	return true
}

func (v *validator) entity(kind, id, name string) {
	if !v.id(kind, id) {
		return
	}
	if prev, dup := v.ids[id]; dup {
		v.addf("%s ID %q is already used by a %s", kind, id, prev)
	} else {
		v.ids[id] = kind
	}
	if strings.TrimSpace(name) == "" {
		v.addf("%s %q has empty name", kind, id)
	}
}

func (v *validator) componentsOf(kind, ownerID string, cs []Component) {
	for _, c := range cs {
		if !v.id("component", c.ID) {
			continue
		}
		if prev, dup := v.components[c.ID]; dup {
			v.addf("component ID %q in %s %q is already used in %q", c.ID, kind, ownerID, prev)
		} else {
			v.components[c.ID] = ownerID
		}
		if !validComponentKind(c.Kind) {
			v.addf("component %q has unknown kind %q", c.ID, c.Kind)
		}
	}
}

func (v *validator) refs(what string, ids []string, kind string) {
	for _, id := range ids {
		if got, ok := v.ids[id]; !ok {
			v.addf("%s %q is not declared", what, id)
		} else if got != kind {
			v.addf("%s %q is a %s, not a %s", what, id, got, kind)
		}
	}
}

func validProviderKind(k ProviderKind) bool {
	switch k {
	case ProviderIaaS, ProviderPaaS, ProviderSaaS, ProviderCDN, ProviderCodeHost, ProviderOther:
		return true
	}
	return false
}

func validComponentKind(k ComponentKind) bool {
	switch k {
	case ComponentService, ComponentDatabase, ComponentHost, ComponentNetwork, ComponentStorage, ComponentPipeline, ComponentOther:
		return true
	}
	return false
}

func quote(s string) string { return fmt.Sprintf("%q", s) }
