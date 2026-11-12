// Package oscal exports assessment-spec records to OSCAL. It is a separate
// module so that its dependencies do not reach collectors and engines that
// use only the core module.
//
// ComponentDefinition writes one system's component definition for one
// audience: a component for the system, each platform it runs on and each
// provider it relies on, with an implemented requirement for each control
// recorded at that scope. Prose and evidence follow the same audience rules
// as controls.Resolve, and findings are never exported.
package oscal

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"
	"github.com/google/uuid"

	"github.com/opensecurity-dev/assessment-spec/controls"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

// Namespace is the OSCAL property namespace for assessment-spec properties.
const Namespace = "https://github.com/opensecurity-dev/assessment-spec/ns/oscal"

// OSCALVersion is the OSCAL version written.
const OSCALVersion = oscaltypes.Version

// Property names in Namespace.
const (
	PropScopeKind            = "scope-kind"
	PropScopeID              = "scope-id"
	PropImplementationStatus = "implementation-status"
	PropEffectiveStatus      = "effective-status"
	PropOrigination          = "origination"
	PropInheritsFrom         = "inherits-from"
	PropVerification         = "verification"
	PropProviderAttestation  = "provider-attestation"
	PropProseWithheld        = "prose-withheld"
)

// Options sets what the records do not carry.
type Options struct {
	// Source is the href of the catalog or profile the controls come from,
	// such as the NIST SP 800-53 Rev 5 Low baseline profile.
	Source string
	// LastModified is the document's last-modified time. It is an option,
	// not the current time, so the same inputs give the same document.
	LastModified time.Time
	// Version is the document's version.
	Version string
}

func (o Options) validate() error {
	var errs []error
	if strings.TrimSpace(o.Source) == "" {
		errs = append(errs, errors.New("oscal: options need a catalog or profile source"))
	}
	if o.LastModified.IsZero() {
		errs = append(errs, errors.New("oscal: options need a last-modified time"))
	}
	if strings.TrimSpace(o.Version) == "" {
		errs = append(errs, errors.New("oscal: options need a version"))
	}
	return errors.Join(errs...)
}

// ComponentDefinition returns the component definition for the system and
// audience of view. UUIDs derive from the organization and scope IDs, so they
// are stable across exports.
func ComponentDefinition(s *scope.Scope, d *controls.Document, view *scope.View, opts Options) (*oscaltypes.ComponentDefinition, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if err := d.Validate(s); err != nil {
		return nil, err
	}
	sys, ok := s.System(view.System)
	if !ok {
		return nil, fmt.Errorf("oscal: unknown system %q", view.System)
	}
	e := exporter{scope: s, view: view, opts: opts, org: s.Organization.ID, byScope: map[string][]controls.Implementation{}}
	for _, r := range d.Records {
		e.byScope[r.Scope] = append(e.byScope[r.Scope], r)
	}
	e.included = map[string]bool{}
	for _, it := range view.Included {
		e.included[it.Manifest] = true
	}

	// Inherited and hybrid system records carry the status they resolve to,
	// beside the record's own, so a reader need not combine them.
	var ids []string
	for _, r := range e.byScope[sys.ID] {
		if r.Origination != controls.OriginSpecific {
			ids = append(ids, r.Control)
		}
	}
	e.effective = map[string]controls.Status{}
	if len(ids) > 0 {
		res, err := controls.Resolve(s, d, view, ids)
		if err != nil {
			return nil, err
		}
		for _, rc := range res.Controls {
			e.effective[rc.Control] = rc.Status
		}
	}

	components := []oscaltypes.DefinedComponent{e.component(scope.KindSystem, sys.ID, sys.Name, sys.Description, nil)}
	for _, id := range view.Platforms {
		p, ok := s.Platform(id)
		if !ok {
			return nil, fmt.Errorf("oscal: view names unknown platform %q", id)
		}
		components = append(components, e.component(scope.KindPlatform, p.ID, p.Name, p.Description, nil))
	}
	for _, id := range view.Providers {
		p, ok := s.Provider(id)
		if !ok {
			return nil, fmt.Errorf("oscal: view names unknown provider %q", id)
		}
		desc := fmt.Sprintf("%s, %s.", p.Name, providerKinds[p.Kind])
		components = append(components, e.component(scope.KindProvider, p.ID, p.Name, desc, p.Attestations))
	}

	party := oscaltypes.Party{UUID: e.uuid("party", s.Organization.ID), Type: "organization", Name: s.Organization.Name}
	return &oscaltypes.ComponentDefinition{
		UUID: e.uuid("component-definition", sys.ID+"/"+string(view.Audience)),
		Metadata: oscaltypes.Metadata{
			Title:        fmt.Sprintf("%s component definition (%s)", sys.Name, view.Audience),
			LastModified: opts.LastModified.UTC(),
			Version:      opts.Version,
			OscalVersion: OSCALVersion,
			Parties:      &[]oscaltypes.Party{party},
			Props:        &[]oscaltypes.Property{prop("audience", string(view.Audience))},
		},
		Components: &components,
	}, nil
}

// Marshal returns the component definition as an OSCAL JSON document.
func Marshal(cd *oscaltypes.ComponentDefinition) ([]byte, error) {
	b, err := json.MarshalIndent(oscaltypes.OscalCompleteSchema{ComponentDefinition: cd}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("oscal: encoding component definition: %w", err)
	}
	return append(b, '\n'), nil
}

type exporter struct {
	scope    *scope.Scope
	view     *scope.View
	opts     Options
	org      string
	byScope  map[string][]controls.Implementation
	included map[string]bool
	// effective maps a system record's control to its resolved status, for
	// inherited and hybrid records.
	effective map[string]controls.Status
}

var providerKinds = map[scope.ProviderKind]string{
	scope.ProviderIaaS:     "an infrastructure provider",
	scope.ProviderPaaS:     "a platform provider",
	scope.ProviderSaaS:     "a software service provider",
	scope.ProviderCDN:      "a content delivery network",
	scope.ProviderCodeHost: "a code host",
	scope.ProviderOther:    "a provider",
}

// uuid returns a name-based UUID for an object of kind with key, unique
// within the organization.
func (e exporter) uuid(kind, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(Namespace+"#"+e.org+"/"+kind+"/"+key)).String()
}

func (e exporter) component(kind, id, name, description string, attestations []string) oscaltypes.DefinedComponent {
	if strings.TrimSpace(description) == "" {
		description = name + "."
	}
	props := []oscaltypes.Property{prop(PropScopeKind, kind), prop(PropScopeID, id)}
	for _, a := range attestations {
		props = append(props, prop(PropProviderAttestation, a))
	}
	c := oscaltypes.DefinedComponent{
		UUID:        e.uuid(kind, id),
		Type:        "service",
		Title:       name,
		Description: description,
		Props:       &props,
	}
	recs := e.byScope[id]
	if len(recs) == 0 {
		return c
	}
	ids := make([]string, 0, len(recs))
	byControl := map[string]controls.Implementation{}
	for _, r := range recs {
		ids = append(ids, r.Control)
		byControl[r.Control] = r
	}
	controls.SortControlIDs(ids)
	reqs := make([]oscaltypes.ImplementedRequirementControlImplementation, 0, len(ids))
	for _, cid := range ids {
		reqs = append(reqs, e.requirement(kind, id, byControl[cid]))
	}
	c.ControlImplementations = &[]oscaltypes.ControlImplementationSet{{
		UUID:                    e.uuid("control-implementation", kind+"/"+id),
		Source:                  e.opts.Source,
		Description:             fmt.Sprintf("Controls recorded for %s.", name),
		ImplementedRequirements: reqs,
	}}
	return c
}

func (e exporter) requirement(kind, id string, r controls.Implementation) oscaltypes.ImplementedRequirementControlImplementation {
	props := []oscaltypes.Property{prop(PropOrigination, string(r.Origination))}
	if r.Status != "" {
		props = append(props, prop(PropImplementationStatus, string(r.Status)))
	}
	if st, ok := e.effective[r.Control]; ok && kind == scope.KindSystem && r.Origination != controls.OriginSpecific {
		props = append(props, prop(PropEffectiveStatus, string(st)))
	}
	for _, src := range r.InheritsFrom {
		props = append(props, prop(PropInheritsFrom, src))
	}
	props = append(props, prop(PropVerification, string(r.EffectiveVerification())))

	req := oscaltypes.ImplementedRequirementControlImplementation{
		UUID:      e.uuid("implemented-requirement", kind+"/"+id+"/"+r.Control),
		ControlId: ControlID(r.Control),
	}
	if reason := controls.ProseWithheld(e.scope, r, e.view.Audience, e.view.System); reason != "" {
		props = append(props, prop(PropProseWithheld, reason))
		req.Description = "Withheld for this audience."
	} else {
		req.Description = strings.TrimSpace(r.Statement)
		var remarks []string
		if g := strings.TrimSpace(r.Gap); g != "" {
			remarks = append(remarks, "Gap: "+g)
		}
		if j := strings.TrimSpace(r.Justification); j != "" {
			remarks = append(remarks, "Not applicable: "+j)
		}
		req.Remarks = strings.Join(remarks, "\n\n")
	}
	if req.Description == "" {
		req.Description = describe(e.scope, r)
	}
	req.Props = &props

	var links []oscaltypes.Link
	for _, ev := range r.Evidence {
		if e.included[ev.Manifest] && !slices.ContainsFunc(links, func(l oscaltypes.Link) bool { return l.Href == ev.Manifest }) {
			links = append(links, oscaltypes.Link{Href: ev.Manifest, Rel: "evidence", MediaType: "application/json"})
		}
	}
	if len(links) > 0 {
		req.Links = &links
	}
	return req
}

// describe gives a requirement with no statement a description built from
// its structure alone.
func describe(s *scope.Scope, r controls.Implementation) string {
	if len(r.InheritsFrom) == 0 {
		return "No statement recorded."
	}
	names := make([]string, 0, len(r.InheritsFrom))
	for _, id := range r.InheritsFrom {
		names = append(names, nameOf(s, id))
	}
	verb := "Inherited from"
	if r.Origination == controls.OriginHybrid {
		verb = "Shared with"
	}
	return fmt.Sprintf("%s %s.", verb, strings.Join(names, " and "))
}

func nameOf(s *scope.Scope, id string) string {
	if p, ok := s.Platform(id); ok {
		return p.Name
	}
	if p, ok := s.Provider(id); ok {
		return p.Name
	}
	return id
}

// ControlID converts a NIST SP 800-53 control ID to its OSCAL catalog form:
// "AC-2" becomes "ac-2" and "SC-7(5)" becomes "sc-7.5".
func ControlID(id string) string {
	base, enh, ok := strings.Cut(id, "(")
	out := strings.ToLower(base)
	if ok {
		out += "." + strings.TrimSuffix(enh, ")")
	}
	return out
}

func prop(name, value string) oscaltypes.Property {
	return oscaltypes.Property{Ns: Namespace, Name: name, Value: value}
}
