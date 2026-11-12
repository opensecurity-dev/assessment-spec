package controls

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/opensecurity-dev/assessment-spec/scope"
)

var (
	controlPattern = regexp.MustCompile(`^[A-Z]{2}-[0-9]+(\([0-9]+\))?$`)
	sha256Hex      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidControlID reports whether id is a NIST SP 800-53 control or
// enhancement ID, such as "AC-2" or "SC-7(5)".
func ValidControlID(id string) bool { return controlPattern.MatchString(id) }

// Validate checks every record against the scope and returns every problem,
// joined: control IDs, known scopes, status and origination rules, required
// gaps and justifications, permitted inheritance sources, attestations and
// evidence references, and at most one record per control and scope.
func (d *Document) Validate(s *scope.Scope) error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("controls: "+format, args...)) }
	if d.SchemaVersion != "" && d.SchemaVersion != SchemaVersion {
		add("unsupported schemaVersion %q", d.SchemaVersion)
	}
	seen := map[string]bool{}
	for _, r := range d.Records {
		where := fmt.Sprintf("%s at %q", r.Control, r.Scope)
		if !ValidControlID(r.Control) {
			add("record %s: control %q is not a control ID such as AC-2 or SC-7(5)", where, r.Control)
		}
		kind := s.KindOf(r.Scope)
		if kind == "" {
			add("record %s: scope %q is not a system, platform or provider", where, r.Scope)
		}
		key := r.Control + "\x00" + r.Scope
		if seen[key] {
			add("record %s: duplicate record for the control and scope", where)
		}
		seen[key] = true

		switch r.Origination {
		case OriginSpecific:
			if len(r.InheritsFrom) > 0 {
				add("record %s: a system-specific record inherits from nothing", where)
			}
		case OriginInherited:
			if r.Status != "" {
				add("record %s: an inherited record takes its status from its sources and sets none", where)
			}
			if len(r.InheritsFrom) == 0 {
				add("record %s: an inherited record needs inheritsFrom", where)
			}
		case OriginHybrid:
			if len(r.InheritsFrom) == 0 {
				add("record %s: a hybrid record needs inheritsFrom", where)
			}
		default:
			add("record %s: unknown origination %q", where, r.Origination)
		}
		if r.Origination != OriginInherited {
			switch r.Status {
			case StatusImplemented, StatusAlternative:
			case StatusPartial, StatusPlanned:
				if strings.TrimSpace(r.Gap) == "" {
					add("record %s: a %s record needs a gap", where, r.Status)
				}
			case StatusNotApplicable:
				if strings.TrimSpace(r.Justification) == "" {
					add("record %s: a not-applicable record needs a justification", where)
				}
			default:
				add("record %s: unknown or missing status %q", where, r.Status)
			}
		}
		if kind != "" {
			allowed := sources(s, r.Scope, kind)
			for _, src := range r.InheritsFrom {
				if !slices.Contains(allowed, src) {
					add("record %s: cannot inherit from %q; allowed: %s", where, src, orNone(allowed))
				}
			}
		}
		if r.Visibility != "" && !r.Visibility.Valid() {
			add("record %s: unknown visibility %q", where, r.Visibility)
		}
		for _, a := range r.Attestations {
			if strings.TrimSpace(a.By) == "" {
				add("record %s: an attestation has no by", where)
			}
			if !validTime(a.At) {
				add("record %s: attestation at %q is not an RFC 3339 date or time", where, a.At)
			}
			switch a.Verification {
			case VerificationUnverified, VerificationReviewed, VerificationVerified:
			default:
				add("record %s: unknown attestation verification %q", where, a.Verification)
			}
		}
		for _, e := range r.Evidence {
			if strings.TrimSpace(e.Manifest) == "" || strings.ContainsAny(e.Manifest, `/\`) {
				add("record %s: evidence manifest %q must be a file name", where, e.Manifest)
			}
			if e.SHA256 != "" && !sha256Hex.MatchString(e.SHA256) {
				add("record %s: evidence sha256 must be 64 lowercase hex characters", where)
			}
		}
	}
	return errors.Join(errs...)
}

// sources returns the scopes a record at id may name in InheritsFrom: a
// system's platforms and every provider it relies on, a platform's providers,
// nothing for a provider.
func sources(s *scope.Scope, id, kind string) []string {
	switch kind {
	case scope.KindSystem:
		if sys, ok := s.System(id); ok {
			return append(slices.Clone(sys.Platforms), s.ProvidersOf(id)...)
		}
	case scope.KindPlatform:
		if p, ok := s.Platform(id); ok {
			return slices.Clone(p.Providers)
		}
	}
	return nil
}

// implicitSources returns the scopes id inherits from when it has no record:
// a system's platforms and its direct providers (its platforms' providers are
// reached through the platforms), a platform's providers, nothing for a
// provider.
func implicitSources(s *scope.Scope, id, kind string) []string {
	switch kind {
	case scope.KindSystem:
		if sys, ok := s.System(id); ok {
			return append(slices.Clone(sys.Platforms), sys.Providers...)
		}
	case scope.KindPlatform:
		return sources(s, id, kind)
	}
	return nil
}

func validTime(v string) bool {
	if _, err := time.Parse(time.RFC3339, v); err == nil {
		return true
	}
	_, err := time.Parse(time.DateOnly, v)
	return err == nil
}

func orNone(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}
