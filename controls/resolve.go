package controls

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

// Withholding reasons for resolved content, beyond those of scope views.
const (
	ReasonVisibility       = "visibility"
	ReasonNamesOtherSystem = scope.ReasonNamesOtherSystems
	ReasonNotInView        = "not-in-view"
)

// Resolution is one system's effective control status for one audience.
type Resolution struct {
	// System is the system resolved.
	System string `json:"system"`
	// Audience is who the resolution is for.
	Audience audience.Audience `json:"audience"`
	// Summary counts controls by effective status.
	Summary map[Status]int `json:"summary"`
	// Controls lists each control in the baseline and the system's added
	// controls, in catalog order.
	Controls []Resolved `json:"controls"`
}

// Resolved is one control's effective status for a system.
type Resolved struct {
	// Control is the control ID.
	Control string `json:"control"`
	// Status is the effective status. A control no record reaches is
	// unassessed, never implemented.
	Status Status `json:"status"`
	// Via lists the scopes whose records produced the status, as
	// "system:<id>", "platform:<id>" or "provider:<id>".
	Via []string `json:"via"`
	// Verification is the weakest verification among the contributing
	// records.
	Verification Verification `json:"verification"`
	// Statements holds the contributing records' prose that this audience may
	// read.
	Statements []Statement `json:"statements,omitempty"`
	// Evidence lists evidence manifests in the system's view for this
	// audience.
	Evidence []string `json:"evidence,omitempty"`
	// Findings lists finding IDs. Findings appear only to the internal
	// audience.
	Findings []string `json:"findings,omitempty"`
	// Withheld lists prose and evidence this audience does not see, with the
	// reason.
	Withheld []Withheld `json:"withheld,omitempty"`
}

// Statement is prose from one contributing record.
type Statement struct {
	// Via is the record's scope, as in Resolved.Via.
	Via string `json:"via"`
	// Kind is "statement", "gap" or "justification".
	Kind string `json:"kind"`
	// Text is the prose.
	Text string `json:"text"`
}

// Withheld is content an audience does not see.
type Withheld struct {
	// Kind is "prose" or "evidence".
	Kind string `json:"kind"`
	// Via is the record's scope.
	Via string `json:"via"`
	// Ref names the evidence manifest, for evidence.
	Ref string `json:"ref,omitempty"`
	// Reason says why it is withheld.
	Reason string `json:"reason"`
}

// Resolve returns the effective status of every control in baseline and the
// system's added controls, for the system and audience of view.
//
// For each control:
//
//   - a record on the system wins; a system-specific record gives its own
//     status, an inherited record its sources' status, and a hybrid record
//     the weaker of its own and its sources';
//   - with no system record, the system inherits from its platforms and
//     providers, and a platform with no record from its providers;
//   - where several sources contribute, the weakest status wins, and
//     not-applicable yields to any other;
//   - a control no record reaches is unassessed.
//
// For an external audience, a record's prose appears only if its visibility
// allows and it names no other system by marker, evidence only if the view
// includes it, and findings never. The baseline is supplied by the caller,
// for example from a NIST SP 800-53 catalog; this package ships none.
func Resolve(s *scope.Scope, d *Document, view *scope.View, baseline []string) (*Resolution, error) {
	if err := d.Validate(s); err != nil {
		return nil, err
	}
	sys, ok := s.System(view.System)
	if !ok {
		return nil, fmt.Errorf("controls: unknown system %q", view.System)
	}
	for _, c := range append(slices.Clone(baseline), sys.AddedControls...) {
		if !ValidControlID(c) {
			return nil, fmt.Errorf("controls: baseline or added control %q is not a control ID", c)
		}
	}
	r := &resolver{scope: s, records: map[string]*Implementation{}}
	for i := range d.Records {
		rec := &d.Records[i]
		r.records[rec.Control+"\x00"+rec.Scope] = rec
	}
	inView := map[string]string{} // manifest -> "" if included, else the reason
	for _, it := range view.Included {
		inView[it.Manifest] = ""
	}
	for _, it := range view.Withheld {
		inView[it.Manifest] = it.Reason
	}

	ids := slices.Clone(baseline)
	ids = append(ids, sys.AddedControls...)
	sortControls(ids)
	ids = slices.Compact(ids)

	out := &Resolution{System: sys.ID, Audience: view.Audience, Summary: map[Status]int{}, Controls: []Resolved{}}
	for _, c := range ids {
		st, contribs, err := r.resolve(c, sys.ID, scope.KindSystem, map[string]bool{})
		if err != nil {
			return nil, err
		}
		rc := Resolved{Control: c, Status: st, Via: []string{}, Verification: VerificationUnverified}
		if len(contribs) > 0 {
			rc.Verification = VerificationVerified
		}
		for _, k := range contribs {
			rec := k.rec
			rc.Via = append(rc.Via, k.via)
			if verificationRank(rec.EffectiveVerification()) < verificationRank(rc.Verification) {
				rc.Verification = rec.EffectiveVerification()
			}
			addProse(s, &rc, k.via, rec, view.Audience, sys.ID)
			for _, e := range rec.Evidence {
				reason, known := inView[e.Manifest]
				switch {
				case !known:
					rc.Withheld = append(rc.Withheld, Withheld{Kind: "evidence", Via: k.via, Ref: e.Manifest, Reason: ReasonNotInView})
				case reason != "":
					rc.Withheld = append(rc.Withheld, Withheld{Kind: "evidence", Via: k.via, Ref: e.Manifest, Reason: reason})
				case !slices.Contains(rc.Evidence, e.Manifest):
					rc.Evidence = append(rc.Evidence, e.Manifest)
				}
			}
			if view.Audience == audience.Internal {
				for _, f := range rec.Findings {
					if !slices.Contains(rc.Findings, f) {
						rc.Findings = append(rc.Findings, f)
					}
				}
			}
		}
		out.Summary[st]++
		out.Controls = append(out.Controls, rc)
	}
	return out, nil
}

func addProse(s *scope.Scope, rc *Resolved, via string, rec *Implementation, aud audience.Audience, self string) {
	texts := []Statement{
		{Via: via, Kind: "statement", Text: rec.Statement},
		{Via: via, Kind: "gap", Text: rec.Gap},
		{Via: via, Kind: "justification", Text: rec.Justification},
	}
	var present []Statement
	for _, t := range texts {
		if strings.TrimSpace(t.Text) != "" {
			present = append(present, t)
		}
	}
	if len(present) == 0 {
		return
	}
	if reason := ProseWithheld(s, *rec, aud, self); reason != "" {
		rc.Withheld = append(rc.Withheld, Withheld{Kind: "prose", Via: via, Reason: reason})
		return
	}
	rc.Statements = append(rc.Statements, present...)
}

// ProseWithheld returns why the record's prose is withheld from aud when
// reporting on system, or "" when aud may read it. The internal audience
// reads all prose. An external audience reads a record's prose only if its
// visibility allows and no statement, gap or justification names another
// system by marker.
func ProseWithheld(s *scope.Scope, rec Implementation, aud audience.Audience, system string) string {
	if !aud.External() {
		return ""
	}
	if !aud.CanSee(rec.EffectiveVisibility()) {
		return ReasonVisibility
	}
	for _, t := range []string{rec.Statement, rec.Gap, rec.Justification} {
		for _, id := range s.DetectMentions([]byte(t)) {
			if id != system {
				return ReasonNamesOtherSystem
			}
		}
	}
	return ""
}

type contribution struct {
	via string
	rec *Implementation
}

type resolver struct {
	scope   *scope.Scope
	records map[string]*Implementation
}

// resolve returns the status of control at id and the records that produced
// it. A status of unassessed with no contributions means nothing reached it.
func (r *resolver) resolve(control, id, kind string, visiting map[string]bool) (Status, []contribution, error) {
	key := control + "\x00" + id
	if visiting[key] {
		return "", nil, fmt.Errorf("controls: %s inherits from itself through %q", control, id)
	}
	visiting[key] = true
	defer delete(visiting, key)

	via := kind + ":" + id
	rec, ok := r.records[key]
	if !ok {
		return r.combine(control, implicitSources(r.scope, id, kind), visiting, true)
	}
	self := []contribution{{via: via, rec: rec}}
	switch rec.Origination {
	case OriginSpecific:
		return rec.Status, self, nil
	case OriginInherited:
		st, contribs, err := r.combine(control, rec.InheritsFrom, visiting, false)
		return st, append(self, contribs...), err
	case OriginHybrid:
		st, contribs, err := r.combine(control, rec.InheritsFrom, visiting, false)
		return Weaker(rec.Status, st), append(self, contribs...), err
	}
	return "", nil, fmt.Errorf("controls: record %s at %q has unknown origination %q", control, id, rec.Origination)
}

// combine resolves control at each source and returns the weakest status.
// When implicit, sources nothing reaches are skipped, so a system inherits
// from whichever of its platforms and providers record the control; when
// explicit, an unreached source counts as unassessed.
func (r *resolver) combine(control string, srcs []string, visiting map[string]bool, implicit bool) (Status, []contribution, error) {
	var (
		status   Status
		contribs []contribution
	)
	for _, src := range srcs {
		st, c, err := r.resolve(control, src, r.scope.KindOf(src), visiting)
		if err != nil {
			return "", nil, err
		}
		if len(c) == 0 {
			if implicit {
				continue
			}
			st = StatusUnassessed
		}
		for _, k := range c {
			if !slices.ContainsFunc(contribs, func(x contribution) bool { return x.via == k.via }) {
				contribs = append(contribs, k)
			}
		}
		if status == "" {
			status = st
		} else {
			status = Weaker(status, st)
		}
	}
	if status == "" {
		status = StatusUnassessed
	}
	return status, contribs, nil
}

// Weaker returns the weaker of two statuses. Not-applicable yields to any
// other status, so it results only when both are not-applicable.
func Weaker(a, b Status) Status {
	switch {
	case a == StatusNotApplicable:
		return b
	case b == StatusNotApplicable:
		return a
	case strength(b) < strength(a):
		return b
	}
	return a
}

func strength(s Status) int {
	switch s {
	case StatusImplemented:
		return 4
	case StatusAlternative:
		return 3
	case StatusPartial:
		return 2
	case StatusPlanned:
		return 1
	}
	return 0
}

// sortControls orders control IDs by family, number and enhancement.
func sortControls(ids []string) {
	sort.Slice(ids, func(i, j int) bool {
		fi, ni, ei := splitControl(ids[i])
		fj, nj, ej := splitControl(ids[j])
		if fi != fj {
			return fi < fj
		}
		if ni != nj {
			return ni < nj
		}
		return ei < ej
	})
}

func splitControl(id string) (family string, number, enhancement int) {
	family, rest, _ := strings.Cut(id, "-")
	num, enh, hasEnh := strings.Cut(rest, "(")
	n, err := strconv.Atoi(num)
	if err != nil {
		panic(fmt.Sprintf("controls: sorting an unvalidated control ID %q", id))
	}
	if hasEnh {
		e, err := strconv.Atoi(strings.TrimSuffix(enh, ")"))
		if err != nil {
			panic(fmt.Sprintf("controls: sorting an unvalidated control ID %q", id))
		}
		return family, n, e
	}
	return family, n, -1
}
