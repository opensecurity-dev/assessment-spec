package crosswalk

import (
	"fmt"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/controls"
)

// Coverage is one system's coverage of a framework, derived from its
// resolved controls.
type Coverage struct {
	// Framework is the crosswalk's framework.
	Framework string `json:"framework"`
	// System is the system covered.
	System string `json:"system"`
	// Audience is the audience of the resolution the coverage was derived
	// from.
	Audience audience.Audience `json:"audience"`
	// Summary counts criteria by status.
	Summary map[controls.Status]int `json:"summary"`
	// Criteria lists each criterion in crosswalk order.
	Criteria []Criterion `json:"criteria"`
}

// Criterion is one criterion's status and the controls behind it.
type Criterion struct {
	// Criterion is the framework's identifier.
	Criterion string `json:"criterion"`
	// Status is the weakest status among the mapped controls.
	Status controls.Status `json:"status"`
	// Controls lists each mapped control's resolved status.
	Controls []ControlStatus `json:"controls"`
}

// ControlStatus is one mapped control's status.
type ControlStatus struct {
	// Control is the control ID.
	Control string `json:"control"`
	// Status is the control's resolved status, or unassessed when the
	// resolution does not include it.
	Status controls.Status `json:"status"`
	// OutsideBaseline is true when the control is not in the resolution,
	// because neither the baseline nor the system's added controls list it.
	OutsideBaseline bool `json:"outsideBaseline,omitempty"`
}

// Coverage derives a system's coverage of the crosswalk's framework from its
// resolution. A criterion takes the weakest status among its controls, with
// not-applicable yielding to any other, so it is implemented only when every
// mapped control is. A mapped control outside the resolution is unassessed:
// add it to the system's added controls to assess it.
func (c *Crosswalk) Coverage(r *controls.Resolution) (*Coverage, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("crosswalk: no resolution")
	}
	resolved := make(map[string]controls.Status, len(r.Controls))
	for _, rc := range r.Controls {
		resolved[rc.Control] = rc.Status
	}
	out := &Coverage{
		Framework: c.Framework,
		System:    r.System,
		Audience:  r.Audience,
		Summary:   map[controls.Status]int{},
		Criteria:  make([]Criterion, 0, len(c.Mappings)),
	}
	for _, m := range c.Mappings {
		cr := Criterion{Criterion: m.Criterion, Controls: make([]ControlStatus, 0, len(m.Controls))}
		for _, id := range m.Controls {
			st, ok := resolved[id]
			cs := ControlStatus{Control: id, Status: st}
			if !ok {
				cs.Status, cs.OutsideBaseline = controls.StatusUnassessed, true
			}
			cr.Controls = append(cr.Controls, cs)
			if cr.Status == "" {
				cr.Status = cs.Status
			} else {
				cr.Status = controls.Weaker(cr.Status, cs.Status)
			}
		}
		out.Summary[cr.Status]++
		out.Criteria = append(out.Criteria, cr)
	}
	return out, nil
}
