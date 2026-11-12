// Package crosswalk maps a framework's criteria to NIST SP 800-53 controls and
// reports a system's coverage of the framework from its resolved controls.
//
// Criteria are identifiers only, such as "CC6.1" or "A.8.8". A crosswalk
// carries no criterion text, so it can be shared wherever the framework's
// terms allow its identifiers to be; it records who made the mapping and
// under what licence.
package crosswalk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/opensecurity-dev/assessment-spec/controls"
)

// SchemaVersion is the crosswalk format version this package reads and
// writes.
const SchemaVersion = "crosswalk/v1"

var frameworkPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// Crosswalk maps one framework's criteria to controls.
type Crosswalk struct {
	// SchemaVersion is the document format version, "crosswalk/v1". Optional;
	// when absent, version 1 is assumed.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// Framework identifies the framework and its edition, in lowercase, such
	// as "iso-27001-2022" or "soc2-tsc-2017".
	Framework string `json:"framework"`
	// Source says who made the mapping, such as a publisher or "operator".
	Source string `json:"source"`
	// License is the terms the mapping is shared under, as an SPDX
	// identifier or a short statement.
	License string `json:"license"`
	// Mappings lists each criterion and the controls that meet it.
	Mappings []Mapping `json:"mappings"`
}

// Mapping is one criterion and the controls that meet it.
type Mapping struct {
	// Criterion is the framework's identifier for the criterion. Identifiers
	// only: no criterion text.
	Criterion string `json:"criterion"`
	// Controls are the NIST SP 800-53 control IDs that together meet the
	// criterion.
	Controls []string `json:"controls"`
}

// Load reads a crosswalk. Unknown fields are rejected. Check it with
// Crosswalk.Validate.
func Load(path string) (*Crosswalk, error) {
	b, err := os.ReadFile(path) //nolint:gosec // reading the caller's crosswalk is the purpose
	if err != nil {
		return nil, fmt.Errorf("crosswalk: reading %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Crosswalk
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("crosswalk: parsing %q: %w", path, err)
	}
	return &c, nil
}

// Validate checks the framework ID, source, licence, and every mapping, and
// returns every problem found, joined: each criterion appears once and maps
// to at least one control ID, with no control listed twice.
func (c *Crosswalk) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("crosswalk: "+format, args...)) }
	if c.SchemaVersion != "" && c.SchemaVersion != SchemaVersion {
		add("unsupported schemaVersion %q", c.SchemaVersion)
	}
	if !frameworkPattern.MatchString(c.Framework) {
		add("framework %q must be lowercase letters, digits, dots and hyphens", c.Framework)
	}
	if strings.TrimSpace(c.Source) == "" {
		add("source is empty")
	}
	if strings.TrimSpace(c.License) == "" {
		add("license is empty")
	}
	if len(c.Mappings) == 0 {
		add("no mappings")
	}
	seen := map[string]bool{}
	for _, m := range c.Mappings {
		crit := strings.TrimSpace(m.Criterion)
		switch {
		case crit == "":
			add("a mapping has an empty criterion")
		case crit != m.Criterion:
			add("criterion %q has surrounding spaces", m.Criterion)
		case seen[crit]:
			add("criterion %q is mapped twice", crit)
		}
		seen[crit] = true
		if len(m.Controls) == 0 {
			add("criterion %q maps to no controls", m.Criterion)
		}
		for i, id := range m.Controls {
			if !controls.ValidControlID(id) {
				add("criterion %q: %q is not a control ID such as AC-2 or SC-7(5)", m.Criterion, id)
			}
			if slices.Contains(m.Controls[:i], id) {
				add("criterion %q lists %s twice", m.Criterion, id)
			}
		}
	}
	return errors.Join(errs...)
}
