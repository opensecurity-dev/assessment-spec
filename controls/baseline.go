package controls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Baseline is a list of the controls a system is assessed against, such as a
// NIST SP 800-53 baseline exported from a catalog. A system's added controls
// are assessed in addition.
type Baseline struct {
	// Description says where the list comes from.
	Description string `json:"description,omitempty"`
	// Controls are the control IDs.
	Controls []string `json:"controls"`
}

// LoadBaseline reads a baseline file and checks every control ID. Unknown
// fields are rejected.
func LoadBaseline(path string) (*Baseline, error) {
	b, err := os.ReadFile(path) //nolint:gosec // reading the caller's baseline is the purpose
	if err != nil {
		return nil, fmt.Errorf("controls: reading baseline %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var base Baseline
	if err := dec.Decode(&base); err != nil {
		return nil, fmt.Errorf("controls: parsing baseline %q: %w", path, err)
	}
	if len(base.Controls) == 0 {
		return nil, fmt.Errorf("controls: baseline %q lists no controls", path)
	}
	for _, id := range base.Controls {
		if !ValidControlID(id) {
			return nil, fmt.Errorf("controls: baseline %q: %q is not a control ID", path, id)
		}
	}
	return &base, nil
}
