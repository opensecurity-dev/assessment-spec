package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/controls"
	"github.com/opensecurity-dev/assessment-spec/evidence"
	"github.com/opensecurity-dev/assessment-spec/scope"
)

// errFailed reports a check that failed after its report was printed.
var errFailed = errors.New("check failed")

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "assessment",
		Short:         "Validate assessment-spec documents and report per system and audience",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newValidateCmd(), newFreshnessCmd(), newViewCmd(), newResolveCmd(), newCoverageCmd())
	return root
}

// inputs holds the document paths shared by the commands.
type inputs struct {
	scope, evidence, controls, baseline string
	system, audience                    string
}

func (in *inputs) scopeFlag(c *cobra.Command) {
	c.Flags().StringVar(&in.scope, "scope", "", "scope document (scope.json)")
	mustRequire(c, "scope")
}

func (in *inputs) evidenceFlag(c *cobra.Command, required bool) {
	c.Flags().StringVar(&in.evidence, "evidence", "", "evidence directory of *.manifest.json files")
	if required {
		mustRequire(c, "evidence")
	}
}

func (in *inputs) controlsFlags(c *cobra.Command) {
	c.Flags().StringVar(&in.controls, "controls", "", "controls document (controls.json)")
	c.Flags().StringVar(&in.baseline, "baseline", "", `baseline file: {"controls": ["AC-2", ...]}`)
	mustRequire(c, "controls")
	mustRequire(c, "baseline")
}

func (in *inputs) systemFlags(c *cobra.Command) {
	c.Flags().StringVar(&in.system, "system", "", "system ID")
	c.Flags().StringVar(&in.audience, "audience", "", "audience: public, nda or internal")
	mustRequire(c, "system")
	mustRequire(c, "audience")
}

func mustRequire(c *cobra.Command, name string) {
	if err := c.MarkFlagRequired(name); err != nil {
		panic(err) // only fails for a flag that is not defined
	}
}

// loadScope reads and validates the scope.
func (in *inputs) loadScope() (*scope.Scope, error) {
	s, err := scope.Load(in.scope)
	if err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadView reads the scope and evidence, checks the evidence against the
// scope, and returns the system's view for the audience.
func (in *inputs) loadView() (*scope.Scope, *scope.View, error) {
	aud, err := audience.Parse(in.audience)
	if err != nil {
		return nil, nil, err
	}
	s, err := in.loadScope()
	if err != nil {
		return nil, nil, err
	}
	set, err := evidence.LoadSet(in.evidence)
	if err != nil {
		return nil, nil, err
	}
	if err := s.CheckEvidence(set); err != nil {
		return nil, nil, err
	}
	v, err := s.NewView(set, in.system, aud)
	if err != nil {
		return nil, nil, err
	}
	return s, v, nil
}

// resolve returns the system's resolution for the audience.
func (in *inputs) resolve() (*controls.Resolution, error) {
	s, v, err := in.loadView()
	if err != nil {
		return nil, err
	}
	doc, err := controls.Load(in.controls)
	if err != nil {
		return nil, err
	}
	base, err := controls.LoadBaseline(in.baseline)
	if err != nil {
		return nil, err
	}
	return controls.Resolve(s, doc, v, base.Controls)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
