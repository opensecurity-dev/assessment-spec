package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/opensecurity-dev/assessment-spec/controls"
	"github.com/opensecurity-dev/assessment-spec/crosswalk"
	"github.com/opensecurity-dev/assessment-spec/evidence"
)

func newValidateCmd() *cobra.Command {
	var (
		in         inputs
		crosswalks []string
	)
	c := &cobra.Command{
		Use:   "validate",
		Short: "Validate the scope and, when given, evidence, controls and crosswalks",
		Long: `Validate checks the scope document and each document given with it:
evidence manifests against the scope, artifact hashes, undeclared system
mentions in artifact content, control records against the scope, and
crosswalks. It reports every problem and fails if any is found.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			out := c.OutOrStdout()
			s, err := in.loadScope()
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(out, "scope: ok (%d systems)\n", len(s.Systems)); err != nil {
				return err
			}
			var errs []error
			if in.evidence != "" {
				set, err := evidence.LoadSet(in.evidence)
				if err != nil {
					return err
				}
				errs = append(errs, s.CheckEvidence(set))
				errs = append(errs, set.VerifyHashes()...)
				problems, err := s.UndeclaredMentions(set)
				if err != nil {
					return err
				}
				for _, p := range problems {
					errs = append(errs, fmt.Errorf("evidence %q (tool %q) names %v but its mentions omit them", p.Manifest, p.Tool, p.Undeclared))
				}
				if _, err := fmt.Fprintf(out, "evidence: %d artifacts checked\n", len(set.Artifacts)); err != nil {
					return err
				}
			}
			if in.controls != "" {
				doc, err := controls.Load(in.controls)
				if err != nil {
					return err
				}
				errs = append(errs, doc.Validate(s))
				if _, err := fmt.Fprintf(out, "controls: %d records checked\n", len(doc.Records)); err != nil {
					return err
				}
			}
			for _, path := range crosswalks {
				cw, err := crosswalk.Load(path)
				if err != nil {
					return err
				}
				errs = append(errs, cw.Validate())
				if _, err := fmt.Fprintf(out, "crosswalk %s: %d criteria checked\n", cw.Framework, len(cw.Mappings)); err != nil {
					return err
				}
			}
			return errors.Join(errs...)
		},
	}
	in.scopeFlag(c)
	in.evidenceFlag(c, false)
	c.Flags().StringVar(&in.controls, "controls", "", "controls document (controls.json)")
	c.Flags().StringArrayVar(&crosswalks, "crosswalk", nil, "crosswalk file; repeatable")
	return c
}

func newFreshnessCmd() *cobra.Command {
	var (
		in       inputs
		required []string
		now      string
		th       = evidence.DefaultPolicy().Default
	)
	c := &cobra.Command{
		Use:   "freshness",
		Short: "Report each tool's evidence age; fail if any is stale or missing",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			at := time.Now().UTC()
			if now != "" {
				t, err := time.Parse(time.RFC3339, now)
				if err != nil {
					return fmt.Errorf("--now: %w", err)
				}
				at = t
			}
			set, err := evidence.LoadSet(in.evidence)
			if err != nil {
				return err
			}
			report, err := set.Freshness(at, evidence.Policy{Default: th}, required...)
			if err != nil {
				return err
			}
			if err := writeJSON(c.OutOrStdout(), report); err != nil {
				return err
			}
			if !report.OK() {
				return fmt.Errorf("%d tools stale or missing: %w", len(report.Failing()), errFailed)
			}
			return nil
		},
	}
	in.evidenceFlag(c, true)
	c.Flags().StringArrayVar(&required, "require", nil, "tool that must have evidence; repeatable")
	c.Flags().StringVar(&now, "now", "", "evaluate at this RFC 3339 time instead of the current time")
	c.Flags().DurationVar(&th.WarnAfter, "warn-after", th.WarnAfter, "artifact age at which a tool warns")
	c.Flags().DurationVar(&th.FailAfter, "fail-after", th.FailAfter, "artifact age at which a tool is stale")
	c.Flags().DurationVar(&th.DatabaseMaxAge, "db-max-age", th.DatabaseMaxAge, "oldest a tool's database may be at scan time; 0 skips the check")
	return c
}

func newViewCmd() *cobra.Command {
	var in inputs
	c := &cobra.Command{
		Use:   "view",
		Short: "Print the evidence that applies to a system for an audience, and what is withheld",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			_, v, err := in.loadView()
			if err != nil {
				return err
			}
			return writeJSON(c.OutOrStdout(), v)
		},
	}
	in.scopeFlag(c)
	in.evidenceFlag(c, true)
	in.systemFlags(c)
	return c
}

func newResolveCmd() *cobra.Command {
	var in inputs
	c := &cobra.Command{
		Use:   "resolve",
		Short: "Print a system's effective control status for an audience",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			r, err := in.resolve()
			if err != nil {
				return err
			}
			return writeJSON(c.OutOrStdout(), r)
		},
	}
	in.scopeFlag(c)
	in.evidenceFlag(c, true)
	in.controlsFlags(c)
	in.systemFlags(c)
	return c
}

func newCoverageCmd() *cobra.Command {
	var (
		in   inputs
		path string
	)
	c := &cobra.Command{
		Use:   "coverage",
		Short: "Print a system's coverage of a framework through a crosswalk",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cw, err := crosswalk.Load(path)
			if err != nil {
				return err
			}
			r, err := in.resolve()
			if err != nil {
				return err
			}
			cov, err := cw.Coverage(r)
			if err != nil {
				return err
			}
			return writeJSON(c.OutOrStdout(), cov)
		},
	}
	in.scopeFlag(c)
	in.evidenceFlag(c, true)
	in.controlsFlags(c)
	in.systemFlags(c)
	c.Flags().StringVar(&path, "crosswalk", "", "crosswalk file")
	mustRequire(c, "crosswalk")
	return c
}
