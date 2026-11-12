package evidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Status is a tool's freshness outcome.
type Status string

// Freshness statuses. Stale and missing fail a report.
const (
	StatusFresh   Status = "fresh"
	StatusWarn    Status = "warn"
	StatusStale   Status = "stale"
	StatusMissing Status = "missing"
)

// Thresholds are the age limits for one tool. A zero DatabaseMaxAge means the
// database age is not checked.
type Thresholds struct {
	// WarnAfter is the artifact age at which a tool warns.
	WarnAfter time.Duration
	// FailAfter is the artifact age at which a tool is stale.
	FailAfter time.Duration
	// DatabaseMaxAge is the oldest a tool's database may be, measured at the
	// artifact's generation time.
	DatabaseMaxAge time.Duration
}

// Policy holds default thresholds and per-tool overrides.
type Policy struct {
	Default Thresholds
	Tools   map[string]Thresholds
}

// DefaultPolicy warns after 24 hours, fails after 48, and fails a database
// more than seven days older than its artifact.
func DefaultPolicy() Policy {
	return Policy{Default: Thresholds{
		WarnAfter:      24 * time.Hour,
		FailAfter:      48 * time.Hour,
		DatabaseMaxAge: 7 * 24 * time.Hour,
	}}
}

// For returns the thresholds for tool.
func (p Policy) For(tool string) Thresholds {
	if t, ok := p.Tools[tool]; ok {
		return t
	}
	return p.Default
}

// ToolStatus is the freshness of one tool's most recent artifact.
type ToolStatus struct {
	Tool        string    `json:"tool"`
	Status      Status    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	GeneratedAt time.Time `json:"generatedAt,omitzero"`
	// Age is the artifact's age at the report's time. In JSON it is a Go
	// duration string, such as "54h0m0s".
	Age time.Duration `json:"-"`
}

// MarshalJSON writes Age as a duration string rather than nanoseconds.
func (t ToolStatus) MarshalJSON() ([]byte, error) {
	type plain ToolStatus
	out := struct {
		plain
		Age string `json:"age,omitempty"`
	}{plain: plain(t)}
	if t.Age != 0 {
		out.Age = t.Age.String()
	}
	return json.Marshal(out)
}

// FreshnessReport is the per-tool freshness of an evidence set.
type FreshnessReport struct {
	Now   time.Time    `json:"now"`
	Tools []ToolStatus `json:"tools"`
}

// OK reports whether no tool is stale or missing.
func (r FreshnessReport) OK() bool { return len(r.Failing()) == 0 }

// Failing returns the stale and missing tools.
func (r FreshnessReport) Failing() []ToolStatus {
	var out []ToolStatus
	for _, t := range r.Tools {
		if t.Status == StatusStale || t.Status == StatusMissing {
			out = append(out, t)
		}
	}
	return out
}

// Freshness evaluates each tool's most recent artifact at now. A tool is
// stale when its artifact is older than FailAfter, or when its database was
// more than DatabaseMaxAge older than the artifact: a new scan with an old
// database is not fresh evidence. Required tools with no artifact are missing.
// It returns an error only for a manifest that fails validation, which a Set
// from LoadSet never holds.
func (s *Set) Freshness(now time.Time, p Policy, required ...string) (FreshnessReport, error) {
	latest := map[string]Manifest{}
	latestAt := map[string]time.Time{}
	for _, a := range s.Artifacts {
		if err := a.Manifest.Validate(); err != nil {
			return FreshnessReport{}, err
		}
		t, err := a.Manifest.GeneratedTime()
		if err != nil {
			return FreshnessReport{}, err
		}
		tool := a.Manifest.Tool
		if cur, ok := latestAt[tool]; !ok || t.After(cur) {
			latest[tool], latestAt[tool] = a.Manifest, t
		}
	}

	r := FreshnessReport{Now: now}
	for tool, m := range latest {
		ts, err := evaluate(m, latestAt[tool], now, p.For(tool))
		if err != nil {
			return FreshnessReport{}, err
		}
		r.Tools = append(r.Tools, ts)
	}
	for _, tool := range required {
		if _, ok := latest[tool]; !ok {
			r.Tools = append(r.Tools, ToolStatus{Tool: tool, Status: StatusMissing, Reason: "no artifact for a required tool"})
		}
	}
	sort.Slice(r.Tools, func(i, j int) bool { return r.Tools[i].Tool < r.Tools[j].Tool })
	return r, nil
}

func evaluate(m Manifest, gen, now time.Time, th Thresholds) (ToolStatus, error) {
	age := now.Sub(gen)
	ts := ToolStatus{Tool: m.Tool, Status: StatusFresh, GeneratedAt: gen, Age: age}
	switch {
	case th.FailAfter > 0 && age >= th.FailAfter:
		ts.Status, ts.Reason = StatusStale, fmt.Sprintf("artifact is %s old; limit %s", age, th.FailAfter)
		return ts, nil
	case th.WarnAfter > 0 && age >= th.WarnAfter:
		ts.Status, ts.Reason = StatusWarn, fmt.Sprintf("artifact is %s old; warns after %s", age, th.WarnAfter)
	}
	if th.DatabaseMaxAge > 0 {
		db, ok, err := m.DatabaseTime()
		if err != nil {
			return ToolStatus{}, err
		}
		if ok && gen.Sub(db) > th.DatabaseMaxAge {
			ts.Status = StatusStale
			ts.Reason = fmt.Sprintf("database was %s old when the artifact was generated; limit %s", gen.Sub(db), th.DatabaseMaxAge)
		}
	}
	return ts, nil
}
