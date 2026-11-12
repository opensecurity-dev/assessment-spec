package scope

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/opensecurity-dev/assessment-spec/evidence"
)

// DetectMentions returns the IDs of the systems, in document order, whose
// markers appear in content, ignoring case. A system with no markers is never
// detected.
func (s *Scope) DetectMentions(content []byte) []string {
	lower := bytes.ToLower(content)
	var out []string
	for _, sys := range s.Systems {
		for _, m := range sys.Markers {
			if bytes.Contains(lower, bytes.ToLower([]byte(m))) {
				out = append(out, sys.ID)
				break
			}
		}
	}
	return out
}

// MentionProblem is an artifact whose content names systems its manifest does
// not declare.
type MentionProblem struct {
	// Manifest is the manifest's file name.
	Manifest string `json:"manifest"`
	// Tool is the tool that produced the artifact.
	Tool string `json:"tool"`
	// Undeclared lists the systems the content names that mentions omits.
	Undeclared []string `json:"undeclared"`
}

// UndeclaredMentions reads every artifact in set and reports those whose
// content names a system, by its markers, that the manifest's mentions does
// not list. An artifact that names only the system it targets is not
// reported. It is the safety net under audience-filtered views: a collector
// that forgets a mention would otherwise disclose a system.
func (s *Scope) UndeclaredMentions(set *evidence.Set) ([]MentionProblem, error) {
	var out []MentionProblem
	for _, a := range set.Artifacts {
		body, err := os.ReadFile(a.ArtifactPath)
		if err != nil {
			return nil, fmt.Errorf("scope: reading artifact %q: %w", a.ArtifactPath, err)
		}
		var missing []string
		for _, id := range s.DetectMentions(body) {
			if t := a.Manifest.Target; t != nil && t.System == id {
				continue
			}
			if !slices.Contains(a.Manifest.Mentions, id) {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			out = append(out, MentionProblem{Manifest: filepath.Base(a.ManifestPath), Tool: a.Manifest.Tool, Undeclared: missing})
		}
	}
	return out, nil
}
