package scope

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opensecurity-dev/assessment-spec/audience"
	"github.com/opensecurity-dev/assessment-spec/evidence"
)

// Withholding reasons.
const (
	ReasonNamesOtherSystems  = "names-other-systems"
	ReasonMentionsUndeclared = "mentions-undeclared"
)

// View is the evidence that applies to one system, for one audience.
type View struct {
	// System is the system the view is for.
	System string `json:"system"`
	// Audience is who the view is for.
	Audience audience.Audience `json:"audience"`
	// Platforms lists the platforms the system runs on.
	Platforms []string `json:"platforms,omitempty"`
	// Providers lists the providers the system relies on, directly or through
	// its platforms.
	Providers []string `json:"providers,omitempty"`
	// Included lists the artifacts in the view.
	Included []ViewItem `json:"included"`
	// Withheld lists artifacts that apply to the system but are not shown to
	// this audience, with the reason, so a reviewer can supply a redacted
	// artifact or a written claim instead.
	Withheld []ViewItem `json:"withheld"`
}

// ViewItem is one artifact in a view.
type ViewItem struct {
	// Manifest is the manifest's file name within its evidence set.
	Manifest string `json:"manifest"`
	// Tool is the tool that produced the artifact.
	Tool string `json:"tool"`
	// Via says how the artifact applies: "system" or "platform:<id>".
	Via string `json:"via"`
	// Reason says why a withheld artifact is not shown.
	Reason string `json:"reason,omitempty"`
	// Detail explains the reason, such as which systems the artifact names.
	Detail string `json:"detail,omitempty"`

	// Artifact is the loaded artifact.
	Artifact evidence.Artifact `json:"-"`
}

// NewView returns the evidence in set that applies to systemID, for aud.
//
// An artifact applies when its target is the system, or a platform the
// system runs on. For an external audience (public or NDA):
//
//   - an artifact whose mentions name any other system is withheld;
//   - a platform artifact that does not declare mentions at all is withheld,
//     because a platform-wide artifact may name every system on the platform
//     and its collector has not said otherwise. An explicit empty list
//     declares that it names none.
//
// The internal audience sees every applicable artifact. Artifacts with no
// target apply to no system and appear in no view. The set must pass
// CheckEvidence.
func (s *Scope) NewView(set *evidence.Set, systemID string, aud audience.Audience) (*View, error) {
	sys, ok := s.System(systemID)
	if !ok {
		return nil, fmt.Errorf("scope: unknown system %q", systemID)
	}
	if !aud.Valid() {
		return nil, fmt.Errorf("scope: unknown audience %q", aud)
	}
	if err := s.CheckEvidence(set); err != nil {
		return nil, err
	}
	onPlatform := map[string]bool{}
	for _, p := range sys.Platforms {
		onPlatform[p] = true
	}

	v := &View{
		System:    systemID,
		Audience:  aud,
		Platforms: append([]string(nil), sys.Platforms...),
		Providers: s.ProvidersOf(systemID),
		Included:  []ViewItem{},
		Withheld:  []ViewItem{},
	}
	for _, a := range set.Artifacts {
		t := a.Manifest.Target
		if t == nil {
			continue
		}
		var via string
		switch {
		case t.System == systemID:
			via = "system"
		case t.Platform != "" && onPlatform[t.Platform]:
			via = "platform:" + t.Platform
		default:
			continue
		}
		item := ViewItem{
			Manifest: filepath.Base(a.ManifestPath),
			Tool:     a.Manifest.Tool,
			Via:      via,
			Artifact: a,
		}
		if aud.External() {
			if others := otherSystems(a.Manifest.Mentions, systemID); len(others) > 0 {
				item.Reason = ReasonNamesOtherSystems
				item.Detail = "names " + strings.Join(others, ", ")
			} else if t.Platform != "" && a.Manifest.Mentions == nil {
				item.Reason = ReasonMentionsUndeclared
				item.Detail = "platform artifact does not declare which systems it names"
			}
		}
		if item.Reason != "" {
			v.Withheld = append(v.Withheld, item)
		} else {
			v.Included = append(v.Included, item)
		}
	}
	sortItems(v.Included)
	sortItems(v.Withheld)
	return v, nil
}

func otherSystems(mentions []string, self string) []string {
	var out []string
	for _, id := range mentions {
		if id != self {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func sortItems(items []ViewItem) {
	sort.Slice(items, func(i, j int) bool { return items[i].Manifest < items[j].Manifest })
}
