// Package audience defines who a view or document is for. The three levels
// mean the same as security-docs-spec's visibility: public is anyone, nda is a
// customer or prospect under a confidentiality agreement, and internal is the
// team that runs the systems.
package audience

import "fmt"

// Audience is who a view is for.
type Audience string

// Audiences, from the widest to the narrowest.
const (
	Public   Audience = "public"
	NDA      Audience = "nda"
	Internal Audience = "internal"
)

// All lists the audiences from the widest to the narrowest.
var All = []Audience{Public, NDA, Internal}

// Parse returns the audience named s.
func Parse(s string) (Audience, error) {
	a := Audience(s)
	if !a.Valid() {
		return "", fmt.Errorf("audience: unknown audience %q (want public, nda or internal)", s)
	}
	return a, nil
}

// Valid reports whether a is a defined audience.
func (a Audience) Valid() bool {
	return a == Public || a == NDA || a == Internal
}

// External reports whether a is outside the team, so content that discloses
// other systems or internal detail is withheld.
func (a Audience) External() bool {
	return a == Public || a == NDA
}

// CanSee reports whether an audience a may see content whose visibility is v:
// internal sees everything, nda sees nda and public, public sees public.
func (a Audience) CanSee(v Audience) bool {
	return rank(v) <= rank(a)
}

func rank(a Audience) int {
	switch a {
	case Public:
		return 0
	case NDA:
		return 1
	case Internal:
		return 2
	}
	// An unknown visibility is treated as internal, so it is never widened.
	return 2
}
