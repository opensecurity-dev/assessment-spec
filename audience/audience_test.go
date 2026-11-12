package audience_test

import (
	"testing"

	"github.com/opensecurity-dev/assessment-spec/audience"
)

func TestParse(t *testing.T) {
	for _, a := range audience.All {
		got, err := audience.Parse(string(a))
		if err != nil || got != a {
			t.Fatalf("Parse(%q) = %q, %v", a, got, err)
		}
	}
	if _, err := audience.Parse("partners"); err == nil {
		t.Fatal("expected an error for an unknown audience")
	}
}

func TestCanSee(t *testing.T) {
	cases := []struct {
		viewer, content audience.Audience
		want            bool
	}{
		{audience.Public, audience.Public, true},
		{audience.Public, audience.NDA, false},
		{audience.Public, audience.Internal, false},
		{audience.NDA, audience.Public, true},
		{audience.NDA, audience.NDA, true},
		{audience.NDA, audience.Internal, false},
		{audience.Internal, audience.Internal, true},
		{audience.Public, "secret", false},
		{audience.NDA, "secret", false},
	}
	for _, c := range cases {
		if got := c.viewer.CanSee(c.content); got != c.want {
			t.Errorf("%s.CanSee(%s) = %v, want %v", c.viewer, c.content, got, c.want)
		}
	}
}

func TestExternal(t *testing.T) {
	if !audience.Public.External() || !audience.NDA.External() || audience.Internal.External() {
		t.Fatal("public and nda are external; internal is not")
	}
}
