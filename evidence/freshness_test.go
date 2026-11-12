package evidence_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/opensecurity-dev/assessment-spec/evidence"
)

func TestToolStatusJSON(t *testing.T) {
	ts := evidence.ToolStatus{Tool: "govulncheck", Status: evidence.StatusStale, Age: 54 * time.Hour}
	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"tool":"govulncheck","status":"stale","age":"54h0m0s"}`; string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
	b, err = json.Marshal(evidence.ToolStatus{Tool: "zap", Status: evidence.StatusMissing})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"tool":"zap","status":"missing"}`; string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
}
