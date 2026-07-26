package version

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	got := String()
	for _, want := range []string{"guided-ssh", "dev", "none", "unknown"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing expected part %q", got, want)
		}
	}
}
