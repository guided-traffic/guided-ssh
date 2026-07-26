// Package version provides build and version information.
// The values are set at build time via -ldflags "-X ..." (see Makefile).
package version

import "fmt"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// String returns the human-readable version string of the build.
func String() string {
	return fmt.Sprintf("guided-ssh %s (commit %s, built %s)", version, commit, date)
}
