// Package version stellt Build- und Versionsinformationen bereit.
// Die Werte werden beim Build über -ldflags "-X ..." gesetzt (siehe Makefile).
package version

import "fmt"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// String liefert die menschenlesbare Versionsangabe des Builds.
func String() string {
	return fmt.Sprintf("guided-ssh %s (commit %s, gebaut %s)", version, commit, date)
}
