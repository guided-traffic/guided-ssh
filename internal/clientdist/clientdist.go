// Package clientdist serves the gssh client binaries bundled in the server
// image for the frontend-driven client install. The binaries are produced in
// the same Docker build as the server (same -ldflags, same commit) and live
// under bin/ as `gssh-<os>-<arch>`; in the repo this directory is empty
// (.gitkeep), so a dev build degrades cleanly to "no binaries".
//
// Scanning, hashing and streaming live in internal/bindist (shared with
// internal/agentdist); this package only pins the client prefix and its own
// embed directory — the directories stay separate so neither family can end
// up in the other's manifest.
package clientdist

import (
	"embed"
	"fmt"
	"io/fs"

	"github.com/guided-traffic/guided-ssh/internal/bindist"
)

// all: is required — without binaries, bin/ contains only the hidden
// .gitkeep, and a plain //go:embed bin would fail with "no matching files".
//
//go:embed all:bin
var binFS embed.FS

// binPrefix is the name prefix of the embedded binaries; the rest of the
// name is `<os>-<arch>` (exactly the names produced by `make cross`).
const binPrefix = "gssh-"

// New returns a Source over the embedded binaries.
func New() *bindist.Source {
	sub, err := fs.Sub(binFS, "bin")
	if err != nil {
		// Can only happen with a broken embed (bin/ is always present).
		panic(fmt.Sprintf("clientdist: embed bin/ not readable: %v", err))
	}
	return NewFromFS(sub)
}

// NewFromFS returns a Source over any filesystem whose root directly
// contains the binaries (tests: fstest.MapFS; e2e: os.DirFS("bin")).
func NewFromFS(fsys fs.FS) *bindist.Source {
	return bindist.NewFromFS(fsys, binPrefix)
}
