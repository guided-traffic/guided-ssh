// Package agentdist serves the gssh-agentd binaries bundled in the server
// image and the systemd unit for the one-command host install. The binaries
// are produced in the same Docker build as the server (same -ldflags, same
// commit) and live under bin/ as `gssh-agentd-<os>-<arch>`; in the repo this
// directory is empty (.gitkeep), so a dev build degrades cleanly to "no
// binaries".
//
// Scanning, hashing and streaming live in internal/bindist (shared with
// internal/clientdist); this package pins the agent prefix and owns the
// systemd unit.
package agentdist

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

// UnitFile is the agent's systemd unit — the single source in the repo;
// deb/rpm (nfpm.yaml) and the manual install.sh both point here.
//
//go:embed gssh-agentd.service
var UnitFile string

// binPrefix is the name prefix of the embedded binaries; the rest of the
// name is `<os>-<arch>` (exactly the names produced by `make cross`).
const binPrefix = "gssh-agentd-"

// Info describes an embedded agent binary.
type Info = bindist.Info

// Source reads agent binaries from a filesystem.
type Source = bindist.Source

// ErrNotFound reports that no binary is embedded for the requested platform.
var ErrNotFound = bindist.ErrNotFound

// New returns a Source over the embedded binaries.
func New() *Source {
	sub, err := fs.Sub(binFS, "bin")
	if err != nil {
		// Can only happen with a broken embed (bin/ is always present).
		panic(fmt.Sprintf("agentdist: embed bin/ not readable: %v", err))
	}
	return NewFromFS(sub)
}

// NewFromFS returns a Source over any filesystem whose root directly
// contains the binaries (tests: fstest.MapFS; e2e: os.DirFS("bin")).
func NewFromFS(fsys fs.FS) *Source {
	return bindist.NewFromFS(fsys, binPrefix)
}
