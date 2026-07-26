// Package agentdist serves the gssh-agentd binaries bundled in the server
// image and the systemd unit for the one-command host install. The binaries
// are produced in the same Docker build as the server (same -ldflags, same
// commit) and live under bin/ as `gssh-agentd-<os>-<arch>`; in the repo this
// directory is empty (.gitkeep), so a dev build degrades cleanly to "no
// binaries".
package agentdist

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"
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

// ErrNotFound reports that no binary is embedded for the requested platform.
var ErrNotFound = errors.New("no agent binary for this platform")

// Info describes an embedded agent binary.
type Info struct {
	OS     string // "linux"
	Arch   string // "amd64" | "arm64"
	Size   int64
	SHA256 string // hex, sha256sum-compatible
}

// Source reads agent binaries from a filesystem. Size and hash are computed
// once on first access and cached.
type Source struct {
	fsys  fs.FS
	once  sync.Once
	infos []Info
	files map[string]string // "<os>/<arch>" -> filename
}

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
	return &Source{fsys: fsys}
}

// List returns all embedded binaries, stably sorted by OS and arch. Without
// binaries (dev build), the result is empty.
func (s *Source) List() []Info {
	s.once.Do(s.scan)
	return append([]Info(nil), s.infos...)
}

// Open streams the binary for os/arch; the caller closes the reader.
func (s *Source) Open(osName, arch string) (io.ReadCloser, Info, error) {
	s.once.Do(s.scan)
	name, ok := s.files[osName+"/"+arch]
	if !ok {
		return nil, Info{}, fmt.Errorf("%w: %s/%s", ErrNotFound, osName, arch)
	}
	f, err := s.fsys.Open(name)
	if err != nil {
		return nil, Info{}, fmt.Errorf("open agent binary %s: %w", name, err)
	}
	var info Info
	for _, candidate := range s.infos {
		if candidate.OS == osName && candidate.Arch == arch {
			info = candidate
			break
		}
	}
	return f, info, nil
}

// scan reads the directory once and computes size and SHA-256 for each
// binary. Non-matching names (in particular .gitkeep) and unreadable files
// are skipped — an empty result is a valid state.
func (s *Source) scan() {
	s.files = map[string]string{}

	entries, err := fs.ReadDir(s.fsys, ".")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		osName, arch, ok := parseName(entry.Name())
		if !ok {
			continue
		}
		size, sum, err := hashFile(s.fsys, entry.Name())
		if err != nil {
			continue
		}
		s.infos = append(s.infos, Info{OS: osName, Arch: arch, Size: size, SHA256: sum})
		s.files[osName+"/"+arch] = entry.Name()
	}
	sort.Slice(s.infos, func(i, j int) bool {
		if s.infos[i].OS != s.infos[j].OS {
			return s.infos[i].OS < s.infos[j].OS
		}
		return s.infos[i].Arch < s.infos[j].Arch
	})
}

func hashFile(fsys fs.FS, name string) (int64, string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(h.Sum(nil)), nil
}

// parseName splits `gssh-agentd-<os>-<arch>`; anything else is not a binary.
func parseName(name string) (osName, arch string, ok bool) {
	rest, ok := strings.CutPrefix(name, binPrefix)
	if !ok {
		return "", "", false
	}
	osName, arch, ok = strings.Cut(rest, "-")
	if !ok || osName == "" || arch == "" || strings.Contains(arch, "-") {
		return "", "", false
	}
	return osName, arch, true
}
