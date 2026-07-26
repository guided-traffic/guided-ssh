// Package bindist serves cross-built binaries that are bundled into the
// server image and handed out over HTTP. It is the shared machinery behind
// internal/agentdist (gssh-agentd, one-command host install) and
// internal/clientdist (gssh, client install); the only difference between
// the two is the file-name prefix, which is a constructor parameter here.
//
// The binaries are produced in the same Docker build as the server (same
// -ldflags, same commit) and are named `<prefix><os>-<arch>` — exactly the
// names `make cross` produces. In the repo the directories are empty
// (.gitkeep), so a dev build degrades cleanly to "no binaries".
package bindist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

// ErrNotFound reports that no binary is embedded for the requested platform.
var ErrNotFound = errors.New("no binary for this platform")

// Info describes an embedded binary.
type Info struct {
	OS     string // "linux" | "darwin"
	Arch   string // "amd64" | "arm64"
	Size   int64
	SHA256 string // hex, sha256sum-compatible
}

// Source reads binaries from a filesystem. Size and hash are computed once
// on first access and cached.
type Source struct {
	fsys   fs.FS
	prefix string
	once   sync.Once
	infos  []Info
	files  map[string]string // "<os>/<arch>" -> filename
}

// NewFromFS returns a Source over any filesystem whose root directly
// contains the binaries (embed: fs.Sub(…, "bin"); tests: fstest.MapFS;
// e2e: os.DirFS("bin")). prefix is the name prefix the files carry, e.g.
// "gssh-agentd-" or "gssh-".
func NewFromFS(fsys fs.FS, prefix string) *Source {
	return &Source{fsys: fsys, prefix: prefix}
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
		return nil, Info{}, fmt.Errorf("open binary %s: %w", name, err)
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
		osName, arch, ok := ParseName(entry.Name(), s.prefix)
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

// ParseName splits `<prefix><os>-<arch>`; anything else is not a binary.
// An arch containing a further "-" is rejected, which is what keeps the
// client prefix "gssh-" from matching agent names: `gssh-agentd-linux-amd64`
// parses as os "agentd", arch "linux-amd64" and is therefore skipped.
func ParseName(name, prefix string) (osName, arch string, ok bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return "", "", false
	}
	osName, arch, ok = strings.Cut(rest, "-")
	if !ok || osName == "" || arch == "" || strings.Contains(arch, "-") {
		return "", "", false
	}
	return osName, arch, true
}
