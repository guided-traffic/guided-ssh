// Package agentdist liefert die im Server-Image mitgelieferten
// gssh-agentd-Binaries und die systemd-Unit für den One-Command-Host-Install
// aus. Die Binaries entstehen im selben Docker-Build wie der Server (gleiche
// -ldflags, gleicher Commit) und liegen unter bin/ als
// `gssh-agentd-<os>-<arch>`; im Repo ist das Verzeichnis leer (.gitkeep), ein
// Dev-Build degradiert also sauber auf „keine Binaries".
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

// all: ist Pflicht — ohne Binaries enthält bin/ nur die versteckte .gitkeep,
// und ein normales //go:embed bin schlüge mit „no matching files" fehl.
//
//go:embed all:bin
var binFS embed.FS

// UnitFile ist die systemd-Unit des Agenten — einzige Quelle im Repo, auch
// deb/rpm (nfpm.yaml) und das manuelle install.sh zeigen hierher.
//
//go:embed gssh-agentd.service
var UnitFile string

// binPrefix ist das Namenspräfix der eingebetteten Binaries; der Rest des
// Namens ist `<os>-<arch>` (exakt die Namen aus `make cross`).
const binPrefix = "gssh-agentd-"

// ErrNotFound meldet, dass für die angefragte Plattform kein Binary
// eingebettet ist.
var ErrNotFound = errors.New("kein agent-binary für diese plattform")

// Info beschreibt ein eingebettetes Agent-Binary.
type Info struct {
	OS     string // "linux"
	Arch   string // "amd64" | "arm64"
	Size   int64
	SHA256 string // Hex, sha256sum-kompatibel
}

// Source liest Agent-Binaries aus einem Dateisystem. Größe und Hash werden
// beim ersten Zugriff einmal berechnet und gecacht.
type Source struct {
	fsys  fs.FS
	once  sync.Once
	infos []Info
	files map[string]string // "<os>/<arch>" -> Dateiname
}

// New liefert eine Source über die eingebetteten Binaries.
func New() *Source {
	sub, err := fs.Sub(binFS, "bin")
	if err != nil {
		// Kann nur bei kaputtem Embed passieren (bin/ ist immer vorhanden).
		panic(fmt.Sprintf("agentdist: embed bin/ nicht lesbar: %v", err))
	}
	return NewFromFS(sub)
}

// NewFromFS liefert eine Source über ein beliebiges Dateisystem, dessen Wurzel
// die Binaries direkt enthält (Tests: fstest.MapFS; E2E: os.DirFS("bin")).
func NewFromFS(fsys fs.FS) *Source {
	return &Source{fsys: fsys}
}

// List liefert alle eingebetteten Binaries, stabil sortiert nach OS und Arch.
// Ohne Binaries (Dev-Build) ist das Ergebnis leer.
func (s *Source) List() []Info {
	s.once.Do(s.scan)
	return append([]Info(nil), s.infos...)
}

// Open streamt das Binary für os/arch; der Aufrufer schließt den Reader.
func (s *Source) Open(osName, arch string) (io.ReadCloser, Info, error) {
	s.once.Do(s.scan)
	name, ok := s.files[osName+"/"+arch]
	if !ok {
		return nil, Info{}, fmt.Errorf("%w: %s/%s", ErrNotFound, osName, arch)
	}
	f, err := s.fsys.Open(name)
	if err != nil {
		return nil, Info{}, fmt.Errorf("agent-binary %s öffnen: %w", name, err)
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

// scan liest das Verzeichnis einmalig und berechnet Größe und SHA-256 je
// Binary. Nicht passende Namen (insbesondere .gitkeep) und unlesbare Dateien
// werden übersprungen — ein leeres Ergebnis ist ein gültiger Zustand.
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

// parseName zerlegt `gssh-agentd-<os>-<arch>`; alles andere ist kein Binary.
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
