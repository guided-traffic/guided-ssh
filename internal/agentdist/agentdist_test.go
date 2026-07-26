package agentdist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/fstest"
)

func fakeFS() fstest.MapFS {
	return fstest.MapFS{
		"gssh-agentd-linux-amd64": {Data: []byte("amd64-binary")},
		"gssh-agentd-linux-arm64": {Data: []byte("arm64-binary-laenger")},
		".gitkeep":                {Data: []byte{}},
		"README":                  {Data: []byte("kein binary")},
	}
}

func sum(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func TestListLiefertArchGroesseUndHash(t *testing.T) {
	got := NewFromFS(fakeFS()).List()

	if len(got) != 2 {
		t.Fatalf("List() = %d Einträge, erwartet 2 (%+v)", len(got), got)
	}
	// Stabil sortiert: amd64 vor arm64.
	if got[0].Arch != "amd64" || got[1].Arch != "arm64" {
		t.Fatalf("List() nicht sortiert: %+v", got)
	}
	for _, info := range got {
		if info.OS != "linux" {
			t.Errorf("OS = %q, erwartet linux", info.OS)
		}
	}
	if want := int64(len("amd64-binary")); got[0].Size != want {
		t.Errorf("Size(amd64) = %d, erwartet %d", got[0].Size, want)
	}
	if want := sum("amd64-binary"); got[0].SHA256 != want {
		t.Errorf("SHA256(amd64) = %q, erwartet %q", got[0].SHA256, want)
	}
	if want := sum("arm64-binary-laenger"); got[1].SHA256 != want {
		t.Errorf("SHA256(arm64) = %q, erwartet %q", got[1].SHA256, want)
	}
}

func TestListIstStabilUeberMehrfachaufrufe(t *testing.T) {
	src := NewFromFS(fakeFS())
	first, second := src.List(), src.List()

	if len(first) != len(second) {
		t.Fatalf("List() instabil: %d vs %d", len(first), len(second))
	}
	// List() gibt eine Kopie zurück: Mutation darf den Cache nicht verändern.
	first[0].SHA256 = "kaputt"
	if src.List()[0].SHA256 == "kaputt" {
		t.Error("List() teilt den internen Slice mit dem Aufrufer")
	}
}

func TestOpenStreamtInhalt(t *testing.T) {
	rc, info, err := NewFromFS(fakeFS()).Open("linux", "arm64")
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if string(data) != "arm64-binary-laenger" {
		t.Errorf("Inhalt = %q", data)
	}
	if info.Arch != "arm64" || info.SHA256 != sum("arm64-binary-laenger") || info.Size != int64(len(data)) {
		t.Errorf("Info = %+v", info)
	}
}

func TestOpenUnbekanntePlattform(t *testing.T) {
	for _, tc := range []struct{ osName, arch string }{
		{"linux", "riscv64"},
		{"darwin", "amd64"},
	} {
		_, _, err := NewFromFS(fakeFS()).Open(tc.osName, tc.arch)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Open(%s, %s) = %v, erwartet ErrNotFound", tc.osName, tc.arch, err)
		}
	}
}

func TestLeeresFSDegradiertSauber(t *testing.T) {
	// Dev-Build: bin/ enthält nur .gitkeep.
	src := NewFromFS(fstest.MapFS{".gitkeep": {Data: []byte{}}})

	if got := src.List(); len(got) != 0 {
		t.Errorf("List() = %+v, erwartet leer", got)
	}
	if _, _, err := src.Open("linux", "amd64"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open() = %v, erwartet ErrNotFound", err)
	}
}

func TestNewNutztEmbed(t *testing.T) {
	// Ohne Binaries im Repo ist die Liste leer; entscheidend ist, dass das
	// Embed lesbar ist und .gitkeep nicht als Binary auftaucht.
	for _, info := range New().List() {
		if info.OS != "linux" || info.Arch == "" {
			t.Errorf("unerwarteter Eintrag im Embed: %+v", info)
		}
	}
}

func TestUnitFileEingebettet(t *testing.T) {
	if !strings.Contains(UnitFile, "ExecStart=/usr/bin/gssh-agentd run") {
		t.Errorf("UnitFile ohne ExecStart:\n%s", UnitFile)
	}
}

func TestParseName(t *testing.T) {
	tests := []struct {
		name           string
		wantOK         bool
		wantOS, wantAr string
	}{
		{name: "gssh-agentd-linux-amd64", wantOK: true, wantOS: "linux", wantAr: "amd64"},
		{name: ".gitkeep"},
		{name: "gssh-agentd"},
		{name: "gssh-agentd-linux"},
		{name: "gssh-agentd-linux-arm-v7"},
		{name: "gssh-linux-amd64"},
	}
	for _, tc := range tests {
		osName, arch, ok := parseName(tc.name)
		if ok != tc.wantOK {
			t.Errorf("parseName(%q) ok = %v, erwartet %v", tc.name, ok, tc.wantOK)
			continue
		}
		if ok && (osName != tc.wantOS || arch != tc.wantAr) {
			t.Errorf("parseName(%q) = %q/%q, erwartet %q/%q", tc.name, osName, arch, tc.wantOS, tc.wantAr)
		}
	}
}
