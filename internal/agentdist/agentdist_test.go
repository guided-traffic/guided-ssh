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
		"gssh-agentd-linux-arm64": {Data: []byte("arm64-binary-longer")},
		".gitkeep":                {Data: []byte{}},
		"README":                  {Data: []byte("not a binary")},
	}
}

func sum(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func TestListReturnsArchSizeAndHash(t *testing.T) {
	got := NewFromFS(fakeFS()).List()

	if len(got) != 2 {
		t.Fatalf("List() = %d entries, expected 2 (%+v)", len(got), got)
	}
	// Stably sorted: amd64 before arm64.
	if got[0].Arch != "amd64" || got[1].Arch != "arm64" {
		t.Fatalf("List() not sorted: %+v", got)
	}
	for _, info := range got {
		if info.OS != "linux" {
			t.Errorf("OS = %q, expected linux", info.OS)
		}
	}
	if want := int64(len("amd64-binary")); got[0].Size != want {
		t.Errorf("Size(amd64) = %d, expected %d", got[0].Size, want)
	}
	if want := sum("amd64-binary"); got[0].SHA256 != want {
		t.Errorf("SHA256(amd64) = %q, expected %q", got[0].SHA256, want)
	}
	if want := sum("arm64-binary-longer"); got[1].SHA256 != want {
		t.Errorf("SHA256(arm64) = %q, expected %q", got[1].SHA256, want)
	}
}

func TestListIsStableAcrossMultipleCalls(t *testing.T) {
	src := NewFromFS(fakeFS())
	first, second := src.List(), src.List()

	if len(first) != len(second) {
		t.Fatalf("List() unstable: %d vs %d", len(first), len(second))
	}
	// List() returns a copy: mutating it must not affect the cache.
	first[0].SHA256 = "broken"
	if src.List()[0].SHA256 == "broken" {
		t.Error("List() shares the internal slice with the caller")
	}
}

func TestOpenStreamsContent(t *testing.T) {
	rc, info, err := NewFromFS(fakeFS()).Open("linux", "arm64")
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if string(data) != "arm64-binary-longer" {
		t.Errorf("content = %q", data)
	}
	if info.Arch != "arm64" || info.SHA256 != sum("arm64-binary-longer") || info.Size != int64(len(data)) {
		t.Errorf("Info = %+v", info)
	}
}

func TestOpenUnknownPlatform(t *testing.T) {
	for _, tc := range []struct{ osName, arch string }{
		{"linux", "riscv64"},
		{"darwin", "amd64"},
	} {
		_, _, err := NewFromFS(fakeFS()).Open(tc.osName, tc.arch)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Open(%s, %s) = %v, expected ErrNotFound", tc.osName, tc.arch, err)
		}
	}
}

func TestEmptyFSDegradesCleanly(t *testing.T) {
	// Dev build: bin/ contains only .gitkeep.
	src := NewFromFS(fstest.MapFS{".gitkeep": {Data: []byte{}}})

	if got := src.List(); len(got) != 0 {
		t.Errorf("List() = %+v, expected empty", got)
	}
	if _, _, err := src.Open("linux", "amd64"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open() = %v, expected ErrNotFound", err)
	}
}

func TestNewUsesEmbed(t *testing.T) {
	// Without binaries in the repo, the list is empty; what matters is that
	// the embed is readable and .gitkeep does not show up as a binary.
	for _, info := range New().List() {
		if info.OS != "linux" || info.Arch == "" {
			t.Errorf("unexpected entry in embed: %+v", info)
		}
	}
}

func TestUnitFileEmbedded(t *testing.T) {
	if !strings.Contains(UnitFile, "ExecStart=/usr/bin/gssh-agentd run") {
		t.Errorf("UnitFile without ExecStart:\n%s", UnitFile)
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
			t.Errorf("parseName(%q) ok = %v, expected %v", tc.name, ok, tc.wantOK)
			continue
		}
		if ok && (osName != tc.wantOS || arch != tc.wantAr) {
			t.Errorf("parseName(%q) = %q/%q, expected %q/%q", tc.name, osName, arch, tc.wantOS, tc.wantAr)
		}
	}
}
