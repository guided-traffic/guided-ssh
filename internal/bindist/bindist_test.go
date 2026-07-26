package bindist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"testing/fstest"
)

const clientPrefix = "gssh-"

func clientFS() fstest.MapFS {
	return fstest.MapFS{
		"gssh-linux-amd64":        {Data: []byte("linux-amd64-binary")},
		"gssh-linux-arm64":        {Data: []byte("linux-arm64-binary")},
		"gssh-darwin-arm64":       {Data: []byte("darwin-arm64-binary")},
		"gssh-agentd-linux-amd64": {Data: []byte("agent binary, wrong family")},
		".gitkeep":                {Data: []byte{}},
		"README":                  {Data: []byte("not a binary")},
	}
}

func sum(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func TestListParsesClientNamesAndSkipsForeignOnes(t *testing.T) {
	got := NewFromFS(clientFS(), clientPrefix).List()

	if len(got) != 3 {
		t.Fatalf("List() = %d entries, expected 3 (%+v)", len(got), got)
	}
	// Stably sorted by OS, then arch: darwin/arm64, linux/amd64, linux/arm64.
	want := []struct{ os, arch string }{
		{"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"},
	}
	for i, w := range want {
		if got[i].OS != w.os || got[i].Arch != w.arch {
			t.Errorf("List()[%d] = %s/%s, expected %s/%s", i, got[i].OS, got[i].Arch, w.os, w.arch)
		}
	}
	if want := int64(len("darwin-arm64-binary")); got[0].Size != want {
		t.Errorf("Size(darwin/arm64) = %d, expected %d", got[0].Size, want)
	}
	if want := sum("darwin-arm64-binary"); got[0].SHA256 != want {
		t.Errorf("SHA256(darwin/arm64) = %q, expected %q", got[0].SHA256, want)
	}
}

func TestListIsStableAcrossMultipleCalls(t *testing.T) {
	src := NewFromFS(clientFS(), clientPrefix)
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
	rc, info, err := NewFromFS(clientFS(), clientPrefix).Open("darwin", "arm64")
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if string(data) != "darwin-arm64-binary" {
		t.Errorf("content = %q", data)
	}
	if info.OS != "darwin" || info.SHA256 != sum("darwin-arm64-binary") || info.Size != int64(len(data)) {
		t.Errorf("Info = %+v", info)
	}
}

func TestOpenUnknownPlatform(t *testing.T) {
	for _, tc := range []struct{ osName, arch string }{
		{"linux", "riscv64"},
		{"darwin", "amd64"},
		{"agentd", "linux-amd64"}, // the foreign family is not reachable either
	} {
		_, _, err := NewFromFS(clientFS(), clientPrefix).Open(tc.osName, tc.arch)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Open(%s, %s) = %v, expected ErrNotFound", tc.osName, tc.arch, err)
		}
	}
}

func TestEmptyFSDegradesCleanly(t *testing.T) {
	// Dev build: bin/ contains only .gitkeep.
	src := NewFromFS(fstest.MapFS{".gitkeep": {Data: []byte{}}}, clientPrefix)

	if got := src.List(); len(got) != 0 {
		t.Errorf("List() = %+v, expected empty", got)
	}
	if _, _, err := src.Open("linux", "amd64"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open() = %v, expected ErrNotFound", err)
	}
}

func TestParseName(t *testing.T) {
	tests := []struct {
		name, prefix   string
		wantOK         bool
		wantOS, wantAr string
	}{
		{name: "gssh-agentd-linux-amd64", prefix: "gssh-agentd-", wantOK: true, wantOS: "linux", wantAr: "amd64"},
		{name: ".gitkeep", prefix: "gssh-agentd-"},
		{name: "gssh-agentd", prefix: "gssh-agentd-"},
		{name: "gssh-agentd-linux", prefix: "gssh-agentd-"},
		{name: "gssh-agentd-linux-arm-v7", prefix: "gssh-agentd-"},
		{name: "gssh-linux-amd64", prefix: "gssh-agentd-"},

		{name: "gssh-linux-amd64", prefix: "gssh-", wantOK: true, wantOS: "linux", wantAr: "amd64"},
		{name: "gssh-darwin-arm64", prefix: "gssh-", wantOK: true, wantOS: "darwin", wantAr: "arm64"},
		{name: ".gitkeep", prefix: "gssh-"},
		{name: "gssh-linux", prefix: "gssh-"},
		// The client prefix does match agent names, but the arch then carries
		// a "-" and is rejected — the two families cannot collide.
		{name: "gssh-agentd-linux-amd64", prefix: "gssh-"},
	}
	for _, tc := range tests {
		osName, arch, ok := ParseName(tc.name, tc.prefix)
		if ok != tc.wantOK {
			t.Errorf("ParseName(%q, %q) ok = %v, expected %v", tc.name, tc.prefix, ok, tc.wantOK)
			continue
		}
		if ok && (osName != tc.wantOS || arch != tc.wantAr) {
			t.Errorf("ParseName(%q, %q) = %q/%q, expected %q/%q", tc.name, tc.prefix, osName, arch, tc.wantOS, tc.wantAr)
		}
	}
}
