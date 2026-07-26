package clientdist

import (
	"errors"
	"io"
	"testing"
	"testing/fstest"

	"github.com/guided-traffic/guided-ssh/internal/bindist"
)

func TestNewFromFSUsesTheClientPrefix(t *testing.T) {
	src := NewFromFS(fstest.MapFS{
		"gssh-linux-amd64":        {Data: []byte("client")},
		"gssh-darwin-arm64":       {Data: []byte("client")},
		"gssh-agentd-linux-amd64": {Data: []byte("agent")},
		".gitkeep":                {Data: []byte{}},
	})

	got := src.List()
	if len(got) != 2 {
		t.Fatalf("List() = %+v, expected the two client binaries only", got)
	}
	if got[0].OS != "darwin" || got[1].OS != "linux" {
		t.Errorf("List() = %+v, expected darwin before linux", got)
	}

	rc, _, err := src.Open("linux", "amd64")
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "client" {
		t.Errorf("content = %q, expected the client binary", data)
	}
}

func TestNewUsesEmbed(t *testing.T) {
	// Without binaries in the repo, the list is empty; what matters is that
	// the embed is readable and .gitkeep does not show up as a binary.
	src := New()
	for _, info := range src.List() {
		if info.OS == "" || info.Arch == "" {
			t.Errorf("unexpected entry in embed: %+v", info)
		}
	}
	if len(src.List()) == 0 {
		if _, _, err := src.Open("linux", "amd64"); !errors.Is(err, bindist.ErrNotFound) {
			t.Errorf("Open() on an empty embed = %v, expected ErrNotFound", err)
		}
	}
}
