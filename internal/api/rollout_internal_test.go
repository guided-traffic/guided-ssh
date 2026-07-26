package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
)

// fakeAgents is an AgentSource with a fixed list; Open returns the arch
// name as content (enough to verify the stream).
type fakeAgents []agentdist.Info

func (f fakeAgents) List() []agentdist.Info { return f }

func (f fakeAgents) Open(osName, arch string) (io.ReadCloser, agentdist.Info, error) {
	for _, info := range f {
		if info.OS == osName && info.Arch == arch {
			return io.NopCloser(strings.NewReader(arch)), info, nil
		}
	}
	return nil, agentdist.Info{}, fmt.Errorf("%w: %s/%s", agentdist.ErrNotFound, osName, arch)
}

// testPinPin is a valid (never actually issued) base64 SPKI pin.
const testPinPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// readyDeps are dependencies with all four gate conditions satisfied.
func readyDeps(t *testing.T) Deps {
	t.Helper()
	logger, _ := testLogger()
	return Deps{
		Agents:         fakeAgents{{OS: "linux", Arch: "amd64", Size: 1, SHA256: "ab"}},
		Pins:           NewPinProvider(PinProviderConfig{StaticPin: testPinPin}, logger),
		AgentPublicURL: "https://agent.gssh.example.com",
		PublicBaseURL:  "https://gssh.example.com",
	}
}

// TestRolloutGateConditions: each missing individual condition produces a
// 503 with exactly its missing entry; once all are satisfied, the gate
// lets requests through.
func TestRolloutGateConditions(t *testing.T) {
	logger, _ := testLogger()

	if gate := newRolloutGate(readyDeps(t)); len(gate.status(t.Context()).Missing) != 0 {
		t.Fatalf("complete configuration: missing = %v, expected empty", gate.status(t.Context()).Missing)
	}

	tests := map[string]struct {
		mutate func(*Deps)
		want   string
	}{
		"no binaries": {
			mutate: func(d *Deps) { d.Agents = fakeAgents{} },
			want:   rolloutMissingBinaries,
		},
		"no agent source": {
			mutate: func(d *Deps) { d.Agents = nil },
			want:   rolloutMissingBinaries,
		},
		"no pin": {
			// Dial source without a public URL ⇒ no pin determinable.
			mutate: func(d *Deps) { d.Pins = NewPinProvider(PinProviderConfig{}, logger) },
			want:   rolloutMissingPin,
		},
		"no pin provider": {
			mutate: func(d *Deps) { d.Pins = nil },
			want:   rolloutMissingPin,
		},
		"no agent url": {
			mutate: func(d *Deps) { d.AgentPublicURL = "" },
			want:   rolloutMissingAgentURL,
		},
		"no public url": {
			mutate: func(d *Deps) { d.PublicBaseURL = "" },
			want:   rolloutMissingPublicURL,
		},
		// http must never pass the gate: the install_command would
		// otherwise be `curl http://… | sudo sh` — plaintext transport
		// defeats the hash check and pin (both only protect after
		// unaltered script delivery).
		"agent url not https": {
			mutate: func(d *Deps) { d.AgentPublicURL = "http://agent.gssh.example.com" },
			want:   rolloutMissingAgentURLHTTPS,
		},
		"public url not https": {
			mutate: func(d *Deps) { d.PublicBaseURL = "http://gssh.example.com" },
			want:   rolloutMissingPublicURLHTTPS,
		},
		"public url unparsable": {
			mutate: func(d *Deps) { d.PublicBaseURL = "https://%zz" },
			want:   rolloutMissingPublicURLHTTPS,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			deps := readyDeps(t)
			tc.mutate(&deps)
			gate := newRolloutGate(deps)

			missing := gate.status(t.Context()).Missing
			if !slices.Equal(missing, []string{tc.want}) {
				t.Fatalf("missing = %v, expected exactly [%s]", missing, tc.want)
			}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
			if gate.allow(recorder, request) {
				t.Fatal("gate let the request through despite a missing condition")
			}
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, expected 503", recorder.Code)
			}
			var body rolloutUnavailable
			if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			if !slices.Equal(body.Missing, []string{tc.want}) {
				t.Fatalf("body-missing = %v, expected [%s]", body.Missing, tc.want)
			}
		})
	}
}

// TestRolloutGateAllowOpen: with an open gate, allow writes nothing and
// lets the handler proceed.
func TestRolloutGateAllowOpen(t *testing.T) {
	gate := newRolloutGate(readyDeps(t))
	recorder := httptest.NewRecorder()
	if !gate.allow(recorder, httptest.NewRequest(http.MethodGet, "/install.sh", nil)) {
		t.Fatalf("gate blocks despite complete configuration (body %q)", recorder.Body.String())
	}
	if recorder.Body.Len() != 0 {
		t.Errorf("allow wrote body %q", recorder.Body.String())
	}
}

// TestRolloutGateMultipleMissing: if several conditions are missing, the
// response names all of them — the operator sees the complete list
// instead of one at a time.
func TestRolloutGateMultipleMissing(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = nil
	deps.AgentPublicURL = ""
	gate := newRolloutGate(deps)

	missing := gate.status(t.Context()).Missing
	if !slices.Equal(missing, []string{rolloutMissingBinaries, rolloutMissingAgentURL}) {
		t.Fatalf("missing = %v, expected [binaries agent_public_url]", missing)
	}
}

// TestRolloutGatePinStatus: the determined pin state is passed through
// (the source ends up in the manifest, phase B).
func TestRolloutGatePinStatus(t *testing.T) {
	gate := newRolloutGate(readyDeps(t))
	status := gate.status(t.Context())
	if status.Pin.Pin != testPinPin || status.Pin.Source != PinSourceStatic {
		t.Fatalf("pin status = %+v, expected the static test pin", status.Pin)
	}
}
