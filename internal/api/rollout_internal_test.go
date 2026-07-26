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

// fakeAgents ist eine AgentSource mit fest vorgegebener Liste; Open liefert den
// Arch-Namen als Inhalt (genügt, um den Stream zu prüfen).
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

// testPinPin ist ein gültiger (nie echt vergebener) Base64-SPKI-Pin.
const testPinPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// readyDeps sind Abhängigkeiten mit allen vier erfüllten Gate-Bedingungen.
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

// TestRolloutGateBedingungen: jede fehlende Einzelbedingung erzeugt 503 mit
// genau ihrem missing-Eintrag; sind alle erfüllt, lässt das Gate durch.
func TestRolloutGateBedingungen(t *testing.T) {
	logger, _ := testLogger()

	if gate := newRolloutGate(readyDeps(t)); len(gate.status(t.Context()).Missing) != 0 {
		t.Fatalf("vollständige konfiguration: missing = %v, erwartet leer", gate.status(t.Context()).Missing)
	}

	tests := map[string]struct {
		mutate func(*Deps)
		want   string
	}{
		"keine binaries": {
			mutate: func(d *Deps) { d.Agents = fakeAgents{} },
			want:   rolloutMissingBinaries,
		},
		"keine agent-source": {
			mutate: func(d *Deps) { d.Agents = nil },
			want:   rolloutMissingBinaries,
		},
		"kein pin": {
			// Dial-Quelle ohne Public-URL ⇒ kein Pin ermittelbar.
			mutate: func(d *Deps) { d.Pins = NewPinProvider(PinProviderConfig{}, logger) },
			want:   rolloutMissingPin,
		},
		"kein pin-provider": {
			mutate: func(d *Deps) { d.Pins = nil },
			want:   rolloutMissingPin,
		},
		"keine agent-url": {
			mutate: func(d *Deps) { d.AgentPublicURL = "" },
			want:   rolloutMissingAgentURL,
		},
		"keine public-url": {
			mutate: func(d *Deps) { d.PublicBaseURL = "" },
			want:   rolloutMissingPublicURL,
		},
		// http darf das Gate nie passieren: der install_command wäre sonst
		// `curl http://… | sudo sh` — Klartext-Transport hebelt Hash-Check und
		// Pin aus (beides schützt erst nach unverfälschter Script-Zustellung).
		"agent-url nicht https": {
			mutate: func(d *Deps) { d.AgentPublicURL = "http://agent.gssh.example.com" },
			want:   rolloutMissingAgentURLHTTPS,
		},
		"public-url nicht https": {
			mutate: func(d *Deps) { d.PublicBaseURL = "http://gssh.example.com" },
			want:   rolloutMissingPublicURLHTTPS,
		},
		"public-url unparsbar": {
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
				t.Fatalf("missing = %v, erwartet genau [%s]", missing, tc.want)
			}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
			if gate.allow(recorder, request) {
				t.Fatal("gate ließ trotz fehlender bedingung durch")
			}
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, erwartet 503", recorder.Code)
			}
			var body rolloutUnavailable
			if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
				t.Fatalf("antwort dekodieren: %v", err)
			}
			if !slices.Equal(body.Missing, []string{tc.want}) {
				t.Fatalf("body-missing = %v, erwartet [%s]", body.Missing, tc.want)
			}
		})
	}
}

// TestRolloutGateAllowOffen: bei offenem Gate schreibt allow nichts und lässt
// den Handler weitermachen.
func TestRolloutGateAllowOffen(t *testing.T) {
	gate := newRolloutGate(readyDeps(t))
	recorder := httptest.NewRecorder()
	if !gate.allow(recorder, httptest.NewRequest(http.MethodGet, "/install.sh", nil)) {
		t.Fatalf("gate blockiert trotz vollständiger konfiguration (body %q)", recorder.Body.String())
	}
	if recorder.Body.Len() != 0 {
		t.Errorf("allow schrieb body %q", recorder.Body.String())
	}
}

// TestRolloutGateMehrereFehlend: fehlen mehrere Bedingungen, nennt die Antwort
// alle — Operator sieht die vollständige Liste statt einer nach der anderen.
func TestRolloutGateMehrereFehlend(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = nil
	deps.AgentPublicURL = ""
	gate := newRolloutGate(deps)

	missing := gate.status(t.Context()).Missing
	if !slices.Equal(missing, []string{rolloutMissingBinaries, rolloutMissingAgentURL}) {
		t.Fatalf("missing = %v, erwartet [binaries agent_public_url]", missing)
	}
}

// TestRolloutGatePinStatus: der ermittelte Pin-Zustand wird durchgereicht
// (Quelle landet im Manifest, Phase B).
func TestRolloutGatePinStatus(t *testing.T) {
	gate := newRolloutGate(readyDeps(t))
	status := gate.status(t.Context())
	if status.Pin.Pin != testPinPin || status.Pin.Source != PinSourceStatic {
		t.Fatalf("pin-status = %+v, erwartet statischen testpin", status.Pin)
	}
}
