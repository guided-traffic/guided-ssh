package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// rolloutMux baut einen Mux mit ausschließlich den drei Rollout-Routen — die
// übrigen Server-Abhängigkeiten sind für Phase B irrelevant.
func rolloutMux(t *testing.T, deps Deps) *http.ServeMux {
	t.Helper()
	if deps.Logger == nil {
		deps.Logger, _ = testLogger()
	}
	mux := http.NewServeMux()
	registerRolloutRoutes(mux, deps)
	return mux
}

// get führt einen GET gegen den Mux aus.
func get(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

// twoAgents sind zwei Fake-Binaries mit realistischen Hex-Hashes.
var twoAgents = fakeAgents{
	{OS: "linux", Arch: "amd64", Size: 15728640, SHA256: strings.Repeat("a1", 32)},
	{OS: "linux", Arch: "arm64", Size: 14680064, SHA256: strings.Repeat("b2", 32)},
}

// TestManifestBereit: bei offenem Gate listet das Manifest alle Binaries,
// meldet rollout_ready und nennt die aktive Pin-Quelle.
func TestManifestBereit(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	recorder := get(t, rolloutMux(t, deps), "/v1/agents")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, erwartet 200", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, erwartet no-store", got)
	}

	var manifest agentManifest
	if err := json.NewDecoder(recorder.Body).Decode(&manifest); err != nil {
		t.Fatalf("manifest dekodieren: %v", err)
	}
	if !manifest.RolloutReady || len(manifest.Missing) != 0 {
		t.Errorf("rollout_ready = %v, missing = %v — erwartet true/leer", manifest.RolloutReady, manifest.Missing)
	}
	if manifest.Version != version.String() {
		t.Errorf("version = %q, erwartet %q", manifest.Version, version.String())
	}
	if manifest.PinSource != PinSourceStatic {
		t.Errorf("pin_source = %q, erwartet %q", manifest.PinSource, PinSourceStatic)
	}
	want := []agentManifestItem{
		{OS: "linux", Arch: "amd64", Size: 15728640, SHA256: strings.Repeat("a1", 32)},
		{OS: "linux", Arch: "arm64", Size: 14680064, SHA256: strings.Repeat("b2", 32)},
	}
	if !slices.Equal(manifest.Agents, want) {
		t.Errorf("agents = %+v, erwartet %+v", manifest.Agents, want)
	}
}

// TestManifestBeiGeschlossenemGate: das Manifest bleibt erreichbar und weist die
// fehlenden Bedingungen aus — genau dafür ist es nicht gatet.
func TestManifestBeiGeschlossenemGate(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = fakeAgents{}
	deps.AgentPublicURL = ""
	recorder := get(t, rolloutMux(t, deps), "/v1/agents")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, erwartet 200 (diagnosefunktion)", recorder.Code)
	}
	var manifest agentManifest
	if err := json.NewDecoder(recorder.Body).Decode(&manifest); err != nil {
		t.Fatalf("manifest dekodieren: %v", err)
	}
	if manifest.RolloutReady {
		t.Error("rollout_ready = true trotz fehlender bedingungen")
	}
	if !slices.Equal(manifest.Missing, []string{rolloutMissingBinaries, rolloutMissingAgentURL}) {
		t.Errorf("missing = %v, erwartet [binaries agent_public_url]", manifest.Missing)
	}
	if len(manifest.Agents) != 0 {
		t.Errorf("agents = %+v, erwartet leer", manifest.Agents)
	}
}

// TestDownloadStreamtBinary prüft den Erfolgsfall inklusive Header.
func TestDownloadStreamtBinary(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	recorder := get(t, rolloutMux(t, deps), "/v1/agents/linux/arm64")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, erwartet 200 (body %q)", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, erwartet application/octet-stream", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, erwartet no-store", got)
	}
	if got := recorder.Header().Get("Content-Length"); got != strconv.FormatInt(14680064, 10) {
		t.Errorf("Content-Length = %q, erwartet 14680064", got)
	}
	if recorder.Body.String() != "arm64" {
		t.Errorf("body = %q, erwartet den binary-inhalt", recorder.Body.String())
	}
}

// TestDownloadUnbekannteArch: nicht eingebettete oder unsinnige Plattformen
// ergeben 404, nicht 503 — das Gate ist ja offen.
func TestDownloadUnbekannteArch(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	mux := rolloutMux(t, deps)

	for _, path := range []string{"/v1/agents/linux/riscv64", "/v1/agents/windows/amd64"} {
		if code := get(t, mux, path).Code; code != http.StatusNotFound {
			t.Errorf("%s: status = %d, erwartet 404", path, code)
		}
	}
}

// TestGateSchliesstDownloadUndScript: fehlt eine Bedingung, antworten Download
// und install.sh mit 503 und nennen sie.
func TestGateSchliesstDownloadUndScript(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	deps.Pins = nil // kein Pin ermittelbar
	mux := rolloutMux(t, deps)

	for _, path := range []string{"/v1/agents/linux/amd64", "/install.sh"} {
		recorder := get(t, mux, path)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, erwartet 503", path, recorder.Code)
		}
		var body rolloutUnavailable
		if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
			t.Fatalf("%s: antwort dekodieren: %v", path, err)
		}
		if !slices.Equal(body.Missing, []string{rolloutMissingPin}) {
			t.Errorf("%s: missing = %v, erwartet [pin]", path, body.Missing)
		}
	}
}

// TestInstallScriptInhalt: das ausgelieferte Script trägt Pin, Hashes, URLs und
// die systemd-Unit bereits in sich; veränderlich bleibt nur das Token.
func TestInstallScriptInhalt(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	recorder := get(t, rolloutMux(t, deps), "/install.sh")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, erwartet 200 (body %q)", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/x-shellscript; charset=utf-8" {
		t.Errorf("Content-Type = %q, erwartet text/x-shellscript", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, erwartet no-store", got)
	}

	script := recorder.Body.String()
	for _, want := range []string{
		"PIN='" + testPinPin + "'",
		"SERVER_URL='" + deps.PublicBaseURL + "'",
		"AGENT_URL='" + deps.AgentPublicURL + "'",
		"VERSION='" + version.String() + "'",
		"ARCHES='amd64 arm64'",
		"amd64) echo '" + strings.Repeat("a1", 32) + "'",
		"arm64) echo '" + strings.Repeat("b2", 32) + "'",
		"--require-pin",
		"ExecStart=/usr/bin/gssh-agentd run", // Unit-Inhalt aus agentdist
		"\nmain \"$@\"\n",                    // Aufruf erst in der letzten Zeile
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script enthält %q nicht", want)
		}
	}
	// Regel 5: kein pipefail, kein bash.
	if strings.Contains(script, "set -o pipefail") {
		t.Error("script nutzt set -o pipefail (in dash/busybox nicht verlässlich)")
	}
	// Der Here-Doc-Terminator muss am Zeilenanfang stehen, sonst schluckt cat
	// den Rest des Scripts.
	if !strings.Contains(script, "\nUNIT_EOF\n") {
		t.Error("here-doc-terminator UNIT_EOF steht nicht am zeilenanfang")
	}
}

// TestInstallScriptSyntax lässt `sh -n` über das gerenderte Script laufen — ein
// Template-Fehler soll hier auffallen, nicht auf dem Host.
func TestInstallScriptSyntax(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("keine sh im PATH: %v", err)
	}

	script, err := renderInstallScript(installScriptData{
		BaseURL:  "https://gssh.example.com",
		AgentURL: "https://agent.gssh.example.com",
		Version:  "v0.0.0-test",
		Pin:      testPinPin,
		Agents:   linuxAgents(twoAgents),
		Unit:     agentdist.UnitFile,
	})
	if err != nil {
		t.Fatalf("script rendern: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), shell, "-n")
	cmd.Stdin = strings.NewReader(string(script))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n meldet einen syntaxfehler: %v\n%s", err, out)
	}
}

// TestInstallScriptQuotingFailClosed: ein Wert, der das Single-Quote-Quoting
// sprengen würde, bricht das Rendern ab, statt ein kaputtes Script an N Hosts
// auszuliefern.
func TestInstallScriptQuotingFailClosed(t *testing.T) {
	_, err := renderInstallScript(installScriptData{
		BaseURL:  "https://gssh.example.com/'; rm -rf /; '",
		AgentURL: "https://agent.gssh.example.com",
		Version:  "v0.0.0-test",
		Pin:      testPinPin,
		Agents:   linuxAgents(twoAgents),
		Unit:     agentdist.UnitFile,
	})
	if err == nil {
		t.Fatal("rendern mit anführungszeichen im wert lieferte kein fehler")
	}
}

// TestRolloutRoutenImVollenMux: die Routen müssen auch im vollständigen
// Public-Mux greifen — /install.sh darf nicht im SPA-Fallback ("/") landen.
func TestRolloutRoutenImVollenMux(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	deps.Logger, _ = testLogger()
	handler := New(deps)

	tests := map[string]string{
		"/v1/agents":             "application/json",
		"/v1/agents/linux/amd64": "application/octet-stream",
		"/install.sh":            "text/x-shellscript",
	}
	for path, wantType := range tests {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("%s: status = %d, erwartet 200", path, recorder.Code)
			continue
		}
		if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, wantType) {
			t.Errorf("%s: Content-Type = %q, erwartet %q", path, got, wantType)
		}
	}
}

// TestDownloadRateLimit: der Download hängt am eigenen, engeren Limiter — nicht
// am regulären der Sign-/Enroll-Endpunkte.
func TestDownloadRateLimit(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	deps.DownloadRateLimit = NewRateLimiter(RateLimiterConfig{RequestsPerMinute: 10, Burst: 2})
	mux := rolloutMux(t, deps)

	for i := range 2 {
		if code := get(t, mux, "/v1/agents/linux/amd64").Code; code != http.StatusOK {
			t.Fatalf("request %d: status = %d, erwartet 200", i, code)
		}
	}
	if code := get(t, mux, "/v1/agents/linux/amd64").Code; code != http.StatusTooManyRequests {
		t.Errorf("nach aufgebrauchtem burst: status = %d, erwartet 429", code)
	}
	// Manifest und Script laufen auf dem regulären Limiter und bleiben frei.
	if code := get(t, mux, "/v1/agents").Code; code != http.StatusOK {
		t.Errorf("manifest: status = %d, erwartet 200 (eigener limiter)", code)
	}
}
