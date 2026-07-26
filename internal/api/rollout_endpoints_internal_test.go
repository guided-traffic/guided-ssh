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

// rolloutMux builds a mux with exclusively the three rollout routes — the
// remaining server dependencies are irrelevant for phase B.
func rolloutMux(t *testing.T, deps Deps) *http.ServeMux {
	t.Helper()
	if deps.Logger == nil {
		deps.Logger, _ = testLogger()
	}
	mux := http.NewServeMux()
	registerRolloutRoutes(mux, deps)
	return mux
}

// get executes a GET against the mux.
func get(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

// twoAgents are two fake binaries with realistic hex hashes.
var twoAgents = fakeAgents{
	{OS: "linux", Arch: "amd64", Size: 15728640, SHA256: strings.Repeat("a1", 32)},
	{OS: "linux", Arch: "arm64", Size: 14680064, SHA256: strings.Repeat("b2", 32)},
}

// TestManifestReady: with the gate open, the manifest lists all binaries,
// reports rollout_ready, and names the active pin source.
func TestManifestReady(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	recorder := get(t, rolloutMux(t, deps), "/v1/agents")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, expected no-store", got)
	}

	var manifest agentManifest
	if err := json.NewDecoder(recorder.Body).Decode(&manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if !manifest.RolloutReady || len(manifest.Missing) != 0 {
		t.Errorf("rollout_ready = %v, missing = %v — expected true/empty", manifest.RolloutReady, manifest.Missing)
	}
	if manifest.Version != version.String() {
		t.Errorf("version = %q, expected %q", manifest.Version, version.String())
	}
	if manifest.PinSource != PinSourceStatic {
		t.Errorf("pin_source = %q, expected %q", manifest.PinSource, PinSourceStatic)
	}
	want := []agentManifestItem{
		{OS: "linux", Arch: "amd64", Size: 15728640, SHA256: strings.Repeat("a1", 32)},
		{OS: "linux", Arch: "arm64", Size: 14680064, SHA256: strings.Repeat("b2", 32)},
	}
	if !slices.Equal(manifest.Agents, want) {
		t.Errorf("agents = %+v, expected %+v", manifest.Agents, want)
	}
}

// TestManifestWithClosedGate: the manifest stays reachable and lists
// the missing conditions — that is exactly why it is not gated.
func TestManifestWithClosedGate(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = fakeAgents{}
	deps.AgentPublicURL = ""
	recorder := get(t, rolloutMux(t, deps), "/v1/agents")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200 (diagnostic function)", recorder.Code)
	}
	var manifest agentManifest
	if err := json.NewDecoder(recorder.Body).Decode(&manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if manifest.RolloutReady {
		t.Error("rollout_ready = true despite missing conditions")
	}
	if !slices.Equal(manifest.Missing, []string{rolloutMissingBinaries, rolloutMissingAgentURL}) {
		t.Errorf("missing = %v, expected [binaries agent_public_url]", manifest.Missing)
	}
	if len(manifest.Agents) != 0 {
		t.Errorf("agents = %+v, expected empty", manifest.Agents)
	}
}

// TestManifestReportsPinErrorCategory: if no pin source returns a pin, the
// manifest reports the coarse category — the full text stays in the log,
// the manifest is unauthenticated and public.
func TestManifestReportsPinErrorCategory(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	logger, _ := testLogger()
	deps.Pins = NewPinProvider(PinProviderConfig{DialURL: "http://gssh.example.com"}, logger)

	recorder := get(t, rolloutMux(t, deps), "/v1/agents")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200", recorder.Code)
	}
	body := recorder.Body.String()

	var manifest agentManifest
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if manifest.PinError != PinErrNoPublicURL {
		t.Errorf("pin_error = %q, expected %q", manifest.PinError, PinErrNoPublicURL)
	}
	if strings.Contains(body, "is not a https url") {
		t.Errorf("manifest contains the full error text: %s", body)
	}
}

// TestDownloadStreamsBinary checks the success case including headers.
func TestDownloadStreamsBinary(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	recorder := get(t, rolloutMux(t, deps), "/v1/agents/linux/arm64")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200 (body %q)", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, expected application/octet-stream", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, expected no-store", got)
	}
	if got := recorder.Header().Get("Content-Length"); got != strconv.FormatInt(14680064, 10) {
		t.Errorf("Content-Length = %q, expected 14680064", got)
	}
	if recorder.Body.String() != "arm64" {
		t.Errorf("body = %q, expected the binary content", recorder.Body.String())
	}
}

// TestDownloadUnknownArch: non-embedded or nonsensical platforms yield
// 404, not 503 — the gate is open after all.
func TestDownloadUnknownArch(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	mux := rolloutMux(t, deps)

	for _, path := range []string{"/v1/agents/linux/riscv64", "/v1/agents/windows/amd64"} {
		if code := get(t, mux, path).Code; code != http.StatusNotFound {
			t.Errorf("%s: status = %d, expected 404", path, code)
		}
	}
}

// TestGateClosesDownloadAndScript: if a condition is missing, download
// and install.sh respond with 503 and name it.
func TestGateClosesDownloadAndScript(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	deps.Pins = nil // no pin determinable
	mux := rolloutMux(t, deps)

	for _, path := range []string{"/v1/agents/linux/amd64", "/install.sh"} {
		recorder := get(t, mux, path)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, expected 503", path, recorder.Code)
		}
		var body rolloutUnavailable
		if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
			t.Fatalf("%s: decoding response: %v", path, err)
		}
		if !slices.Equal(body.Missing, []string{rolloutMissingPin}) {
			t.Errorf("%s: missing = %v, expected [pin]", path, body.Missing)
		}
	}
}

// TestInstallScriptContent: the served script already carries the pin,
// hashes, URLs, and the systemd unit within it; only the token stays
// variable.
func TestInstallScriptContent(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	recorder := get(t, rolloutMux(t, deps), "/install.sh")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200 (body %q)", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/x-shellscript; charset=utf-8" {
		t.Errorf("Content-Type = %q, expected text/x-shellscript", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, expected no-store", got)
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
		"ExecStart=/usr/bin/gssh-agentd run", // unit content from agentdist
		"\nmain \"$@\"\n",                    // call only on the last line
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script does not contain %q", want)
		}
	}
	// Rule 5: no pipefail, no bash.
	if strings.Contains(script, "set -o pipefail") {
		t.Error("script uses set -o pipefail (not reliable in dash/busybox)")
	}
	// The here-doc terminator must be at the start of a line, otherwise
	// cat swallows the rest of the script.
	if !strings.Contains(script, "\nUNIT_EOF\n") {
		t.Error("here-doc terminator UNIT_EOF is not at the start of a line")
	}
}

// TestInstallScriptSyntax runs `sh -n` over the rendered script — a
// template error should surface here, not on the host.
func TestInstallScriptSyntax(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh in PATH: %v", err)
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
		t.Fatalf("rendering script: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), shell, "-n")
	cmd.Stdin = strings.NewReader(string(script))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n reports a syntax error: %v\n%s", err, out)
	}
}

// TestInstallScriptQuotingFailClosed: every templated value that could
// break the script aborts rendering instead of shipping a broken script
// to N hosts.
func TestInstallScriptQuotingFailClosed(t *testing.T) {
	valid := installScriptData{
		BaseURL:  "https://gssh.example.com",
		AgentURL: "https://agent.gssh.example.com",
		Version:  "v0.0.0-test",
		Pin:      testPinPin,
		Agents:   linuxAgents(twoAgents),
		Unit:     agentdist.UnitFile,
	}

	for name, mutate := range map[string]func(d *installScriptData){
		"quote in the url": func(d *installScriptData) {
			d.BaseURL = "https://gssh.example.com/'; rm -rf /; '"
		},
		"arch breaks the case pattern": func(d *installScriptData) {
			d.Agents = []agentManifestItem{{OS: "linux", Arch: "amd64) echo pwned ;;", SHA256: strings.Repeat("a1", 32)}}
		},
		"sha is not hex": func(d *installScriptData) {
			d.Agents = []agentManifestItem{{OS: "linux", Arch: "amd64", SHA256: "not-hex"}}
		},
		"terminator in the first unit line": func(d *installScriptData) {
			d.Unit = "UNIT_EOF\nrm -rf /\n"
		},
	} {
		data := valid
		mutate(&data)
		if _, err := renderInstallScript(data); err == nil {
			t.Errorf("%s: rendering returned no error", name)
		}
	}

	if _, err := renderInstallScript(valid); err != nil {
		t.Fatalf("valid data: %v", err)
	}
}

// TestRolloutRoutesInFullMux: the routes must also work in the full
// public mux — /install.sh must not end up in the SPA fallback ("/").
func TestRolloutRoutesInFullMux(t *testing.T) {
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
			t.Errorf("%s: status = %d, expected 200", path, recorder.Code)
			continue
		}
		if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, wantType) {
			t.Errorf("%s: Content-Type = %q, expected %q", path, got, wantType)
		}
	}
}

// TestDownloadRateLimit: the download hangs off its own, tighter limiter —
// not the regular one of the sign/enroll endpoints.
func TestDownloadRateLimit(t *testing.T) {
	deps := readyDeps(t)
	deps.Agents = twoAgents
	deps.DownloadRateLimit = NewRateLimiter(RateLimiterConfig{RequestsPerMinute: 10, Burst: 2})
	mux := rolloutMux(t, deps)

	for i := range 2 {
		if code := get(t, mux, "/v1/agents/linux/amd64").Code; code != http.StatusOK {
			t.Fatalf("request %d: status = %d, expected 200", i, code)
		}
	}
	if code := get(t, mux, "/v1/agents/linux/amd64").Code; code != http.StatusTooManyRequests {
		t.Errorf("after burst exhausted: status = %d, expected 429", code)
	}
	// Manifest and script run on the regular limiter and stay free.
	if code := get(t, mux, "/v1/agents").Code; code != http.StatusOK {
		t.Errorf("manifest: status = %d, expected 200 (own limiter)", code)
	}
}
