package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/bindist"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// fakeClients is a ClientSource with a fixed list; Open returns "<os>/<arch>"
// as content (enough to verify the stream).
type fakeClients []bindist.Info

func (f fakeClients) List() []bindist.Info { return f }

func (f fakeClients) Open(osName, arch string) (io.ReadCloser, bindist.Info, error) {
	for _, info := range f {
		if info.OS == osName && info.Arch == arch {
			return io.NopCloser(strings.NewReader(osName + "/" + arch)), info, nil
		}
	}
	return nil, bindist.Info{}, fmt.Errorf("%w: %s/%s", bindist.ErrNotFound, osName, arch)
}

// threeClients mirrors the three platforms the Docker build embeds.
var threeClients = fakeClients{
	{OS: "darwin", Arch: "arm64", Size: 8178000, SHA256: strings.Repeat("c3", 32)},
	{OS: "linux", Arch: "amd64", Size: 8599000, SHA256: strings.Repeat("a1", 32)},
	{OS: "linux", Arch: "arm64", Size: 7968000, SHA256: strings.Repeat("b2", 32)},
}

// readyClientDeps are dependencies with all client gate conditions satisfied.
func readyClientDeps(t *testing.T) Deps {
	t.Helper()
	logger, _ := testLogger()
	return Deps{
		Clients:       threeClients,
		Pins:          NewPinProvider(PinProviderConfig{StaticPin: testPinPin}, logger),
		PublicBaseURL: "https://gssh.example.com",
		UIConfig: UIConfig{
			OIDCIssuer:   "https://idp.example.com",
			OIDCClientID: "gssh-cli",
		},
		Logger: logger,
	}
}

// clientMux builds a mux with exclusively the three client routes.
func clientMux(t *testing.T, deps Deps) *http.ServeMux {
	t.Helper()
	if deps.Logger == nil {
		deps.Logger, _ = testLogger()
	}
	mux := http.NewServeMux()
	registerClientRoutes(mux, deps)
	return mux
}

// TestClientGateConditions: each missing individual condition produces a 503
// with exactly its missing entry.
func TestClientGateConditions(t *testing.T) {
	if gate := newClientGate(readyClientDeps(t)); len(gate.status(t.Context()).Missing) != 0 {
		t.Fatalf("complete configuration: missing = %v, expected empty",
			gate.status(t.Context()).Missing)
	}

	tests := map[string]struct {
		mutate func(*Deps)
		want   string
	}{
		"no binaries":      {func(d *Deps) { d.Clients = fakeClients{} }, clientMissingBinaries},
		"no client source": {func(d *Deps) { d.Clients = nil }, clientMissingBinaries},
		"no public url":    {func(d *Deps) { d.PublicBaseURL = "" }, clientMissingPublicURL},
		"public url not https": {
			func(d *Deps) { d.PublicBaseURL = "http://gssh.example.com" },
			clientMissingPublicURLHTTPS,
		},
		"public url unparsable": {
			func(d *Deps) { d.PublicBaseURL = "https://%zz" },
			clientMissingPublicURLHTTPS,
		},
		"no issuer":    {func(d *Deps) { d.UIConfig.OIDCIssuer = "" }, clientMissingOIDCIssuer},
		"no client id": {func(d *Deps) { d.UIConfig.OIDCClientID = "" }, clientMissingOIDCClientID},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			deps := readyClientDeps(t)
			tc.mutate(&deps)
			gate := newClientGate(deps)

			missing := gate.status(t.Context()).Missing
			if !slices.Equal(missing, []string{tc.want}) {
				t.Fatalf("missing = %v, expected exactly [%s]", missing, tc.want)
			}

			recorder := httptest.NewRecorder()
			if gate.allow(recorder, httptest.NewRequest(http.MethodGet, "/client.sh", nil)) {
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

// TestClientGateIgnoresPin: the pin is deliberately not a gate condition —
// the generated config uses WebPKI, the pin is an opt-in.
func TestClientGateIgnoresPin(t *testing.T) {
	logger, _ := testLogger()
	for name, pins := range map[string]*PinProvider{
		"no pin provider": nil,
		"pin source without a pin": NewPinProvider(
			PinProviderConfig{DialURL: "http://gssh.example.com"}, logger),
	} {
		t.Run(name, func(t *testing.T) {
			deps := readyClientDeps(t)
			deps.Pins = pins
			if missing := newClientGate(deps).status(t.Context()).Missing; len(missing) != 0 {
				t.Fatalf("missing = %v, expected the gate to be open without a pin", missing)
			}
		})
	}
}

// TestClientManifestReady: with the gate open, the manifest lists all
// platforms and carries the operator-controlled pin.
func TestClientManifestReady(t *testing.T) {
	recorder := get(t, clientMux(t, readyClientDeps(t)), "/v1/clients")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, expected no-store", got)
	}

	var manifest clientManifest
	if err := json.NewDecoder(recorder.Body).Decode(&manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if !manifest.Ready || len(manifest.Missing) != 0 {
		t.Errorf("ready = %v, missing = %v — expected true/empty", manifest.Ready, manifest.Missing)
	}
	if manifest.Version != version.String() {
		t.Errorf("version = %q, expected %q", manifest.Version, version.String())
	}
	if manifest.Pin != testPinPin || manifest.PinSource != PinSourceStatic {
		t.Errorf("pin = %q / source = %q, expected the static test pin", manifest.Pin, manifest.PinSource)
	}
	want := []clientManifestItem{
		{OS: "darwin", Arch: "arm64", Size: 8178000, SHA256: strings.Repeat("c3", 32)},
		{OS: "linux", Arch: "amd64", Size: 8599000, SHA256: strings.Repeat("a1", 32)},
		{OS: "linux", Arch: "arm64", Size: 7968000, SHA256: strings.Repeat("b2", 32)},
	}
	if !slices.Equal(manifest.Clients, want) {
		t.Errorf("clients = %+v, expected %+v", manifest.Clients, want)
	}
}

// TestClientManifestWithClosedGate: the manifest stays reachable and lists
// the missing conditions — that is exactly why it is not gated.
func TestClientManifestWithClosedGate(t *testing.T) {
	deps := readyClientDeps(t)
	deps.Clients = fakeClients{}
	deps.UIConfig.OIDCClientID = ""
	recorder := get(t, clientMux(t, deps), "/v1/clients")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200 (diagnostic function)", recorder.Code)
	}
	var manifest clientManifest
	if err := json.NewDecoder(recorder.Body).Decode(&manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if manifest.Ready {
		t.Error("ready = true despite missing conditions")
	}
	if !slices.Equal(manifest.Missing, []string{clientMissingBinaries, clientMissingOIDCClientID}) {
		t.Errorf("missing = %v, expected [binaries oidc_client_id]", manifest.Missing)
	}
	if len(manifest.Clients) != 0 {
		t.Errorf("clients = %+v, expected empty", manifest.Clients)
	}
}

// TestClientManifestNeverOffersDialPin: a dialed pin rotates with the
// certificate and would break the DNS fallback mid-outage — it is reported
// as a source but never handed out as a value.
func TestClientManifestNeverOffersDialPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := testLogger()
	pins := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Nanosecond}, logger)
	pins.dialRoots = trustPool(server.Certificate())
	if st := pins.Status(t.Context()); st.Pin == "" || st.Source != PinSourceDial {
		t.Fatalf("test setup: pin status = %+v, expected a dialed pin", st)
	}

	deps := readyClientDeps(t)
	deps.Pins = pins

	var manifest clientManifest
	if err := json.NewDecoder(get(t, clientMux(t, deps), "/v1/clients").Body).Decode(&manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if manifest.Pin != "" {
		t.Errorf("pin = %q, expected empty for the dial source", manifest.Pin)
	}
	if manifest.PinSource != PinSourceDial {
		t.Errorf("pin_source = %q, expected %q (diagnosis for the UI)", manifest.PinSource, PinSourceDial)
	}

	// The same rule applies to the script: no pin line, and --pin explains
	// the dial source instead of silently downgrading.
	script := get(t, clientMux(t, deps), "/client.sh").Body.String()
	if !strings.Contains(script, "PIN=''") {
		t.Error("script carries a pin despite the dial source")
	}
	if !strings.Contains(script, "auto-derived (dial)") {
		t.Error("script does not explain the dial source in PIN_HINT")
	}
}

// TestClientDownloadStreamsBinary checks the success case including headers.
func TestClientDownloadStreamsBinary(t *testing.T) {
	recorder := get(t, clientMux(t, readyClientDeps(t)), "/v1/clients/darwin/arm64")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200 (body %q)", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, expected application/octet-stream", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, expected no-store", got)
	}
	if got := recorder.Header().Get("Content-Length"); got != strconv.Itoa(8178000) {
		t.Errorf("Content-Length = %q, expected 8178000", got)
	}
	if recorder.Body.String() != "darwin/arm64" {
		t.Errorf("body = %q, expected the binary content", recorder.Body.String())
	}
}

// TestClientDownloadUnknownPlatform: non-embedded platforms yield 404, not
// 503 — the gate is open after all.
func TestClientDownloadUnknownPlatform(t *testing.T) {
	mux := clientMux(t, readyClientDeps(t))
	for _, path := range []string{"/v1/clients/linux/riscv64", "/v1/clients/windows/amd64"} {
		if code := get(t, mux, path).Code; code != http.StatusNotFound {
			t.Errorf("%s: status = %d, expected 404", path, code)
		}
	}
}

// TestClientGateClosesDownloadAndScript: if a condition is missing, download
// and client.sh respond with 503 and name it.
func TestClientGateClosesDownloadAndScript(t *testing.T) {
	deps := readyClientDeps(t)
	deps.UIConfig.OIDCIssuer = ""
	mux := clientMux(t, deps)

	for _, path := range []string{"/v1/clients/linux/amd64", "/client.sh"} {
		recorder := get(t, mux, path)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, expected 503", path, recorder.Code)
		}
		var body rolloutUnavailable
		if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
			t.Fatalf("%s: decoding response: %v", path, err)
		}
		if !slices.Equal(body.Missing, []string{clientMissingOIDCIssuer}) {
			t.Errorf("%s: missing = %v, expected [oidc_issuer]", path, body.Missing)
		}
	}
}

// TestClientScriptContent: the served script already carries every config
// value and all hashes; it needs no arguments.
func TestClientScriptContent(t *testing.T) {
	deps := readyClientDeps(t)
	recorder := get(t, clientMux(t, deps), "/client.sh")

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
		"SERVER_URL='" + deps.PublicBaseURL + "'",
		"ISSUER='" + deps.UIConfig.OIDCIssuer + "'",
		"CLIENT_ID='" + deps.UIConfig.OIDCClientID + "'",
		"PIN='" + testPinPin + "'",
		"VERSION='" + version.String() + "'",
		"PLATFORMS='darwin/arm64 linux/amd64 linux/arm64'",
		"darwin/arm64) echo '" + strings.Repeat("c3", 32) + "'",
		"linux/amd64) echo '" + strings.Repeat("a1", 32) + "'",
		"linux/arm64) echo '" + strings.Repeat("b2", 32) + "'",
		"\nmain \"$@\"\n", // call only on the last line
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script does not contain %q", want)
		}
	}
	// Rule 5 of the host plan: no pipefail, no bash.
	if strings.Contains(script, "set -o pipefail") {
		t.Error("script uses set -o pipefail (not reliable in dash/busybox)")
	}
	// Root-free by construction: refusal for uid 0, no system-wide target,
	// and no sudo call anywhere (the word appears only in the abort message).
	if !strings.Contains(script, `[ "$(id -u)" != 0 ]`) {
		t.Error("script does not refuse to run as root")
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "sudo ") {
			t.Errorf("script calls sudo: %q", line)
		}
	}
	if strings.Contains(script, "/usr/local/bin") {
		t.Error("script installs into /usr/local/bin — that path needs root")
	}
}

// TestClientScriptSyntax runs `sh -n` over the rendered script — a template
// error should surface here, not on the user's machine.
func TestClientScriptSyntax(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh in PATH: %v", err)
	}
	script := renderTestClientScript(t, testPinPin)

	cmd := exec.CommandContext(t.Context(), shell, "-n")
	cmd.Stdin = strings.NewReader(string(script))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n reports a syntax error: %v\n%s", err, out)
	}
}

// TestClientScriptPinFlagFailsClosed: `--pin` against a server without an
// operator-controlled pin aborts before anything is downloaded or written —
// never a silent downgrade to an unpinned config.
func TestClientScriptPinFlagFailsClosed(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh in PATH: %v", err)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: the script aborts on the root check first")
	}

	home := t.TempDir()
	script := filepath.Join(home, "client.sh")
	if err := os.WriteFile(script, renderTestClientScript(t, ""), 0o700); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), shell, script, "--pin")
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("script with --pin and no pin succeeded: %s", out)
	}
	if !strings.Contains(string(out), "--pin requested") {
		t.Errorf("output does not name the cause: %s", out)
	}
	if entries, _ := os.ReadDir(filepath.Join(home, "cfg")); len(entries) != 0 {
		t.Errorf("script wrote configuration despite aborting: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", "gssh")); err == nil {
		t.Error("script installed a binary despite aborting")
	}
}

// TestClientScriptRenderFailClosed: every templated value that could break
// the script or the written YAML aborts rendering instead of shipping a
// broken script.
func TestClientScriptRenderFailClosed(t *testing.T) {
	valid := clientScriptData{
		BaseURL:  "https://gssh.example.com",
		Version:  "v0.0.0-test",
		Issuer:   "https://idp.example.com",
		ClientID: "gssh-cli",
		Pin:      testPinPin,
		Clients:  clientItems(threeClients),
	}

	for name, mutate := range map[string]func(d *clientScriptData){
		"quote in the url": func(d *clientScriptData) {
			d.BaseURL = "https://gssh.example.com/'; rm -rf /; '"
		},
		"double quote in the client id": func(d *clientScriptData) {
			d.ClientID = `gssh"cli`
		},
		"backslash in the issuer": func(d *clientScriptData) {
			d.Issuer = `https://idp.example.com\n`
		},
		"line break in the pin hint": func(d *clientScriptData) {
			d.Pin, d.PinHint = "", "no pin\nrm -rf /"
		},
		"os breaks the case pattern": func(d *clientScriptData) {
			d.Clients = []clientManifestItem{{OS: "linux) echo pwned ;;", Arch: "amd64", SHA256: strings.Repeat("a1", 32)}}
		},
		"arch breaks the case pattern": func(d *clientScriptData) {
			d.Clients = []clientManifestItem{{OS: "linux", Arch: "amd64) echo pwned ;;", SHA256: strings.Repeat("a1", 32)}}
		},
		"sha is not hex": func(d *clientScriptData) {
			d.Clients = []clientManifestItem{{OS: "linux", Arch: "amd64", SHA256: "not-hex"}}
		},
	} {
		data := valid
		mutate(&data)
		if _, err := renderClientScript(data); err == nil {
			t.Errorf("%s: rendering returned no error", name)
		}
	}

	if _, err := renderClientScript(valid); err != nil {
		t.Fatalf("valid data: %v", err)
	}
}

// TestClientRoutesInFullMux: the routes must also work in the full public
// mux — /client.sh must not end up in the SPA fallback ("/").
func TestClientRoutesInFullMux(t *testing.T) {
	handler := New(readyClientDeps(t))

	tests := map[string]string{
		"/v1/clients":             "application/json",
		"/v1/clients/linux/amd64": "application/octet-stream",
		"/client.sh":              "text/x-shellscript",
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

// TestClientDownloadSharesDownloadLimiter: the client binary hangs off the
// same tighter limiter as the agent download (decision log 6) — manifest and
// script stay on the regular one.
func TestClientDownloadSharesDownloadLimiter(t *testing.T) {
	deps := readyClientDeps(t)
	deps.Agents = twoAgents
	deps.AgentPublicURL = "https://agent.gssh.example.com"
	deps.DownloadRateLimit = NewRateLimiter(RateLimiterConfig{RequestsPerMinute: 10, Burst: 2})

	mux := http.NewServeMux()
	registerRolloutRoutes(mux, deps)
	registerClientRoutes(mux, deps)

	if code := get(t, mux, "/v1/agents/linux/amd64").Code; code != http.StatusOK {
		t.Fatalf("agent download: status = %d, expected 200", code)
	}
	if code := get(t, mux, "/v1/clients/linux/amd64").Code; code != http.StatusOK {
		t.Fatalf("client download: status = %d, expected 200", code)
	}
	if code := get(t, mux, "/v1/clients/linux/amd64").Code; code != http.StatusTooManyRequests {
		t.Errorf("after the shared burst is exhausted: status = %d, expected 429", code)
	}
	if code := get(t, mux, "/v1/clients").Code; code != http.StatusOK {
		t.Errorf("manifest: status = %d, expected 200 (own limiter)", code)
	}
}

// renderTestClientScript renders the script with the given pin (empty ⇒ the
// hint of a server without an operator-controlled source).
func renderTestClientScript(t *testing.T, pin string) []byte {
	t.Helper()
	data := clientScriptData{
		BaseURL:  "https://gssh.example.com",
		Version:  "v0.0.0-test",
		Issuer:   "https://idp.example.com",
		ClientID: "gssh-cli",
		Pin:      pin,
		Clients:  clientItems(threeClients),
	}
	if pin == "" {
		data.PinHint = "no operator-controlled pin source configured on the server"
	}
	script, err := renderClientScript(data)
	if err != nil {
		t.Fatalf("rendering script: %v", err)
	}
	return script
}
