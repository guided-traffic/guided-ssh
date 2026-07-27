package api

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubBinary is what the fake curl "downloads"; its hash goes into the
// rendered script, so the script's SHA-256 check passes unchanged.
const stubBinary = "stub-gssh-binary\n"

// curlStub replaces curl for the run: it ignores every option except -o and
// writes the stub binary there. Everything else in the script — hash check,
// atomic mv, config handling — runs for real.
const curlStub = `#!/bin/sh
out=''
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$out" ] || exit 1
printf '%s' '` + stubBinary + `' > "$out"
`

// scriptRun is one client.sh execution against a temporary HOME.
type scriptRun struct {
	t          *testing.T
	script     string // path of the rendered script
	home       string
	binDir     string
	configPath string
	path       string // PATH with the curl stub in front
}

// scriptServerURL is the server the rendered script belongs to.
const scriptServerURL = "https://gssh.example.com"

// newScriptRun renders client.sh for the host platform and prepares a
// throwaway HOME plus the curl stub.
func newScriptRun(t *testing.T) *scriptRun {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("client.sh refuses to run as root by design")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no sh in PATH: %v", err)
	}

	sum := sha256.Sum256([]byte(stubBinary))
	script, err := renderClientScript(clientScriptData{
		BaseURL:  scriptServerURL,
		Version:  "v0.0.0-test",
		Issuer:   "https://idp.example.com",
		ClientID: "gssh-cli",
		PinHint:  "no operator-controlled pin source configured on the server",
		// One entry is enough: the run passes --os/--arch explicitly, so
		// uname mapping is not part of this test.
		Clients: []clientManifestItem{{OS: "linux", Arch: "amd64", SHA256: hex.EncodeToString(sum[:])}},
	})
	if err != nil {
		t.Fatalf("rendering script: %v", err)
	}

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "client.sh")
	if err := os.WriteFile(scriptPath, script, 0o600); err != nil {
		t.Fatal(err)
	}
	stubDir := filepath.Join(dir, "stub")
	if err := os.Mkdir(stubDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stubDir, "curl"), []byte(curlStub), 0o700); err != nil {
		t.Fatal(err)
	}

	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return &scriptRun{
		t:          t,
		script:     scriptPath,
		home:       home,
		binDir:     filepath.Join(dir, "bin"),
		configPath: filepath.Join(home, ".config", "guided-ssh", "config.yaml"),
		path:       stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	}
}

// run executes the script once and returns its combined output.
func (r *scriptRun) run() string {
	r.t.Helper()
	cmd := exec.CommandContext(r.t.Context(), "sh",
		r.script, "--os", "linux", "--arch", "amd64", "--bin-dir", r.binDir)
	cmd.Env = append(os.Environ(), "HOME="+r.home, "PATH="+r.path)
	cmd.Env = append(cmd.Env, "XDG_CONFIG_HOME="+filepath.Join(r.home, ".config"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("client.sh: %v\n%s", err, out)
	}
	return string(out)
}

// config reads the written configuration.
func (r *scriptRun) config(suffix string) string {
	r.t.Helper()
	raw, err := os.ReadFile(r.configPath + suffix)
	if err != nil {
		r.t.Fatalf("reading config%s: %v", suffix, err)
	}
	return string(raw)
}

// writeConfig plants a configuration for the next run.
func (r *scriptRun) writeConfig(content string) {
	r.t.Helper()
	if err := os.MkdirAll(filepath.Dir(r.configPath), 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.configPath, []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// TestClientScriptWritesConfig: the first run writes exactly the server's
// values, unpinned and 0600.
func TestClientScriptWritesConfig(t *testing.T) {
	run := newScriptRun(t)

	out := run.run()
	if !strings.Contains(out, "configuration written") {
		t.Errorf("first run without 'configuration written':\n%s", out)
	}
	config := run.config("")
	for _, want := range []string{
		`api_url: "https://gssh.example.com"`,
		`issuer: "https://idp.example.com"`,
		`client_id: "gssh-cli"`,
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config is missing %s:\n%s", want, config)
		}
	}
	if strings.Contains(config, "pin_sha256") {
		t.Errorf("config contains a pin without --pin:\n%s", config)
	}
	info, err := os.Stat(run.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("config mode = %o, want 600", mode)
	}
}

// TestClientScriptReplacesForeignConfig: installing from another server
// repoints the client at that server — that is how an environment switch
// works — and the pin of the previous server does not travel along.
func TestClientScriptReplacesForeignConfig(t *testing.T) {
	run := newScriptRun(t)
	run.writeConfig(`api_url: "https://gssh.other.example"
issuer: "https://idp.other.example"
client_id: "gssh-cli"
pin_sha256: "` + strings.Repeat("A", 43) + `="
validity: 4h
`)

	out := run.run()
	for _, want := range []string{
		"switching configuration from https://gssh.other.example",
		"existing configuration replaced",
		"was dropped",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output without %q:\n%s", want, out)
		}
	}
	config := run.config("")
	if !strings.Contains(config, `api_url: "https://gssh.example.com"`) {
		t.Errorf("api_url not repointed:\n%s", config)
	}
	if strings.Contains(config, "pin_sha256") {
		t.Errorf("pin of the other server carried over:\n%s", config)
	}
	// The replaced file stays readable, so hand-made settings can be copied
	// back out of it.
	backup := run.config(".bak")
	if !strings.Contains(backup, "validity: 4h") || !strings.Contains(backup, "gssh.other.example") {
		t.Errorf("backup does not hold the previous configuration:\n%s", backup)
	}
	info, err := os.Stat(run.configPath + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("backup mode = %o, want 600", mode)
	}
}

// TestClientScriptKeepsPinOfSameServer: a pin the user set for this server
// survives the rewrite — silently dropping it would downgrade a pinned
// client to plain WebPKI.
func TestClientScriptKeepsPinOfSameServer(t *testing.T) {
	pin := strings.Repeat("A", 43) + "="
	run := newScriptRun(t)
	run.writeConfig(`api_url: "https://gssh.example.com"
issuer: "https://idp.example.com"
client_id: "gssh-cli"
pin_sha256: "` + pin + `"
`)

	out := run.run()
	if !strings.Contains(out, "keeping the configured pin") {
		t.Errorf("output without a notice about the kept pin:\n%s", out)
	}
	if config := run.config(""); !strings.Contains(config, `pin_sha256: "`+pin+`"`) {
		t.Errorf("pin for this server was dropped:\n%s", config)
	}
}

// TestClientScriptRejectsUnparsablePin: a pin_sha256 that is not base64
// would end up unescaped in a double-quoted YAML scalar — it is dropped
// with a notice instead of being copied blindly.
func TestClientScriptRejectsUnparsablePin(t *testing.T) {
	run := newScriptRun(t)
	run.writeConfig(`api_url: "https://gssh.example.com"
issuer: "https://idp.example.com"
client_id: "gssh-cli"
pin_sha256: "not a pin\" # broken"
`)

	out := run.run()
	if !strings.Contains(out, "not base64") {
		t.Errorf("output without a notice about the unusable pin:\n%s", out)
	}
	if config := run.config(""); strings.Contains(config, "pin_sha256") {
		t.Errorf("unusable pin was carried over:\n%s", config)
	}
}
