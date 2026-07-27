package agentd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testSSHDir builds an sshd directory whose sshd_config includes the
// generated snippet — the state a host must be in for enrollment to work.
func testSSHDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(SSHDConfigPath(dir), []byte(includeLine(dir)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// stubSSHD writes a fake sshd binary: `-t` exits with tExit, `-T` prints the
// given port. Keeps the enrollment tests independent of a real sshd.
func stubSSHD(t *testing.T, port string, tExit int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub requires a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "sshd")
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
  -t) exit %d ;;
  -T) echo "port %s"; echo "pidfile /nonexistent/sshd.pid" ;;
esac
`, tExit, port)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	return path
}

func TestIncludeCovers(t *testing.T) {
	tests := map[string]struct {
		config string
		want   bool
	}{
		"absolute glob":     {config: "Include /etc/ssh/sshd_config.d/*.conf", want: true},
		"relative glob":     {config: "Include sshd_config.d/*.conf", want: true},
		"exact path":        {config: "Include /etc/ssh/sshd_config.d/guided-ssh.conf", want: true},
		"lowercase keyword": {config: "include /etc/ssh/sshd_config.d/*.conf", want: true},
		"several patterns":  {config: "Include /etc/ssh/other.d/*.conf /etc/ssh/sshd_config.d/*.conf", want: true},
		"leading comment":   {config: "# Include /etc/ssh/sshd_config.d/*.conf", want: false},
		"missing":           {config: "PasswordAuthentication no", want: false},
		"other directory":   {config: "Include /etc/ssh/other.d/*.conf", want: false},
		// An Include inside a Match block applies conditionally — it does not
		// cover every login, so it must not count as included.
		"after match block": {config: "Match User root\n  Include /etc/ssh/sshd_config.d/*.conf", want: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := includeCovers(tc.config, "/etc/ssh"); got != tc.want {
				t.Errorf("includeCovers(%q) = %v, want %v", tc.config, got, tc.want)
			}
		})
	}
}

// TestVerifyIncludeNamesTheLine: the error must be actionable — it names the
// exact line to add, instead of hiding a hint in the success output.
func TestVerifyIncludeNamesTheLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(SSHDConfigPath(dir), []byte("PasswordAuthentication no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifyInclude(dir)
	if err == nil || !strings.Contains(err.Error(), includeLine(dir)) {
		t.Fatalf("error must name the Include line, got %v", err)
	}
	// The operator's sshd_config stays untouched.
	raw, readErr := os.ReadFile(SSHDConfigPath(dir))
	if readErr != nil || string(raw) != "PasswordAuthentication no\n" {
		t.Fatalf("sshd_config was modified: %q %v", raw, readErr)
	}

	if err := verifyInclude(t.TempDir()); err == nil {
		t.Error("missing sshd_config must be an error")
	}
	if err := verifyInclude(testSSHDir(t)); err != nil {
		t.Errorf("valid Include rejected: %v", err)
	}
}

func TestDetectReloadCommand(t *testing.T) {
	binDir := t.TempDir()
	systemctl := filepath.Join(binDir, "systemctl")
	// Answers like a RHEL host: sshd.service exists, ssh.service does not.
	script := `#!/bin/sh
case "$4" in
  sshd.service) echo loaded ;;
  *) echo not-found ;;
esac
`
	if err := os.WriteFile(systemctl, []byte(script), 0o700); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	if got := detectReloadCommand(""); got != "systemctl reload sshd" {
		t.Errorf("detectReloadCommand = %q", got)
	}

	// Nothing on PATH and no pid file ⇒ nothing detected; the caller warns.
	t.Setenv("PATH", t.TempDir())
	if got := detectReloadCommand(stubSSHD(t, "22", 0)); got != "" {
		t.Errorf("detectReloadCommand without an init system = %q", got)
	}
}

// startTestSSHD serves the SSH handshake with the given host key on
// 127.0.0.1 and returns its port. Authentication never happens — the probe
// aborts as soon as it has seen the host key.
func startTestSSHD(t *testing.T, hostKey ssh.Signer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostKey)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				serverConn, _, _, serveErr := ssh.NewServerConn(conn, cfg)
				if serveErr == nil {
					_ = serverConn.Close()
				}
			}()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// testHostSigners returns a plain host key signer and one presenting a host
// certificate for the same key.
func testHostSigners(t *testing.T) (plain, certified ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.HostCert,
		KeyId:           "host:probe",
		ValidPrincipals: []string{"probe"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()), //nolint:gosec // unix time after 1970
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),    //nolint:gosec // same
	}
	if err := cert.SignCert(rand.Reader, plain); err != nil {
		t.Fatal(err)
	}
	certified, err = ssh.NewCertSigner(cert, plain)
	if err != nil {
		t.Fatal(err)
	}
	return plain, certified
}

// TestVerifyRunningSSHD covers the point of the whole exercise: what the
// *running* daemon serves, not what is on disk.
func TestVerifyRunningSSHD(t *testing.T) {
	plain, certified := testHostSigners(t)

	certPort := startTestSSHD(t, certified)
	var out bytes.Buffer
	if err := verifyRunningSSHD(stubSSHD(t, certPort, 0), "/etc/ssh", false, &out); err != nil {
		t.Fatalf("daemon serving a certificate must pass: %v", err)
	}
	if !strings.Contains(out.String(), "serves the guided-ssh host certificate") {
		t.Errorf("output = %q", out.String())
	}

	// Same files on disk, but the running daemon still serves a plain key —
	// the failure that used to be invisible.
	plainPort := startTestSSHD(t, plain)
	out.Reset()
	err := verifyRunningSSHD(stubSSHD(t, plainPort, 0), "/etc/ssh", false, &out)
	if err == nil || !strings.Contains(err.Error(), "plain host key") {
		t.Fatalf("stale daemon must fail loudly, got %v", err)
	}
	// With --no-reload the operator reloads themselves ⇒ reported, not fatal.
	out.Reset()
	if err := verifyRunningSSHD(stubSSHD(t, plainPort, 0), "/etc/ssh", true, &out); err != nil {
		t.Fatalf("--no-reload must not fail: %v", err)
	}
	if !strings.Contains(out.String(), "has not read the new configuration") {
		t.Errorf("output = %q", out.String())
	}

	// Nothing listening ⇒ inconclusive, reported but not fatal (image build,
	// sshd not started yet).
	out.Reset()
	if err := verifyRunningSSHD(stubSSHD(t, "1", 0), "/etc/ssh", false, &out); err != nil {
		t.Fatalf("unreachable sshd must not fail enrollment: %v", err)
	}
	if !strings.Contains(out.String(), "not reachable") {
		t.Errorf("output = %q", out.String())
	}

	// No sshd binary at all ⇒ nothing can be verified, but it is said out loud.
	out.Reset()
	if err := verifyRunningSSHD("", "/etc/ssh", false, &out); err != nil {
		t.Fatalf("missing sshd binary must not fail enrollment: %v", err)
	}
	if !strings.Contains(out.String(), "sshd not found") {
		t.Errorf("output = %q", out.String())
	}
}

func TestValidateSSHDConfig(t *testing.T) {
	if err := validateSSHDConfig(stubSSHD(t, "22", 0)); err != nil {
		t.Errorf("valid configuration: %v", err)
	}
	if err := validateSSHDConfig(stubSSHD(t, "22", 1)); err == nil {
		t.Error("sshd -t failure must be reported")
	}
	if err := validateSSHDConfig(""); err != nil {
		t.Errorf("without an sshd binary there is nothing to validate: %v", err)
	}
}

func TestRunReloadCmd(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "reloaded")
	if err := runReloadCmd("touch " + marker); err != nil {
		t.Fatalf("runReloadCmd: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("reload command did not run: %v", err)
	}
	if err := runReloadCmd("echo boom >&2; false"); err == nil {
		t.Error("failing reload command must be reported")
	}
}

// TestActivateSSHDReloadFailure: a failed reload is an enrollment failure —
// the host would be enrolled, granted, and unreachable.
func TestActivateSSHDReloadFailure(t *testing.T) {
	err := activateSSHD(stubSSHD(t, "1", 0), "/etc/ssh", "false", false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "reloading sshd") {
		t.Fatalf("expected reload error, got %v", err)
	}
}

// TestActivateSSHDWithoutReload: both ways of not reloading say so — the
// operator must never be left believing the configuration is live.
func TestActivateSSHDWithoutReload(t *testing.T) {
	tests := map[string]struct {
		reloadCmd string
		noReload  bool
		want      string
	}{
		"--no-reload":         {noReload: true, want: "reload skipped"},
		"nothing detected":    {want: "no reload command detected"},
		"reload command runs": {reloadCmd: "true", want: "sshd reloaded: true"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := activateSSHD(stubSSHD(t, "1", 0), "/etc/ssh", tc.reloadCmd, tc.noReload, &out); err != nil {
				t.Fatalf("activateSSHD: %v", err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Errorf("output = %q, want %q", out.String(), tc.want)
			}
		})
	}
}
