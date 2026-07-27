package agentd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshd reads its configuration exactly once, at startup: per-connection
// children are forks of the listener and inherit the already-parsed
// configuration. Writing the snippet therefore changes nothing for a daemon
// that is already running — `sshd -T` reads the files fresh from disk and
// reports the new configuration regardless, which makes the failure mode
// invisible to every obvious diagnostic. Everything in this file exists to
// make enrollment activate the configuration and prove it took effect.

// sshdSearchPaths are tried when sshd is not in PATH (it usually is not for
// a login shell, and enrollment runs as root from cron/systemd too).
var sshdSearchPaths = []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"}

// probeTimeout bounds the local handshake used to verify the running daemon.
const probeTimeout = 5 * time.Second

// probeHostKeyAlgos lists certificate algorithms first: the server picks the
// first algorithm of the *client's* list that it also supports, so a daemon
// with our HostCertificate loaded answers with a certificate and one without
// it falls back to a plain key. That difference is the whole probe.
var probeHostKeyAlgos = []string{
	ssh.CertAlgoED25519v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
	ssh.CertAlgoECDSA521v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA256v01,
	ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA,
	ssh.KeyAlgoECDSA521, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA256,
}

// errProbeDone aborts the probe handshake right after the host key is known —
// the probe must never attempt authentication.
var errProbeDone = errors.New("host key seen")

// SSHDConfigPath is the main sshd configuration file of an sshd directory.
func SSHDConfigPath(sshDir string) string {
	return filepath.Join(sshDir, "sshd_config")
}

// includeLine is the line the main sshd_config needs for the generated
// snippet to be read at all.
func includeLine(sshDir string) string {
	return fmt.Sprintf("Include %s/sshd_config.d/*.conf", strings.TrimRight(sshDir, "/"))
}

// verifyInclude checks that the main sshd_config actually pulls in the
// generated snippet. Without it enrollment writes a file nothing ever reads —
// the host looks enrolled and rejects every certificate. The operator's
// sshd_config is deliberately not edited: it is theirs, and an appended
// Include at the bottom would be shadowed by earlier keywords anyway (sshd
// keeps the first value it obtains).
func verifyInclude(sshDir string) error {
	configPath := SSHDConfigPath(sshDir)
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading %s (is openssh-server installed?): %w", configPath, err)
	}
	if includeCovers(string(raw), sshDir) {
		return nil
	}
	return fmt.Errorf("%s does not include %s — add this as the first line of %s and re-run:\n\n    %s",
		configPath, SnippetPath(sshDir), configPath, includeLine(sshDir))
}

// includeCovers reports whether an Include directive of the configuration
// matches the generated snippet.
func includeCovers(config, sshDir string) bool {
	snippet := SnippetPath(sshDir)
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		// Everything after a Match line applies conditionally; an Include
		// hidden in there would not cover every login, so it does not count.
		if strings.EqualFold(fields[0], "Match") {
			return false
		}
		if !strings.EqualFold(fields[0], "Include") {
			continue
		}
		for _, pattern := range fields[1:] {
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(sshDir, pattern)
			}
			if matched, err := filepath.Match(pattern, snippet); err == nil && matched {
				return true
			}
		}
	}
	return false
}

// resolveSSHD locates the sshd binary used for validation and probing.
// Empty result ⇒ neither is possible; the caller warns instead of failing,
// enrollment on a host with an unusual sshd layout must still work.
func resolveSSHD(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if path, err := exec.LookPath("sshd"); err == nil {
		return path
	}
	for _, candidate := range sshdSearchPaths {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// effectiveSSHDConfig runs `sshd -T` and returns the effective configuration
// keyed by directive (sshd lowercases them). Note that this is the
// configuration *on disk*, not what the running daemon has loaded — it is
// used here only for facts that do not change on reload (port, pid file).
func effectiveSSHDConfig(sshdBin string) map[string][]string {
	if sshdBin == "" {
		return nil
	}
	out, err := exec.Command(sshdBin, "-T").Output() //nolint:gosec // resolved sshd binary
	if err != nil {
		return nil
	}
	config := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found {
			continue
		}
		config[key] = append(config[key], value)
	}
	return config
}

// validateSSHDConfig runs `sshd -t` over the written configuration. Empty
// sshdBin ⇒ nothing to validate with (reported by the caller).
func validateSSHDConfig(sshdBin string) error {
	if sshdBin == "" {
		return nil
	}
	out, err := exec.Command(sshdBin, "-t").CombinedOutput() //nolint:gosec // resolved sshd binary
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// detectReloadCommand determines how the running sshd is told to re-read its
// configuration. The command is persisted in config.yaml, because the daemon
// needs it for every certificate renewal, not just for enrollment.
func detectReloadCommand(sshdBin string) string {
	if systemctl, err := exec.LookPath("systemctl"); err == nil {
		// Debian/Ubuntu name the unit ssh, RHEL/SUSE name it sshd; on
		// Debian sshd.service is an alias, so checking ssh first is safe.
		for _, unit := range []string{"ssh", "sshd"} {
			if systemdUnitLoaded(systemctl, unit) {
				return "systemctl reload " + unit
			}
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		if err := exec.Command("rc-service", "sshd", "status").Run(); err == nil {
			return "rc-service sshd reload"
		}
	}
	// Last resort, and the only option on a host without a service manager:
	// SIGHUP the listener directly (sshd re-execs itself and re-reads). The
	// path is interpolated into a shell command; it comes from sshd's own
	// effective configuration, i.e. from root-owned sshd_config on a host
	// where enrollment already runs as root — no privilege boundary is
	// crossed by trusting it.
	if pidFiles := effectiveSSHDConfig(sshdBin)["pidfile"]; len(pidFiles) > 0 {
		if _, err := os.Stat(pidFiles[0]); err == nil {
			return "kill -HUP $(cat " + pidFiles[0] + ")"
		}
	}
	return ""
}

// systemdUnitLoaded reports whether systemd knows the unit at all.
func systemdUnitLoaded(systemctl, unit string) bool {
	out, err := exec.Command(systemctl, "show", "--property=LoadState", "--value", unit+".service").Output() //nolint:gosec // fixed argv
	return err == nil && strings.TrimSpace(string(out)) == "loaded"
}

// runReloadCmd executes a reload command through the shell (the detected
// forms use $(…), and operators configure their own).
func runReloadCmd(command string) error {
	out, err := exec.Command("sh", "-c", command).CombinedOutput() //nolint:gosec // deliberately configurable
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// activateSSHD reloads the running daemon and verifies that the new
// configuration is really in memory. reloadCmd may be empty (nothing
// detected, or --no-reload); the verification runs either way, because a
// silently unreloaded daemon is exactly the failure this guards against.
func activateSSHD(sshdBin, sshDir, reloadCmd string, noReload bool, stdout io.Writer) error {
	switch {
	case noReload:
		fmt.Fprintln(stdout, "sshd reload skipped (--no-reload) — reload sshd yourself, otherwise the configuration stays inactive")
	case reloadCmd == "":
		fmt.Fprintln(stdout, "sshd reload: no reload command detected — set reload_command manually or pass --reload-command")
	default:
		if err := runReloadCmd(reloadCmd); err != nil {
			return fmt.Errorf("reloading sshd (%s) failed — the configuration is written but inactive: %w", reloadCmd, err)
		}
		fmt.Fprintf(stdout, "sshd reloaded: %s\n", reloadCmd)
	}
	return verifyRunningSSHD(sshdBin, sshDir, noReload || reloadCmd == "", stdout)
}

// verifyRunningSSHD asks the *running* daemon for its host key: with the
// snippet loaded it answers with the guided-ssh host certificate, without it
// with a plain key. This is the only check that distinguishes "on disk" from
// "in memory" — comparing the listener's start time would not, because sshd
// re-execs on SIGHUP and keeps its original start time.
//
// unreloaded marks the case where no reload was performed; a plain key is
// then expected and only reported.
func verifyRunningSSHD(sshdBin, sshDir string, unreloaded bool, stdout io.Writer) error {
	if sshdBin == "" {
		fmt.Fprintln(stdout, "sshd not found — configuration could neither be validated nor verified")
		return nil
	}
	addr := probeAddr(effectiveSSHDConfig(sshdBin))
	key, err := probeHostKey(addr)
	if err != nil {
		// Not running, listening elsewhere, or firewalled — inconclusive.
		fmt.Fprintf(stdout, "sshd not reachable at %s — could not verify the running daemon (%v)\n", addr, err)
		return nil
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		fmt.Fprintln(stdout, "verified: the running sshd serves the guided-ssh host certificate")
		return nil
	}
	if unreloaded {
		fmt.Fprintf(stdout, "note: the running sshd at %s still serves a plain host key — it has not read the new configuration yet\n", addr)
		return nil
	}
	return fmt.Errorf("the running sshd at %s still serves a plain host key (%s) — the reload did not take effect; "+
		"check that %s is included before any Match block, then reload sshd", addr, key.Type(), SnippetPath(sshDir))
}

// probeAddr is the loopback address of the first configured port.
func probeAddr(config map[string][]string) string {
	port := "22"
	if ports := config["port"]; len(ports) > 0 {
		port = ports[0]
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// probeHostKey performs an SSH handshake and aborts as soon as the host key
// is known — no authentication is attempted, nothing is sent that sshd would
// log as a failed login.
func probeHostKey(addr string) (ssh.PublicKey, error) {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return nil, err
	}
	var seen ssh.PublicKey
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              "gssh-probe",
		HostKeyAlgorithms: probeHostKeyAlgos,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errProbeDone
		},
		Timeout: probeTimeout,
	})
	if seen != nil {
		return seen, nil
	}
	return nil, err
}
