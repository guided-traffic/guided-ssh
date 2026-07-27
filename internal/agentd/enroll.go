package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// EnrollOptions control the enrollment.
type EnrollOptions struct {
	// ServerURL is the public API of the gssh server (POST /v1/enroll).
	ServerURL string
	// AgentURL is the mTLS agent API used for later operation.
	AgentURL string
	// Token is the one-time enrollment token.
	Token string
	// Hostname; empty = os.Hostname().
	Hostname string
	// Tags for the enrollment (token tags take precedence server-side).
	Tags map[string]string
	// PinSHA256 pins the TLS certificate of the enroll endpoint (base64 SPKI).
	PinSHA256 string
	// StateDir, SSHDir, SSHKeyPath: empty = defaults.
	StateDir   string
	SSHDir     string
	SSHKeyPath string
	// SessionAudit enables host session/sudo audit (phase 9, opt-in): writes
	// pam_exec hooks + sshd correlation, generates the socket token.
	SessionAudit bool
	// PAMDir is the PAM configuration directory (default /etc/pam.d); if
	// missing, the pam_exec hooks are skipped (tests/non-Linux).
	PAMDir string
	// ReloadCommand overrides the detected command that makes the running
	// sshd re-read its configuration; it is persisted in config.yaml and
	// reused for every certificate renewal.
	ReloadCommand string
	// NoReload leaves the reload to the operator (immutable images, config
	// management). The configuration stays inactive until they reload sshd.
	NoReload bool
	// sshdBinary overrides the sshd binary used for `sshd -t` and the probe
	// of the running daemon (test seam; empty = resolved from PATH).
	sshdBinary string
}

// enrollResponse mirrors the response of POST /v1/enroll (internal/api).
type enrollResponse struct {
	HostID          string `json:"host_id"`
	HostCertificate string `json:"host_certificate"`
	UserCABundle    string `json:"user_ca_bundle"`
	MTLSCertificate string `json:"mtls_certificate"`
	MTLSCA          string `json:"mtls_ca"`
}

// Enroll registers the host: generates the mTLS key + CSR, exchanges the
// token for a host certificate and an mTLS client certificate, and writes
// the state directory and sshd configuration. Idempotent — a repeated
// enrollment (new token) overwrites the files.
func Enroll(ctx context.Context, opts EnrollOptions, stdout io.Writer) error {
	if opts.ServerURL == "" || opts.Token == "" || opts.AgentURL == "" {
		return fmt.Errorf("server-url, agent-url, and token are required")
	}
	if err := opts.applyDefaults(); err != nil {
		return err
	}

	// Preflight before the network call: without the Include the snippet is
	// written but never read, and a failure here leaves the token unused.
	if err := verifyInclude(opts.SSHDir); err != nil {
		return err
	}

	sshPub, err := os.ReadFile(opts.SSHKeyPath)
	if err != nil {
		return fmt.Errorf("reading ssh-host-key (is sshd installed? run ssh-keygen -A): %w", err)
	}

	// Ephemeral mTLS key + CSR; the server assigns the identity (CN).
	priv, csrPEM, err := newMTLSKeyAndCSR()
	if err != nil {
		return err
	}

	response, err := postEnroll(ctx, opts, strings.TrimSpace(string(sshPub)), string(csrPEM))
	if err != nil {
		return err
	}
	return writeAndActivate(opts, priv, response, stdout)
}

// applyDefaults fills the optional paths and the hostname.
func (o *EnrollOptions) applyDefaults() error {
	if o.StateDir == "" {
		o.StateDir = DefaultStateDir
	}
	if o.SSHDir == "" {
		o.SSHDir = DefaultSSHDir
	}
	if o.SSHKeyPath == "" {
		o.SSHKeyPath = filepath.Join(o.SSHDir, "ssh_host_ed25519_key.pub")
	}
	if o.PAMDir == "" {
		o.PAMDir = DefaultPAMDir
	}
	if o.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("determining hostname: %w", err)
		}
		o.Hostname = hostname
	}
	return nil
}

// writeAndActivate persists the enrollment result and makes it effective:
// writing the files is only half the job, a running sshd keeps serving the
// configuration it parsed at startup until it is reloaded.
func writeAndActivate(opts EnrollOptions, priv ed25519.PrivateKey, response *enrollResponse, stdout io.Writer) error {
	sshdBin := resolveSSHD(opts.sshdBinary)
	reloadCmd := opts.ReloadCommand
	if reloadCmd == "" && !opts.NoReload {
		reloadCmd = detectReloadCommand(sshdBin)
	}
	if reloadCmd == "" {
		// Never drop a command a previous enrollment found: re-enrolling on
		// a host whose init system we no longer detect would otherwise stop
		// renewals from reaching sshd — silently, one certificate later.
		reloadCmd = previousReloadCommand(opts.StateDir)
	}

	if err := writeState(opts, priv, response, reloadCmd); err != nil {
		return err
	}
	previous, hadPrevious := readSnippet(opts.SSHDir)
	if err := writeSSHDFiles(opts, response); err != nil {
		return err
	}
	// A written but invalid configuration would take sshd down on its next
	// restart — roll the snippet back instead of leaving that behind.
	if err := validateSSHDConfig(sshdBin); err != nil {
		restoreSnippet(opts.SSHDir, previous, hadPrevious)
		return fmt.Errorf("sshd rejected the generated configuration (rolled back %s): %w", SnippetPath(opts.SSHDir), err)
	}

	fmt.Fprintf(stdout, "enrolled: %s (host-id %s)\n", opts.Hostname, response.HostID)
	fmt.Fprintf(stdout, "sshd snippet: %s\n", SnippetPath(opts.SSHDir))
	return activateSSHD(sshdBin, opts.SSHDir, reloadCmd, opts.NoReload, stdout)
}

// readSnippet returns the current snippet so an invalid new one can be rolled
// back; hadPrevious is false when no snippet existed yet.
func readSnippet(sshDir string) (content []byte, hadPrevious bool) {
	raw, err := os.ReadFile(SnippetPath(sshDir))
	if err != nil {
		return nil, false
	}
	return raw, true
}

// restoreSnippet undoes the snippet write (best effort — the error path is
// already reported by the caller).
func restoreSnippet(sshDir string, previous []byte, hadPrevious bool) {
	if !hadPrevious {
		_ = os.Remove(SnippetPath(sshDir))
		return
	}
	_ = os.WriteFile(SnippetPath(sshDir), previous, 0o644) //nolint:gosec // sshd configuration, must be readable by sshd
}

// newMTLSKeyAndCSR generates a fresh Ed25519 key pair and an empty CSR for
// it (enrollment and rotation; the server sets the identity).
func newMTLSKeyAndCSR() (ed25519.PrivateKey, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating mtls key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("generating csr: %w", err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// postEnroll calls POST /v1/enroll (optionally with SPKI pinning).
func postEnroll(ctx context.Context, opts EnrollOptions, sshPub, csrPEM string) (*enrollResponse, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	if opts.PinSHA256 != "" {
		pin, err := pintls.DecodePin(opts.PinSHA256)
		if err != nil {
			return nil, err
		}
		client.Transport = pintls.Transport(pin)
	}
	body, err := json.Marshal(map[string]any{
		"token":          opts.Token,
		"hostname":       opts.Hostname,
		"ssh_public_key": sshPub,
		"mtls_csr":       csrPEM,
		"tags":           opts.Tags,
	})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(opts.ServerURL, "/") + "/v1/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching enroll endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("enrollment rejected: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var response enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decoding enroll response: %w", err)
	}
	if response.HostID == "" || response.MTLSCertificate == "" || response.HostCertificate == "" {
		return nil, fmt.Errorf("enroll response incomplete")
	}
	return &response, nil
}

// writeState writes the mTLS material and agent configuration into the
// state directory (0700; keys 0600). reloadCmd is persisted so the daemon
// can activate renewed host certificates unattended.
func writeState(opts EnrollOptions, priv ed25519.PrivateKey, response *enrollResponse, reloadCmd string) error {
	paths := Paths{StateDir: opts.StateDir}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{paths.AgentKeyFile(), keyPEM, 0o600},
		{paths.AgentCertFile(), []byte(response.MTLSCertificate), 0o644},
		{paths.ServerCAFile(), []byte(response.MTLSCA), 0o644},
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}
	}
	cfg := &Config{
		AgentURL:      opts.AgentURL,
		HostID:        response.HostID,
		HostName:      opts.Hostname,
		SSHKeyPath:    opts.SSHKeyPath,
		SSHDir:        opts.SSHDir,
		ReloadCommand: reloadCmd,
		SessionAudit:  opts.SessionAudit,
	}
	cfg.applyDefaults(paths)
	if opts.SessionAudit {
		if err := writeSocketToken(paths); err != nil {
			return err
		}
	}
	return writeConfig(paths, cfg)
}

// writeSocketToken generates the token for the writable socket endpoints
// (phase 9), unless one already exists (idempotent re-enrollment). 0600 →
// root only.
func writeSocketToken(paths Paths) error {
	if _, err := os.Stat(paths.SocketTokenFile()); err == nil {
		return nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("generating socket token: %w", err)
	}
	return os.WriteFile(paths.SocketTokenFile(), []byte(hex.EncodeToString(buf)), 0o600)
}

// writeSSHDFiles writes the host certificate, the TrustedUserCAKeys bundle,
// and the sshd configuration snippet (idempotent).
func writeSSHDFiles(opts EnrollOptions, response *enrollResponse) error {
	certPath := HostCertPath(opts.SSHKeyPath)
	if err := os.WriteFile(certPath, []byte(response.HostCertificate+"\n"), 0o644); err != nil { //nolint:gosec // public certificate, sshd must read it
		return fmt.Errorf("writing host certificate: %w", err)
	}
	if err := os.WriteFile(UserCAPath(opts.SSHDir), []byte(response.UserCABundle), 0o644); err != nil { //nolint:gosec // public ca keys
		return fmt.Errorf("writing user ca bundle: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(SnippetPath(opts.SSHDir)), 0o755); err != nil { //nolint:gosec // standard sshd directory
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		binary = "gssh-agentd"
	}
	// With session audit enabled, sshd hands the principals helper the
	// certificate's serial (%s) and key id (%i), and LogLevel VERBOSE logs
	// the serial (ADR-005 tier 2). Without audit, the snippet stays as in
	// phase 5.
	principalsArgs := "-user %u"
	logLevel := ""
	if opts.SessionAudit {
		principalsArgs = "-user %u -serial %s -keyid %i"
		logLevel = "LogLevel VERBOSE\n"
	}
	snippet := fmt.Sprintf(`# guided-ssh — generated by gssh-agentd enroll, do not edit manually.
# Requires the main sshd_config to contain "Include %s/sshd_config.d/*.conf".
TrustedUserCAKeys %s
HostCertificate %s
%sAuthorizedPrincipalsCommand %s principals -state-dir %s %s
AuthorizedPrincipalsCommandUser root
`, opts.SSHDir, UserCAPath(opts.SSHDir), certPath, logLevel, binary, opts.StateDir, principalsArgs)
	if err := os.WriteFile(SnippetPath(opts.SSHDir), []byte(snippet), 0o644); err != nil { //nolint:gosec // sshd configuration, must be readable by sshd
		return fmt.Errorf("writing sshd snippet: %w", err)
	}
	if opts.SessionAudit {
		if err := writePAMFiles(opts, binary); err != nil {
			return err
		}
	}
	return nil
}

// pamManagedMarker marks the pam_exec line managed by guided-ssh.
const pamManagedMarker = "# guided-ssh session audit (managed)"

// writePAMFiles idempotently appends a pam_exec hook to the PAM stacks of
// sshd and sudo (session open/close → gssh-agentd pam-session). `optional`
// + helper exit 0 ⇒ fail-open. If the PAM directory is missing
// (tests/non-Linux), this is skipped. Existing lines are left untouched.
func writePAMFiles(opts EnrollOptions, binary string) error {
	if info, err := os.Stat(opts.PAMDir); err != nil || !info.IsDir() {
		return nil //nolint:nilerr // no PAM stack (e.g. non-Linux) — deliberately skipped
	}
	line := fmt.Sprintf("%s\nsession optional pam_exec.so quiet %s pam-session -state-dir %s\n",
		pamManagedMarker, binary, opts.StateDir)
	for _, service := range []string{"sshd", "sudo"} {
		if err := ensurePAMLine(filepath.Join(opts.PAMDir, service), line); err != nil {
			return fmt.Errorf("pam hook %s: %w", service, err)
		}
	}
	return nil
}

// ensurePAMLine appends the hook if the file exists and does not yet
// contain the marker. Missing service files are skipped (not every host has
// /etc/pam.d/sudo).
func ensurePAMLine(path, line string) error {
	existing, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.Contains(string(existing), pamManagedMarker) {
		return nil
	}
	body := existing
	if len(body) > 0 && body[len(body)-1] != '\n' {
		body = append(body, '\n')
	}
	return os.WriteFile(path, append(body, []byte(line)...), 0o644) //nolint:gosec // PAM configuration, must be readable
}
