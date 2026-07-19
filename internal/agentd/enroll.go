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

// EnrollOptions steuern das Enrollment.
type EnrollOptions struct {
	// ServerURL ist die öffentliche API des gssh-servers (POST /v1/enroll).
	ServerURL string
	// AgentURL ist die mTLS-Agent-API für den späteren Betrieb.
	AgentURL string
	// Token ist das einmalige Enrollment-Token.
	Token string
	// Hostname; leer = os.Hostname().
	Hostname string
	// Tags aus dem Enrollment (Token-Tags haben serverseitig Vorrang).
	Tags map[string]string
	// PinSHA256 pinnt das TLS-Zertifikat des Enroll-Endpoints (Base64-SPKI).
	PinSHA256 string
	// StateDir, SSHDir, SSHKeyPath: leer = Defaults.
	StateDir   string
	SSHDir     string
	SSHKeyPath string
	// SessionAudit aktiviert das Host-Session-/sudo-Audit (Phase 9, Opt-in):
	// schreibt pam_exec-Hooks + sshd-Korrelation, erzeugt das Socket-Token.
	SessionAudit bool
	// PAMDir ist das PAM-Konfigurationsverzeichnis (Default /etc/pam.d); fehlt
	// es, werden die pam_exec-Hooks übersprungen (Tests/nicht-Linux).
	PAMDir string
}

// enrollResponse spiegelt die Antwort von POST /v1/enroll (internal/api).
type enrollResponse struct {
	HostID          string `json:"host_id"`
	HostCertificate string `json:"host_certificate"`
	UserCABundle    string `json:"user_ca_bundle"`
	MTLSCertificate string `json:"mtls_certificate"`
	MTLSCA          string `json:"mtls_ca"`
}

// Enroll registriert den Host: mTLS-Schlüssel + CSR erzeugen, Token gegen
// Host-Zertifikat und mTLS-Client-Zertifikat tauschen, State-Verzeichnis und
// sshd-Konfiguration schreiben. Idempotent — ein erneutes Enrollment (neues
// Token) überschreibt die Dateien.
func Enroll(ctx context.Context, opts EnrollOptions, stdout io.Writer) error {
	if opts.ServerURL == "" || opts.Token == "" || opts.AgentURL == "" {
		return fmt.Errorf("server-url, agent-url und token sind pflicht")
	}
	if opts.StateDir == "" {
		opts.StateDir = DefaultStateDir
	}
	if opts.SSHDir == "" {
		opts.SSHDir = DefaultSSHDir
	}
	if opts.SSHKeyPath == "" {
		opts.SSHKeyPath = filepath.Join(opts.SSHDir, "ssh_host_ed25519_key.pub")
	}
	if opts.PAMDir == "" {
		opts.PAMDir = DefaultPAMDir
	}
	if opts.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("hostname ermitteln: %w", err)
		}
		opts.Hostname = hostname
	}

	sshPub, err := os.ReadFile(opts.SSHKeyPath)
	if err != nil {
		return fmt.Errorf("ssh-host-key lesen (sshd installiert? ssh-keygen -A): %w", err)
	}

	// Ephemeraler mTLS-Schlüssel + CSR; die Identität (CN) vergibt der Server.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("mtls-schlüssel erzeugen: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		return fmt.Errorf("csr erzeugen: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	response, err := postEnroll(ctx, opts, strings.TrimSpace(string(sshPub)), string(csrPEM))
	if err != nil {
		return err
	}

	if err := writeState(opts, priv, response); err != nil {
		return err
	}
	if err := writeSSHDFiles(opts, response); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "enrolled: %s (host-id %s)\n", opts.Hostname, response.HostID)
	fmt.Fprintf(stdout, "sshd-snippet: %s — Include prüfen und sshd neu laden\n", SnippetPath(opts.SSHDir))
	return nil
}

// postEnroll ruft POST /v1/enroll auf (optional mit SPKI-Pinning).
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
		return nil, fmt.Errorf("enroll-endpoint erreichen: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("enrollment abgelehnt: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var response enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("enroll-antwort dekodieren: %w", err)
	}
	if response.HostID == "" || response.MTLSCertificate == "" || response.HostCertificate == "" {
		return nil, fmt.Errorf("enroll-antwort unvollständig")
	}
	return &response, nil
}

// writeState schreibt mTLS-Material und Agent-Konfiguration ins
// State-Verzeichnis (0700; Schlüssel 0600).
func writeState(opts EnrollOptions, priv ed25519.PrivateKey, response *enrollResponse) error {
	paths := Paths{StateDir: opts.StateDir}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return fmt.Errorf("state-verzeichnis anlegen: %w", err)
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
			return fmt.Errorf("%s schreiben: %w", f.path, err)
		}
	}
	cfg := &Config{
		AgentURL:     opts.AgentURL,
		HostID:       response.HostID,
		HostName:     opts.Hostname,
		SSHKeyPath:   opts.SSHKeyPath,
		SSHDir:       opts.SSHDir,
		SessionAudit: opts.SessionAudit,
	}
	cfg.applyDefaults(paths)
	if opts.SessionAudit {
		if err := writeSocketToken(paths); err != nil {
			return err
		}
	}
	return writeConfig(paths, cfg)
}

// writeSocketToken erzeugt das Token der schreibenden Socket-Endpunkte (Phase 9),
// sofern noch keins existiert (idempotentes Re-Enrollment). 0600 → nur root.
func writeSocketToken(paths Paths) error {
	if _, err := os.Stat(paths.SocketTokenFile()); err == nil {
		return nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("socket-token erzeugen: %w", err)
	}
	return os.WriteFile(paths.SocketTokenFile(), []byte(hex.EncodeToString(buf)), 0o600)
}

// writeSSHDFiles schreibt Host-Zertifikat, TrustedUserCAKeys-Bundle und den
// sshd-Konfigurations-Schnipsel (idempotent).
func writeSSHDFiles(opts EnrollOptions, response *enrollResponse) error {
	certPath := HostCertPath(opts.SSHKeyPath)
	if err := os.WriteFile(certPath, []byte(response.HostCertificate+"\n"), 0o644); err != nil { //nolint:gosec // öffentliches Zertifikat, sshd muss lesen
		return fmt.Errorf("host-zertifikat schreiben: %w", err)
	}
	if err := os.WriteFile(UserCAPath(opts.SSHDir), []byte(response.UserCABundle), 0o644); err != nil { //nolint:gosec // öffentliche CA-Keys
		return fmt.Errorf("user-ca-bundle schreiben: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(SnippetPath(opts.SSHDir)), 0o755); err != nil { //nolint:gosec // sshd-Standardverzeichnis
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		binary = "gssh-agentd"
	}
	// Bei aktivem Session-Audit reicht sshd dem Principals-Helfer Serial (%s) und
	// Key-ID (%i) des Zertifikats, und LogLevel VERBOSE loggt den Serial (ADR-005
	// Stufe 2). Ohne Audit bleibt das Snippet wie in Phase 5.
	principalsArgs := "-user %u"
	logLevel := ""
	if opts.SessionAudit {
		principalsArgs = "-user %u -serial %s -keyid %i"
		logLevel = "LogLevel VERBOSE\n"
	}
	snippet := fmt.Sprintf(`# guided-ssh — generiert von gssh-agentd enroll, nicht manuell editieren.
# Voraussetzung: die Haupt-sshd_config enthält "Include %s/sshd_config.d/*.conf".
TrustedUserCAKeys %s
HostCertificate %s
%sAuthorizedPrincipalsCommand %s principals -state-dir %s %s
AuthorizedPrincipalsCommandUser root
`, opts.SSHDir, UserCAPath(opts.SSHDir), certPath, logLevel, binary, opts.StateDir, principalsArgs)
	if err := os.WriteFile(SnippetPath(opts.SSHDir), []byte(snippet), 0o644); err != nil { //nolint:gosec // sshd-Konfiguration, muss für sshd lesbar sein
		return fmt.Errorf("sshd-snippet schreiben: %w", err)
	}
	if opts.SessionAudit {
		if err := writePAMFiles(opts, binary); err != nil {
			return err
		}
	}
	return nil
}

// pamManagedMarker kennzeichnet die von guided-ssh verwaltete pam_exec-Zeile.
const pamManagedMarker = "# guided-ssh session audit (managed)"

// writePAMFiles hängt idempotent einen pam_exec-Hook an die PAM-Stacks von sshd
// und sudo an (session open/close → gssh-agentd pam-session). `optional` +
// Helfer-Exit 0 ⇒ fail-open. Fehlt das PAM-Verzeichnis (Tests/nicht-Linux), wird
// übersprungen. Bestehende Zeilen bleiben unangetastet.
func writePAMFiles(opts EnrollOptions, binary string) error {
	if info, err := os.Stat(opts.PAMDir); err != nil || !info.IsDir() {
		return nil //nolint:nilerr // kein PAM-Stack (z. B. nicht-Linux) — bewusst überspringen
	}
	line := fmt.Sprintf("%s\nsession optional pam_exec.so quiet %s pam-session -state-dir %s\n",
		pamManagedMarker, binary, opts.StateDir)
	for _, service := range []string{"sshd", "sudo"} {
		if err := ensurePAMLine(filepath.Join(opts.PAMDir, service), line); err != nil {
			return fmt.Errorf("pam-hook %s: %w", service, err)
		}
	}
	return nil
}

// ensurePAMLine hängt den Hook an, falls die Datei existiert und den Marker noch
// nicht enthält. Nicht vorhandene Service-Dateien werden übersprungen (nicht jeder
// Host hat /etc/pam.d/sudo).
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
	return os.WriteFile(path, append(body, []byte(line)...), 0o644) //nolint:gosec // PAM-Konfiguration, muss lesbar sein
}
