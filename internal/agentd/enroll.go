package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
		AgentURL:   opts.AgentURL,
		HostID:     response.HostID,
		HostName:   opts.Hostname,
		SSHKeyPath: opts.SSHKeyPath,
		SSHDir:     opts.SSHDir,
	}
	cfg.applyDefaults(paths)
	return writeConfig(paths, cfg)
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
	snippet := fmt.Sprintf(`# guided-ssh — generiert von gssh-agentd enroll, nicht manuell editieren.
# Voraussetzung: die Haupt-sshd_config enthält "Include %s/sshd_config.d/*.conf".
TrustedUserCAKeys %s
HostCertificate %s
AuthorizedPrincipalsCommand %s principals -state-dir %s -user %%u
AuthorizedPrincipalsCommandUser root
`, opts.SSHDir, UserCAPath(opts.SSHDir), certPath, binary, opts.StateDir)
	if err := os.WriteFile(SnippetPath(opts.SSHDir), []byte(snippet), 0o644); err != nil { //nolint:gosec // sshd-Konfiguration, muss für sshd lesbar sein
		return fmt.Errorf("sshd-snippet schreiben: %w", err)
	}
	return nil
}
