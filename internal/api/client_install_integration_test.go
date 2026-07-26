//go:build integration

// Phase E smoke test of the frontend client install: pull the templated
// client.sh via curl in a workstation container, run it as a non-root user →
// binary download + SHA-256 check → ~/.local/bin/gssh + config.yaml →
// working `gssh version`/`gssh status`. No database and no store: the client
// routes need only the embedded binaries, an https public URL, and the OIDC
// values (see clients.go).
package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/clientdist"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// clientHostInternal is the DNS name under which the container reaches the
// test host (testcontainers WithHostPortAccess).
const clientHostInternal = "host.testcontainers.internal"

// OIDC values the script must template verbatim into the written config.yaml.
const (
	clientTestIssuer   = "https://idp.test/realms/gssh"
	clientTestClientID = "gssh-cli"
)

func TestClientInstallScriptEndToEnd(t *testing.T) {
	ctx := context.Background()

	// ── Provide the client binary under the embed name ────────────────────
	// The embed is empty at test time (bin/ only contains .gitkeep) — that is
	// exactly what clientdist.NewFromFS exists for.
	distDir := t.TempDir()
	buildClientBinary(t, filepath.Join(distDir, "gssh-linux-"+runtime.GOARCH))

	// ── Public API over TLS (the client gate requires https) ──────────────
	publicListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	publicPort := publicListener.Addr().(*net.TCPAddr).Port
	publicBaseURL := fmt.Sprintf("https://%s:%d", clientHostInternal, publicPort)
	tlsCert, leaf := clientSelfSignedCert(t, clientHostInternal)

	logger := slog.New(slog.NewTextHandler(t.Output(), nil))
	publicServer := &http.Server{
		Handler: api.New(api.Deps{
			Logger:        logger,
			Clients:       clientdist.NewFromFS(os.DirFS(distDir)),
			PublicBaseURL: publicBaseURL,
			UIConfig:      api.UIConfig{OIDCIssuer: clientTestIssuer, OIDCClientID: clientTestClientID},
		}),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{tlsCert},
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = publicServer.ServeTLS(publicListener, "", "") }()
	t.Cleanup(func() { _ = publicServer.Close() })

	// ── Workstation container ─────────────────────────────────────────────
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{Context: "testdata/clientinstall"},
			WaitingFor:     wait.ForLog("workstation ready"),
		},
		Started: true,
	}
	if err := testcontainers.WithHostPortAccess(publicPort).Customize(&req); err != nil {
		t.Fatal(err)
	}
	ctr, err := testcontainers.GenericContainer(ctx, req)
	if ctr != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(ctr) })
	}
	if err != nil {
		t.Fatalf("workstation container: %v", err)
	}

	// Add the test certificate to the trust store: curl in the script checks
	// TLS normally (the generated config is WebPKI-based, no pin).
	certPath := filepath.Join(t.TempDir(), "gssh-test-ca.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ctr.CopyFileToContainer(ctx, certPath, "/usr/local/share/ca-certificates/gssh-test-ca.crt", 0o644); err != nil {
		t.Fatalf("copying test ca: %v", err)
	}
	assertClientCmd(t, ctr, []string{"update-ca-certificates"}, "update-ca-certificates")

	// Exactly the UI's one-liner (Client setup page / connect dialog).
	install := fmt.Sprintf("curl -fsSL %s/client.sh | sh", publicBaseURL)

	// ── Run as root: abort before any download or write (iron rule 1) ─────
	code, raw := execClientCmd(t, ctr, []string{"sh", "-c", install})
	if code == 0 {
		t.Fatalf("client.sh as root must fail:\n%s", raw)
	}
	if !strings.Contains(raw, "not as root/sudo") {
		t.Errorf("root refusal without explanation:\n%s", raw)
	}
	assertClientCmd(t, ctr,
		[]string{"sh", "-c", "test ! -e /root/.local/bin/gssh && test ! -e /root/.config/guided-ssh"},
		"root run left files behind")

	// ── First run as the non-root user ────────────────────────────────────
	code, raw = execClientCmd(t, ctr, []string{"su", "-l", "alice", "-c", install})
	if code != 0 {
		t.Fatalf("client.sh exit %d:\n%s", code, raw)
	}
	if !strings.Contains(raw, "configuration written") {
		t.Errorf("first run without 'configuration written':\n%s", raw)
	}
	t.Logf("client.sh:\n%s", raw)

	binPath := "/home/alice/.local/bin/gssh"
	configPath := "/home/alice/.config/guided-ssh/config.yaml"
	assertClientCmd(t, ctr, []string{"test", "-x", binPath}, "binary not installed")

	// The embedded binary and the test process share the default build values
	// (both are plain `go build`s without -ldflags) — version.String() of the
	// test process is the expected banner.
	code, raw = execClientCmd(t, ctr, []string{"su", "-l", "alice", "-c", binPath + " version"})
	if code != 0 || !strings.Contains(raw, version.String()) {
		t.Errorf("gssh version (exit %d) = %q, want %q", code, raw, version.String())
	}

	// config.yaml: all three required fields, no pin line (WebPKI default,
	// --pin was not passed), mode 0600.
	_, raw = execClientCmd(t, ctr, []string{"cat", configPath})
	for _, want := range []string{
		fmt.Sprintf("api_url: %q", publicBaseURL),
		fmt.Sprintf("issuer: %q", clientTestIssuer),
		fmt.Sprintf("client_id: %q", clientTestClientID),
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("config.yaml is missing %s:\n%s", want, raw)
		}
	}
	if strings.Contains(raw, "pin_sha256") {
		t.Errorf("config.yaml contains a pin without --pin:\n%s", raw)
	}
	if mode := containerFileMode(t, ctr, configPath); mode != "600" {
		t.Errorf("config.yaml mode = %s, want 600", mode)
	}

	// gssh status: exit 1 is correct — the config loads (it prints the
	// configured API URL) but there is no ssh-agent, let alone a certificate.
	code, raw = execClientCmd(t, ctr, []string{"su", "-l", "alice", "-c", binPath + " status"})
	if code != 1 {
		t.Errorf("gssh status exit %d, want 1 (no certificate):\n%s", code, raw)
	}
	if !strings.Contains(raw, publicBaseURL) {
		t.Errorf("gssh status does not print the configured api url:\n%s", raw)
	}

	// ── Second run: config kept (iron rule 2), binary still replaced ──────
	assertClientCmd(t, ctr, []string{"sh", "-c", "echo broken > " + binPath}, "corrupting binary for the re-run")
	code, raw = execClientCmd(t, ctr, []string{"su", "-l", "alice", "-c", install})
	if code != 0 {
		t.Fatalf("client.sh re-run exit %d:\n%s", code, raw)
	}
	if !strings.Contains(raw, "existing configuration kept") {
		t.Errorf("re-run without 'existing configuration kept':\n%s", raw)
	}
	// The corrupted binary works again ⇒ the re-run replaced it.
	code, raw = execClientCmd(t, ctr, []string{"su", "-l", "alice", "-c", binPath + " version"})
	if code != 0 || !strings.Contains(raw, version.String()) {
		t.Errorf("gssh version after re-run (exit %d) = %q, want %q", code, raw, version.String())
	}
	_, raw = execClientCmd(t, ctr, []string{"cat", configPath})
	if !strings.Contains(raw, fmt.Sprintf("api_url: %q", publicBaseURL)) {
		t.Errorf("config.yaml changed by the re-run:\n%s", raw)
	}
}

// buildClientBinary builds gssh for linux/<runner-arch> under the given
// embed-conform path (gssh-linux-<arch>).
func buildClientBinary(t *testing.T, out string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, "github.com/guided-traffic/guided-ssh/cmd/gssh")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building gssh: %v\n%s", err, output)
	}
}

// execClientCmd runs a command in the container and returns exit code and
// combined output (the exec stream's 8-byte multiplex headers stay in the
// string — they contain no printable characters, Contains checks are safe).
func execClientCmd(t *testing.T, ctr testcontainers.Container, cmd []string) (int, string) {
	t.Helper()
	code, output, err := ctr.Exec(context.Background(), cmd)
	if err != nil {
		t.Fatalf("exec %v: %v", cmd, err)
	}
	raw, _ := io.ReadAll(output)
	return code, string(raw)
}

// assertClientCmd runs a command in the container and expects exit 0.
func assertClientCmd(t *testing.T, ctr testcontainers.Container, cmd []string, msg string) {
	t.Helper()
	if code, raw := execClientCmd(t, ctr, cmd); code != 0 {
		t.Fatalf("%s (exit %d): %s", msg, code, raw)
	}
}

// containerFileMode returns the octal permission bits of a file, stripped of
// the exec stream's multiplex headers.
func containerFileMode(t *testing.T, ctr testcontainers.Container, path string) string {
	t.Helper()
	code, raw := execClientCmd(t, ctr, []string{"stat", "-c", "%a", path})
	if code != 0 {
		t.Fatalf("stat %s (exit %d): %s", path, code, raw)
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, raw))
}

// clientSelfSignedCert builds a self-signed certificate for the public
// listener; IsCA so the same certificate suffices for the container's curl
// trust store.
func clientSelfSignedCert(t *testing.T, dnsName string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{dnsName, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}
