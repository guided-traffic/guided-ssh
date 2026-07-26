//go:build integration

// Phase E smoke test of the one-command host install: mint a token (admin
// API) → pull the templated install.sh via curl in the container → binary
// download + SHA-256 check → enrollment with a required pin → running agent.
//
// The systemctl branch is deliberately left untested (--no-systemd): the
// fixture has no systemd, a systemd container in CI would be privileged and
// flaky, and a systemctl stub would only fake the behavior (see the README
// security section).
package agentd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/pintls"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// adminGroup is the IdP group the test verifier grants to the mint caller.
const adminGroup = "gssh-admins"

// adminBearer is the bearer token that staticVerifier maps to admin claims.
const adminBearer = "e2e-admin-token"

// staticVerifier maps exactly one bearer token to admin claims; the OIDC
// verification itself is not the subject of this test.
type staticVerifier struct{}

func (staticVerifier) Verify(_ context.Context, rawToken string) (*auth.Claims, error) {
	if rawToken != adminBearer {
		return nil, fmt.Errorf("%w: unknown token", auth.ErrInvalidToken)
	}
	return &auth.Claims{
		Issuer: "https://idp.test/realms/gssh", Subject: "e2e-admin",
		Email: "admin@example.com", PreferredUsername: "admin",
		Groups: []string{adminGroup},
	}, nil
}

func TestInstallScriptEndToEnd(t *testing.T) {
	ctx := context.Background()

	// ── Postgres + store + CA ────────────────────────────────────────────
	pgCtr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("guidedssh"),
		tcpostgres.WithUsername("guidedssh"),
		tcpostgres.WithPassword("guidedssh"),
		tcpostgres.BasicWaitStrategies(),
	)
	if pgCtr != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(pgCtr) })
	}
	if err != nil {
		t.Fatalf("postgres container: %v", err)
	}
	dsn, err := pgCtr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	st, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	masterKey := make([]byte, ca.MasterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	certAuthority, err := ca.New(st, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatal(err)
	}
	if err := certAuthority.EnsureCAKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if err := certAuthority.EnsureMTLSCA(ctx); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), nil))

	// ── Provide the agent binary under the embed name ────────────────────
	// The embed is empty at test time (bin/ only contains .gitkeep) — that
	// is exactly what agentdist.NewFromFS exists for.
	distDir := t.TempDir()
	if err := os.Link(buildAgentBinary(t), filepath.Join(distDir, "gssh-agentd-linux-"+runtime.GOARCH)); err != nil {
		t.Fatalf("providing agent binary: %v", err)
	}

	// ── Public API over TLS (the pin applies to /v1/enroll) ───────────────
	publicListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	publicPort := publicListener.Addr().(*net.TCPAddr).Port
	publicBaseURL := fmt.Sprintf("https://%s:%d", hostInternal, publicPort)

	tlsCert, leaf := selfSignedCert(t, hostInternal)
	// Static pin source from the same certificate the listener presents —
	// dogfoods pintls.FromCertificate (P1).
	pin := pintls.FromCertificate(leaf)

	agentListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	agentPort := agentListener.Addr().(*net.TCPAddr).Port
	agentPublicURL := fmt.Sprintf("https://%s:%d", hostInternal, agentPort)

	publicServer := &http.Server{
		Handler: api.New(api.Deps{
			CA: certAuthority, Store: st, Hosts: st, Grants: st, Admin: st, UI: st,
			Verifier: staticVerifier{}, Logger: logger, AdminGroup: adminGroup,
			Agents:         agentdist.NewFromFS(os.DirFS(distDir)),
			Pins:           api.NewPinProvider(api.PinProviderConfig{StaticPin: pin}, logger),
			AgentPublicURL: agentPublicURL,
			PublicBaseURL:  publicBaseURL,
		}),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{tlsCert},
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = publicServer.ServeTLS(publicListener, "", "") }()
	t.Cleanup(func() { _ = publicServer.Close() })

	// ── Agent API (mTLS) — target of the enrolled config.yaml ────────────
	serverCert, err := certAuthority.IssueServerCert(ctx, []string{hostInternal, "localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := certAuthority.MTLSCAPool(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agentServer := &http.Server{
		Handler: api.NewAgent(api.AgentDeps{CA: certAuthority, Hosts: st, Logger: logger}),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = agentServer.ServeTLS(agentListener, "", "") }()
	t.Cleanup(func() { _ = agentServer.Close() })

	// ── Mint a token via the admin API (C2) ───────────────────────────────
	token, installCommand := mintEnrollToken(t, publicPort, pin, map[string]any{
		"tags": map[string]string{"env": "prod"}, "ttl_seconds": 600,
	})
	if !strings.Contains(installCommand, publicBaseURL+"/install.sh") || !strings.Contains(installCommand, token) {
		t.Fatalf("unexpected install_command: %q", installCommand)
	}

	// ── sshd fixture: pull and run the script ─────────────────────────────
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{Context: "testdata/sshd"},
			ExposedPorts:   []string{"22/tcp"},
			WaitingFor:     wait.ForLog("entrypoint ready"),
		},
		Started: true,
	}
	if err := testcontainers.WithHostPortAccess(publicPort, agentPort).Customize(&req); err != nil {
		t.Fatal(err)
	}
	ctr, err := testcontainers.GenericContainer(ctx, req)
	if ctr != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(ctr) })
	}
	if err != nil {
		t.Fatalf("sshd container: %v", err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		if logs, logErr := ctr.Logs(context.Background()); logErr == nil {
			raw, _ := io.ReadAll(logs)
			t.Logf("container logs:\n%s", raw)
		}
	})

	// Add the test certificate to the trust store: curl in the script checks
	// TLS normally (the pin only applies to the agent's enroll call).
	certPath := filepath.Join(t.TempDir(), "gssh-test-ca.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ctr.CopyFileToContainer(ctx, certPath, "/usr/local/share/ca-certificates/gssh-test-ca.crt", 0o644); err != nil {
		t.Fatalf("copying test ca: %v", err)
	}
	if code, output, err := ctr.Exec(ctx, []string{"update-ca-certificates"}); err != nil || code != 0 {
		raw, _ := io.ReadAll(output)
		t.Fatalf("update-ca-certificates: exit %d, %v: %s", code, err, raw)
	}

	// Exactly the UI command, just without sudo (root is active in the
	// container) and with --no-systemd (the fixture has no systemd).
	script := fmt.Sprintf("curl -fsSL %s/install.sh | sh -s -- --token %s --no-systemd", publicBaseURL, token)
	code, output, err := ctr.Exec(ctx, []string{"sh", "-c", script})
	if err != nil {
		t.Fatalf("install.sh exec: %v", err)
	}
	raw, _ := io.ReadAll(output)
	if code != 0 {
		t.Fatalf("install.sh exit %d:\n%s", code, raw)
	}
	t.Logf("install.sh:\n%s", raw)

	// ── Result on the host ─────────────────────────────────────────────────
	// Binary installed, config.yaml written; the fixture entrypoint then
	// starts the agent — the socket is the same readiness signal the
	// systemd branch of the script waits for.
	assertContainerCmd(t, ctr, []string{"test", "-x", "/usr/bin/gssh-agentd"}, "binary not installed")
	assertContainerCmd(t, ctr, []string{"test", "-f", "/var/lib/guided-ssh/config.yaml"}, "config.yaml missing")
	waitForContainerCmd(t, ctr, []string{"test", "-S", "/var/lib/guided-ssh/agentd.sock"}, 30*time.Second,
		"agentd.sock did not appear — agent did not start")

	// ── Host in the database ──────────────────────────────────────────────
	hostname := containerHostname(t, ctr)
	host, err := st.GetHostByName(ctx, hostname)
	if err != nil {
		t.Fatalf("host %q not registered: %v", hostname, err)
	}
	tags, err := st.GetHostTags(ctx, host.ID)
	if err != nil || tags["env"] != "prod" {
		t.Fatalf("host tags: %v %v", tags, err)
	}

	// Single use: the same line a second time fails at enroll — with an
	// existing config.yaml the script deliberately continues in degraded mode.
	code, output, err = ctr.Exec(ctx, []string{"sh", "-c", script})
	if err != nil {
		t.Fatalf("install.sh re-run exec: %v", err)
	}
	raw, _ = io.ReadAll(output)
	if code != 0 {
		t.Fatalf("install.sh re-run exit %d (expected degraded success):\n%s", code, raw)
	}
	if !strings.Contains(string(raw), "previous enrollment") {
		t.Errorf("re-run without degradation warning:\n%s", raw)
	}
}

// mintEnrollToken calls POST /v1/admin/enroll-tokens over the pinned TLS
// listener (127.0.0.1, the test runs outside the container).
func mintEnrollToken(t *testing.T, port int, pin string, payload map[string]any) (token, installCommand string) {
	t.Helper()
	decoded, err := pintls.DecodePin(pin)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: pintls.Transport(decoded), Timeout: 10 * time.Second}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("https://127.0.0.1:%d/v1/admin/enroll-tokens", port)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminBearer)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("mint request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mint status %d: %s", resp.StatusCode, raw)
	}
	var minted struct {
		Token          string `json:"token"`
		InstallCommand string `json:"install_command"`
	}
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatalf("parsing mint response: %v", err)
	}
	if minted.Token == "" {
		t.Fatal("mint response without token")
	}
	return minted.Token, minted.InstallCommand
}

// selfSignedCert builds a self-signed certificate for the public listener.
// IsCA so the same certificate is sufficient for curl in the container trust store.
func selfSignedCert(t *testing.T, dnsName string) (tls.Certificate, *x509.Certificate) {
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

// assertContainerCmd runs a command in the container and expects exit 0.
func assertContainerCmd(t *testing.T, ctr testcontainers.Container, cmd []string, msg string) {
	t.Helper()
	code, output, err := ctr.Exec(context.Background(), cmd)
	if err != nil {
		t.Fatalf("%s: exec %v: %v", msg, cmd, err)
	}
	if code != 0 {
		raw, _ := io.ReadAll(output)
		t.Fatalf("%s (exit %d): %s", msg, code, raw)
	}
}

// waitForContainerCmd repeats a command until exit 0 or timeout.
func waitForContainerCmd(t *testing.T, ctr testcontainers.Container, cmd []string, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		code, _, err := ctr.Exec(context.Background(), cmd)
		if err == nil && code == 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal(msg)
}

// containerHostname returns the hostname under which the agent registered
// (the script passes none — the agent uses os.Hostname).
func containerHostname(t *testing.T, ctr testcontainers.Container) string {
	t.Helper()
	code, output, err := ctr.Exec(context.Background(), []string{"hostname"})
	if err != nil || code != 0 {
		t.Fatalf("determining hostname: exit %d, %v", code, err)
	}
	raw, _ := io.ReadAll(output)
	// The exec stream is multiplexed; the 8-byte headers contain no
	// printable characters, so trimming the rest is sufficient.
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, string(raw)))
}
