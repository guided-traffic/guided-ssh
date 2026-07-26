//go:build integration

// Phase-E-Smoke des One-Command-Host-Installs: Token minten (Admin-API) →
// getemplatetes install.sh per curl im Container ziehen → Binary-Download +
// SHA-256-Prüfung → Enrollment mit Pflicht-Pin → laufender Agent.
//
// Der systemctl-Zweig bleibt bewusst ungetestet (--no-systemd): die Fixture hat
// kein systemd, ein systemd-Container im CI wäre privilegiert und flaky, ein
// systemctl-Stub würde Verhalten nur vortäuschen (siehe README-Sicherheitsteil).
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

// adminGroup ist die IdP-Gruppe, die der Testverifier dem Mint-Aufrufer gibt.
const adminGroup = "gssh-admins"

// adminBearer ist das Bearer-Token, das staticVerifier auf Admin-Claims abbildet.
const adminBearer = "e2e-admin-token"

// staticVerifier bildet genau ein Bearer-Token auf Admin-Claims ab; die
// OIDC-Verifikation selbst ist nicht Gegenstand dieses Tests.
type staticVerifier struct{}

func (staticVerifier) Verify(_ context.Context, rawToken string) (*auth.Claims, error) {
	if rawToken != adminBearer {
		return nil, fmt.Errorf("%w: token unbekannt", auth.ErrInvalidToken)
	}
	return &auth.Claims{
		Issuer: "https://idp.test/realms/gssh", Subject: "e2e-admin",
		Email: "admin@example.com", PreferredUsername: "admin",
		Groups: []string{adminGroup},
	}, nil
}

func TestInstallScriptEndToEnd(t *testing.T) {
	ctx := context.Background()

	// ── Postgres + Store + CA ────────────────────────────────────────────
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
		t.Fatalf("postgres-container: %v", err)
	}
	dsn, err := pgCtr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrationen: %v", err)
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

	// ── Agent-Binary unter dem Embed-Namen bereitstellen ─────────────────
	// Das Embed ist zur Testzeit leer (bin/ enthält nur .gitkeep) — genau
	// dafür existiert agentdist.NewFromFS.
	distDir := t.TempDir()
	if err := os.Link(buildAgentBinary(t), filepath.Join(distDir, "gssh-agentd-linux-"+runtime.GOARCH)); err != nil {
		t.Fatalf("agent-binary bereitstellen: %v", err)
	}

	// ── Öffentliche API über TLS (der Pin gilt für /v1/enroll) ───────────
	publicListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	publicPort := publicListener.Addr().(*net.TCPAddr).Port
	publicBaseURL := fmt.Sprintf("https://%s:%d", hostInternal, publicPort)

	tlsCert, leaf := selfSignedCert(t, hostInternal)
	// Statische Pin-Quelle aus demselben Zertifikat, das der Listener
	// präsentiert — dogfoodet pintls.FromCertificate (P1).
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

	// ── Agent-API (mTLS) — Ziel der enrollten config.yaml ────────────────
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

	// ── Token über die Admin-API minten (C2) ─────────────────────────────
	token, installCommand := mintEnrollToken(t, publicPort, pin, map[string]any{
		"tags": map[string]string{"env": "prod"}, "ttl_seconds": 600,
	})
	if !strings.Contains(installCommand, publicBaseURL+"/install.sh") || !strings.Contains(installCommand, token) {
		t.Fatalf("install_command unerwartet: %q", installCommand)
	}

	// ── sshd-Fixture: Script ziehen und ausführen ────────────────────────
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
		t.Fatalf("sshd-container: %v", err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		if logs, logErr := ctr.Logs(context.Background()); logErr == nil {
			raw, _ := io.ReadAll(logs)
			t.Logf("container-logs:\n%s", raw)
		}
	})

	// Das Test-Zertifikat in den Trust-Store: curl im Script prüft TLS regulär
	// (der Pin gilt nur für den Enroll-Call des Agenten).
	certPath := filepath.Join(t.TempDir(), "gssh-test-ca.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ctr.CopyFileToContainer(ctx, certPath, "/usr/local/share/ca-certificates/gssh-test-ca.crt", 0o644); err != nil {
		t.Fatalf("test-ca kopieren: %v", err)
	}
	if code, output, err := ctr.Exec(ctx, []string{"update-ca-certificates"}); err != nil || code != 0 {
		raw, _ := io.ReadAll(output)
		t.Fatalf("update-ca-certificates: exit %d, %v: %s", code, err, raw)
	}

	// Exakt der UI-Befehl, nur ohne sudo (im Container ist root aktiv) und mit
	// --no-systemd (die Fixture hat kein systemd).
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

	// ── Ergebnis auf dem Host ────────────────────────────────────────────
	// Binary installiert, config.yaml geschrieben; der Fixture-Entrypoint
	// startet daraufhin den Agenten — der Socket ist dasselbe Readiness-Signal,
	// auf das der systemd-Zweig des Scripts wartet.
	assertContainerCmd(t, ctr, []string{"test", "-x", "/usr/bin/gssh-agentd"}, "binary nicht installiert")
	assertContainerCmd(t, ctr, []string{"test", "-f", "/var/lib/guided-ssh/config.yaml"}, "config.yaml fehlt")
	waitForContainerCmd(t, ctr, []string{"test", "-S", "/var/lib/guided-ssh/agentd.sock"}, 30*time.Second,
		"agentd.sock erschien nicht — agent nicht gestartet")

	// ── Host in der Datenbank ────────────────────────────────────────────
	hostname := containerHostname(t, ctr)
	host, err := st.GetHostByName(ctx, hostname)
	if err != nil {
		t.Fatalf("host %q nicht registriert: %v", hostname, err)
	}
	tags, err := st.GetHostTags(ctx, host.ID)
	if err != nil || tags["env"] != "prod" {
		t.Fatalf("host-tags: %v %v", tags, err)
	}

	// Einmalverbrauch: dieselbe Zeile ein zweites Mal scheitert beim Enroll —
	// mit vorhandener config.yaml läuft das Script bewusst degradiert weiter.
	code, output, err = ctr.Exec(ctx, []string{"sh", "-c", script})
	if err != nil {
		t.Fatalf("install.sh re-run exec: %v", err)
	}
	raw, _ = io.ReadAll(output)
	if code != 0 {
		t.Fatalf("install.sh re-run exit %d (erwartet degradierter erfolg):\n%s", code, raw)
	}
	if !strings.Contains(string(raw), "bestehendes enrollment") {
		t.Errorf("re-run ohne degradations-warnung:\n%s", raw)
	}
}

// mintEnrollToken ruft POST /v1/admin/enroll-tokens über den gepinnten
// TLS-Listener (127.0.0.1, der Test läuft außerhalb des Containers).
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
		t.Fatalf("mint-request: %v", err)
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
		t.Fatalf("mint-antwort parsen: %v", err)
	}
	if minted.Token == "" {
		t.Fatal("mint-antwort ohne token")
	}
	return minted.Token, minted.InstallCommand
}

// selfSignedCert baut ein selbstsigniertes Zertifikat für den Public-Listener.
// IsCA, damit dasselbe Zertifikat im Container-Trust-Store curl genügt.
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

// assertContainerCmd führt ein Kommando im Container aus und erwartet Exit 0.
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

// waitForContainerCmd wiederholt ein Kommando bis Exit 0 oder Timeout.
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

// containerHostname liefert den Hostnamen, unter dem sich der Agent registriert
// hat (das Script übergibt keinen — der Agent nimmt os.Hostname).
func containerHostname(t *testing.T, ctr testcontainers.Container) string {
	t.Helper()
	code, output, err := ctr.Exec(context.Background(), []string{"hostname"})
	if err != nil || code != 0 {
		t.Fatalf("hostname ermitteln: exit %d, %v", code, err)
	}
	raw, _ := io.ReadAll(output)
	// Der Exec-Stream ist gemultiplext; die 8-Byte-Header enthalten keine
	// druckbaren Zeichen, deshalb reicht das Trimmen des Rests.
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, string(raw)))
}
