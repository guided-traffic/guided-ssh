//go:build integration

// Phase-7-E2E-Test: simuliertes GitLab-OIDC (Discovery + JWKS), CI-Grant,
// POST /v1/sign/ci mit signiertem Job-Token, Login auf dem Container-Host als
// deploy über den kompletten Pfad TrustedUserCAKeys + CI-Principals im
// AuthorizedPrincipalsCommand; optional Ansible-Ping, falls ansible auf dem
// Runner installiert ist.
package agentd_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeGitLab ist ein minimaler GitLab-OIDC-Issuer: Discovery + JWKS + Signatur
// von Job-Tokens (id_tokens).
type fakeGitLab struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newFakeGitLab(t *testing.T) *fakeGitLab {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa-key: %v", err)
	}
	gl := &fakeGitLab{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                gl.server.URL,
			"jwks_uri":                              gl.server.URL + "/oauth/discovery/keys",
			"authorization_endpoint":                gl.server.URL + "/oauth/authorize",
			"token_endpoint":                        gl.server.URL + "/oauth/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /oauth/discovery/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "gitlab-key", Algorithm: "RS256", Use: "sig",
		}}})
	})
	gl.server = httptest.NewServer(mux)
	t.Cleanup(gl.server.Close)
	return gl
}

// jobToken signiert ein GitLab-Job-Token; overrides überschreibt Claims.
func (gl *fakeGitLab) jobToken(overrides map[string]any) string {
	gl.t.Helper()
	claims := map[string]any{
		"iss":            gl.server.URL,
		"aud":            auth.DefaultCIAudience,
		"sub":            "project_path:infra/ansible:ref_type:branch:ref:main",
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
		"project_path":   "infra/ansible",
		"namespace_path": "infra",
		"ref":            "main",
		"ref_type":       "branch",
		"ref_protected":  "true",
		"pipeline_id":    "4711",
		"job_id":         "815",
		"user_login":     "alice",
	}
	for k, v := range overrides {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		gl.t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: gl.key},
		(&jose.SignerOptions{}).WithHeader("kid", "gitlab-key"),
	)
	if err != nil {
		gl.t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		gl.t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		gl.t.Fatal(err)
	}
	return raw
}

func TestGitLabCIEndToEnd(t *testing.T) {
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

	// ── Simuliertes GitLab + echter CI-Verifier ──────────────────────────
	gitlab := newFakeGitLab(t)
	ciVerifier, err := auth.NewCIVerifier(ctx, auth.CIVerifierConfig{IssuerURL: gitlab.server.URL})
	if err != nil {
		t.Fatalf("ci-verifier: %v", err)
	}

	// ── Öffentliche API (Enroll + Sign-CI) + Agent-API (mTLS) ────────────
	publicListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	publicServer := &http.Server{
		Handler: api.New(api.Deps{
			CA: certAuthority, Hosts: st, CIVerifier: ciVerifier, CIStore: st, Logger: logger,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = publicServer.Serve(publicListener) }()
	t.Cleanup(func() { _ = publicServer.Close() })
	publicPort := publicListener.Addr().(*net.TCPAddr).Port

	serverCert, err := certAuthority.IssueServerCert(ctx, []string{hostInternal, "localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := certAuthority.MTLSCAPool(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agentListener, err := net.Listen("tcp", "0.0.0.0:0")
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
	agentPort := agentListener.Addr().(*net.TCPAddr).Port

	// ── CI-Grant: infra/ansible → deploy auf env=prod ────────────────────
	if err := st.CreateCIGrant(ctx, "test", &store.CIGrant{
		ProjectPath: "infra/ansible", ProtectedOnly: true,
		TagSelector: map[string]string{"env": "prod"},
		Principals:  []string{"deploy"}, MaxValiditySeconds: 3600,
	}); err != nil {
		t.Fatal(err)
	}

	// ── Enrollment-Token + sshd-Container ────────────────────────────────
	token := "gssh-et-ci-integration-test"
	hash := sha256.Sum256([]byte(token))
	if err := st.CreateEnrollmentToken(ctx, &store.EnrollmentToken{
		TokenHash: hash[:],
		Tags:      map[string]string{"env": "prod"},
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	binaryPath := buildAgentBinary(t)
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
	if err := ctr.CopyFileToContainer(ctx, binaryPath, "/usr/local/bin/gssh-agentd", 0o755); err != nil {
		t.Fatalf("binary kopieren: %v", err)
	}
	code, output, err := ctr.Exec(ctx, []string{
		"/usr/local/bin/gssh-agentd", "enroll",
		"--server", fmt.Sprintf("http://%s:%d", hostInternal, publicPort),
		"--agent-url", fmt.Sprintf("https://%s:%d", hostInternal, agentPort),
		"--token", token,
		"--hostname", "ci-target.test",
	})
	if err != nil {
		t.Fatalf("enroll exec: %v", err)
	}
	if code != 0 {
		raw, _ := io.ReadAll(output)
		t.Fatalf("enroll exit %d: %s", code, raw)
	}

	// ── Simuliertes GitLab-Token → Zertifikat über POST /v1/sign/ci ──────
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", publicPort)
	ciPub, ciPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ciSSHPub, err := ssh.NewPublicKey(ciPub)
	if err != nil {
		t.Fatal(err)
	}
	ciCert := signCICert(t, apiURL, gitlab.jobToken(nil), ciSSHPub)
	if ciCert.KeyId != "ci:infra/ansible:4711:815" {
		t.Errorf("keyid: %q", ciCert.KeyId)
	}

	// Unprotected Ref wird abgelehnt (Grant verlangt protected).
	if status := postSignCIStatus(t, apiURL, gitlab.jobToken(map[string]any{"ref_protected": "false"}), ciSSHPub); status != http.StatusForbidden {
		t.Errorf("unprotected ref: status %d, erwartet 403", status)
	}
	// Fremdes Projekt wird abgelehnt.
	if status := postSignCIStatus(t, apiURL, gitlab.jobToken(map[string]any{
		"project_path": "andere/app", "sub": "project_path:andere/app",
	}), ciSSHPub); status != http.StatusForbidden {
		t.Errorf("fremdes projekt: status %d, erwartet 403", status)
	}

	// ── Login als deploy mit dem CI-Zertifikat ───────────────────────────
	keySigner, err := ssh.NewSignerFromKey(ciPriv)
	if err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(ciCert, keySigner)
	if err != nil {
		t.Fatal(err)
	}
	hostBundle, err := certAuthority.Bundle(ctx, store.CertTypeHost)
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			marshaled := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(auth)))
			return strings.Contains(hostBundle, marshaled)
		},
	}
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("kein host-zertifikat: %T", key)
		}
		if !checker.IsHostAuthority(cert.SignatureKey, "") {
			return fmt.Errorf("host-zertifikat von unbekannter ca")
		}
		return checker.CheckCert("ci-target.test", cert)
	}
	mappedPort, err := ctr.MappedPort(ctx, "22/tcp")
	if err != nil {
		t.Fatal(err)
	}
	containerHost, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sshAddr := net.JoinHostPort(containerHost, mappedPort.Port())

	// deploy: CI-Grant matcht (Host-ACL liefert ci:infra/ansible).
	assertWhoami(t, sshAddr, "deploy", certSigner, hostKeyCallback, "deploy")
	// root: kein CI-Grant ⇒ fail-closed.
	if err := trySSH(sshAddr, "root", certSigner, hostKeyCallback); err == nil {
		t.Fatal("login als root muss scheitern (kein ci-grant)")
	}

	// Audit: Ausstellung ist der Pipeline zugeordnet.
	events, err := st.ListAuditEvents(ctx, store.AuditFilter{EventType: ca.EventCertIssued})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Actor == "ci:infra/ansible:4711:815" {
			found = true
		}
	}
	if !found {
		t.Errorf("kein audit-event mit ci-keyid gefunden (%d events)", len(events))
	}

	// ── Ansible-Ping (nur wenn ansible auf dem Runner installiert ist) ───
	runAnsiblePing(t, sshAddr, ciPriv, ciCert)
}

// signCICert tauscht das Job-Token am Sign-Endpoint gegen ein Zertifikat.
func signCICert(t *testing.T, apiURL, jobToken string, pub ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	status, body := postSignCIRaw(t, apiURL, jobToken, pub)
	if status != http.StatusOK {
		t.Fatalf("sign/ci: status %d: %s", status, body)
	}
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("zertifikat parsen: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("kein zertifikat: %T", parsed)
	}
	return cert
}

func postSignCIStatus(t *testing.T, apiURL, jobToken string, pub ssh.PublicKey) int {
	t.Helper()
	status, _ := postSignCIRaw(t, apiURL, jobToken, pub)
	return status
}

func postSignCIRaw(t *testing.T, apiURL, jobToken string, pub ssh.PublicKey) (int, []byte) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, apiURL+"/v1/sign/ci", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+jobToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sign/ci erreichen: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

// runAnsiblePing führt `ansible all -m ping` gegen den Testhost aus, sofern
// ansible installiert ist — der komplette Referenz-Pfad der Doku (Zertifikat
// statt statischer Key). Ohne ansible wird der Schritt nur geloggt; der
// SSH-Durchstich ist bereits verifiziert.
func runAnsiblePing(t *testing.T, sshAddr string, priv ed25519.PrivateKey, cert *ssh.Certificate) {
	t.Helper()
	ansible, err := exec.LookPath("ansible")
	if err != nil {
		t.Log("ansible nicht installiert — ping-schritt übersprungen (ssh-durchstich bereits geprüft)")
		return
	}

	dir := t.TempDir()
	keyPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("private key marshalen: %v", err)
	}
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatal(err)
	}

	host, port, err := net.SplitHostPort(sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(dir, "inventory.ini")
	if err := os.WriteFile(inventory, []byte(fmt.Sprintf(
		"[ci_targets]\ntarget ansible_host=%s ansible_port=%s ansible_user=deploy ansible_python_interpreter=/usr/bin/python3\n",
		host, port,
	)), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(ansible, "all", "-i", inventory, "-m", "ping")
	cmd.Env = append(os.Environ(),
		"ANSIBLE_HOST_KEY_CHECKING=False",
		fmt.Sprintf("ANSIBLE_SSH_ARGS=-o IdentityFile=%s -o CertificateFile=%s -o IdentitiesOnly=yes", keyPath, certPath),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-ping fehlgeschlagen: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "pong") {
		t.Errorf("ansible-ping ohne pong:\n%s", output)
	}
	t.Logf("ansible-ping ok")
}
