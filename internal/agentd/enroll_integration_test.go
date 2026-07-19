//go:build integration

// Phase-5-Integrationstest: Container-Host mit sshd, Enrollment über die
// echte API (inkl. mTLS-Agent-Listener), Login mit Benutzerzertifikat über
// den kompletten Pfad TrustedUserCAKeys + AuthorizedPrincipalsCommand.
package agentd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// hostInternal ist der DNS-Name, unter dem Container den Test-Host erreichen
// (testcontainers WithHostPortAccess).
const hostInternal = "host.testcontainers.internal"

func TestEnrollmentUndLoginEndToEnd(t *testing.T) {
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// ── Öffentliche API (Enroll) + Agent-API (mTLS) auf Host-Ports ───────
	publicListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	publicServer := &http.Server{
		Handler:           api.New(api.Deps{CA: certAuthority, Hosts: st, Logger: logger}),
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

	// ── Benutzer, Gruppe, Grant, Enrollment-Token ────────────────────────
	alice := &store.User{Issuer: "idp", Subject: "s1", Username: "alice", Email: "alice@example.com", Active: true}
	if err := st.CreateUser(ctx, alice); err != nil {
		t.Fatal(err)
	}
	ops := &store.Group{Issuer: "idp", Name: "ops"}
	if err := st.CreateGroup(ctx, ops); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserGroups(ctx, alice.ID, []uuid.UUID{ops.ID}); err != nil {
		t.Fatal(err)
	}
	// ops darf als alice und deploy auf Hosts mit env=prod.
	grant := &store.AccessGrant{
		GroupID: ops.ID, TagSelector: map[string]string{"env": "prod"},
		Principals: []string{"alice", "deploy"}, MaxValiditySeconds: 3600,
	}
	if err := st.CreateGrant(ctx, "test", grant); err != nil {
		t.Fatal(err)
	}

	token := "gssh-et-integration-test"
	hash := sha256.Sum256([]byte(token))
	if err := st.CreateEnrollmentToken(ctx, &store.EnrollmentToken{
		TokenHash: hash[:],
		Tags:      map[string]string{"env": "prod"},
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// ── Agent-Binary für linux bauen ─────────────────────────────────────
	binaryPath := buildAgentBinary(t)

	// ── sshd-Container ───────────────────────────────────────────────────
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

	// ── Enrollment im Container ──────────────────────────────────────────
	code, output, err := ctr.Exec(ctx, []string{
		"/usr/local/bin/gssh-agentd", "enroll",
		"--server", fmt.Sprintf("http://%s:%d", hostInternal, publicPort),
		"--agent-url", fmt.Sprintf("https://%s:%d", hostInternal, agentPort),
		"--token", token,
		"--hostname", "web1.test",
	})
	if err != nil {
		t.Fatalf("enroll exec: %v", err)
	}
	if code != 0 {
		raw, _ := io.ReadAll(output)
		t.Fatalf("enroll exit %d: %s", code, raw)
	}

	// Host in der DB registriert, Tags aus dem Token.
	host, err := st.GetHostByName(ctx, "web1.test")
	if err != nil {
		t.Fatalf("host nicht registriert: %v", err)
	}
	tags, err := st.GetHostTags(ctx, host.ID)
	if err != nil || tags["env"] != "prod" {
		t.Fatalf("host-tags: %v %v", tags, err)
	}

	// ── sshd abwarten (entrypoint startet agentd + sshd nach Enrollment) ─
	mappedPort, err := ctr.MappedPort(ctx, "22/tcp")
	if err != nil {
		t.Fatal(err)
	}
	containerHost, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sshAddr := net.JoinHostPort(containerHost, mappedPort.Port())

	// ── Benutzerzertifikat ausstellen (wie POST /v1/sign/user) ───────────
	userPub, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSSHPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	userCert, _, err := certAuthority.Issue(ctx, ca.RequesterUser, ca.CertRequest{
		CertType:    store.CertTypeUser,
		PublicKey:   userSSHPub,
		KeyID:       ca.UserKeyID("s1", "idp"),
		Principals:  []string{"alice", "alice@example.com"},
		ValidAfter:  now.Add(-time.Minute),
		ValidBefore: now.Add(time.Hour),
		Extensions:  map[string]string{"permit-pty": ""},
	}, ca.IssueRef{Actor: "test", UserID: &alice.ID})
	if err != nil {
		t.Fatalf("benutzerzertifikat: %v", err)
	}
	keySigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(userCert, keySigner)
	if err != nil {
		t.Fatal(err)
	}

	// Host-Zertifikate gegen das Host-CA-Bundle verifizieren.
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
	// Der Test verbindet über localhost:<mapped-port>; das Host-Zertifikat
	// trägt aber die Principals web1.test/web1 — deshalb Principal-Prüfung
	// gegen den registrierten Hostnamen statt der Verbindungsadresse.
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("kein host-zertifikat: %T", key)
		}
		if !checker.IsHostAuthority(cert.SignatureKey, "") {
			return fmt.Errorf("host-zertifikat von unbekannter ca")
		}
		return checker.CheckCert("web1.test", cert)
	}

	// ── Login-Pfade ──────────────────────────────────────────────────────
	// alice: Grant-Principal "alice" matcht Zertifikats-Principal alice.
	assertWhoami(t, sshAddr, "alice", certSigner, hostKeyCallback, "alice")
	// deploy: Grant-Pfad — Zertifikat trägt alice, Grant erlaubt deploy.
	assertWhoami(t, sshAddr, "deploy", certSigner, hostKeyCallback, "deploy")
	// root: kein Grant ⇒ AuthorizedPrincipalsCommand liefert nichts ⇒ abgelehnt.
	if err := trySSH(sshAddr, "root", certSigner, hostKeyCallback); err == nil {
		t.Fatal("login als root muss scheitern (kein grant, fail-closed)")
	}
}

// buildAgentBinary baut gssh-agentd für linux/<runner-arch>.
func buildAgentBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "gssh-agentd")
	cmd := exec.Command("go", "build", "-o", out, "github.com/guided-traffic/guided-ssh/cmd/gssh-agentd")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agent-binary bauen: %v\n%s", err, output)
	}
	return out
}

// trySSH versucht Login + `whoami`; liefert Fehler oder die Ausgabe.
func trySSH(addr, user string, signer ssh.Signer, hostKeyCallback ssh.HostKeyCallback) error {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	output, err := session.Output("whoami")
	if err != nil {
		return err
	}
	if got := strings.TrimSpace(string(output)); got != user {
		return fmt.Errorf("whoami = %q, erwartet %q", got, user)
	}
	return nil
}

// assertWhoami wartet auf sshd (Retry) und prüft den Login.
func assertWhoami(t *testing.T, addr, user string, signer ssh.Signer, hostKeyCallback ssh.HostKeyCallback, want string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = trySSH(addr, user, signer, hostKeyCallback); lastErr == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("ssh als %s (erwartet whoami=%s): %v", user, want, lastErr)
}
