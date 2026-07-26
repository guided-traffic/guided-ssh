//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestE2E runs the plan's scenarios (Phase 13) in a fixed order against a
// shared environment: SSO login, grant change, CI certificate + Ansible,
// host rotation, chaos (API down), offboarding, audit, and the internal
// test database (Postgres sidecar, separate Helm release).
// Session/sudo audit events are deliberately not covered here (opt-in
// feature; PAM behavior is verified in the Phase 9 tests).
func TestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e skipped (-short)")
	}
	e := setupEnv(t)

	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.Fatalf("scenario %s failed — subsequent scenarios build on it", name)
		}
	}
	step("01_SSO_Login_DeviceFlow", e.testSSOLogin)
	step("02_Grant_Change", e.testGrantChange)
	step("03_CI_Certificate_Ansible", e.testCIProvisioning)
	step("04_Host_Rotation", e.testHostRotation)
	step("05_Chaos_API_Down", e.testChaos)
	step("06_Offboarding", e.testOffboarding)
	step("07_Audit_Completeness", e.testAudit)
	step("08_Internal_Database", e.testInternalDatabase)
}

// testInternalDatabase: internalDatabase.enabled — a second Helm release in
// the same namespace, Postgres runs as a native sidecar in the server pod,
// without a DB secret. This verifies the complete path sidecar → migrations
// → server healthy → CA bootstrapped, the ephemerality (pod restart ⇒ empty
// database ⇒ NEW CA — hence tests only) and the render guard against a
// simultaneously set DB secret.
func (e *env) testInternalDatabase(t *testing.T) {
	chart := filepath.Join(e.repoRoot, "deploy/helm/guided-ssh")
	// Release name contains the chart name ⇒ fullname == release name.
	const release = "guided-ssh-internal"

	// CA secret — the only required secret with an internal database.
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	secret := e.mustKubectl("create", "secret", "generic", release+"-ca",
		"--from-literal=ca-master-key="+base64.StdEncoding.EncodeToString(masterKey),
		"--dry-run=client", "-o", "yaml")
	e.applyYAML(secret)

	values := filepath.Join(e.tmp, "values-internal.yaml")
	if err := os.WriteFile(values, []byte(render(helmValuesInternal, map[string]string{"RELEASE": release})), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run("", "", "helm", "--kube-context", e.context(),
		"upgrade", "--install", release, chart,
		"-n", e.ns, "-f", values, "--wait", "--timeout", "5m")
	if err != nil {
		t.Fatalf("helm install (internal database): %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = run("", "", "helm", "--kube-context", e.context(), "uninstall", release, "-n", e.ns)
	})

	pf := e.portForward("svc/"+release, 80)
	e.poll(60*time.Second, "healthz (internal database)", func() error {
		_, err := httpGet(pf.URL()+"/healthz", "")
		return err
	})
	bundleBefore, err := httpGet(pf.URL()+"/v1/ca/bundle/user", "")
	if err != nil {
		t.Fatalf("ca-bundle: %v", err)
	}
	if !strings.Contains(bundleBefore, "ssh-") {
		t.Fatalf("ca-bundle without ssh-key: %q", bundleBefore)
	}

	// Ephemerality: delete pod ⇒ emptyDir gone ⇒ fresh database ⇒ the server
	// bootstraps a NEW CA. If the bundle stays identical, the database is
	// not pod-local (persistence or wrong connection).
	e.mustKubectl("delete", "pod", "-l", "app.kubernetes.io/instance="+release, "--wait=true")
	e.mustKubectl("rollout", "status", "deploy/"+release, "--timeout=300s")
	pf.restart()
	e.poll(60*time.Second, "healthz after pod restart", func() error {
		_, err := httpGet(pf.URL()+"/healthz", "")
		return err
	})
	bundleAfter, err := httpGet(pf.URL()+"/v1/ca/bundle/user", "")
	if err != nil {
		t.Fatalf("ca-bundle after restart: %v", err)
	}
	if bundleAfter == bundleBefore {
		t.Error("ca-bundle unchanged after pod restart — internal database is not ephemeral")
	}

	// Guard: internalDatabase + DB secret at the same time ⇒ render error
	// with a clear message (protection against an accidental test database).
	out, err = run("", "", "helm", "template", release, chart,
		"-f", values, "--set", "secrets.db.existingSecret=must-not-exist")
	if err == nil {
		t.Fatal("helm template with internalDatabase + db-secret must fail")
	}
	// The guard message itself is produced by
	// deploy/helm/guided-ssh/templates/_helpers.tpl.
	if !strings.Contains(out, "mutually exclusive") {
		t.Errorf("unexpected guard error message: %q", out)
	}
}

// startWS starts a workstation command asynchronously (for device flow and
// long-running SSH sessions).
func (e *env) startWS(command string) *exec.Cmd {
	return exec.Command("kubectl", "--context", e.context(), "-n", e.ns,
		"exec", "pod/workstation", "--", "sh", "-c",
		"export SSH_AUTH_SOCK=/tmp/agent.sock GSSH_CONFIG=/etc/gssh/config.yaml HOME=/root; "+command)
}

// testSSOLogin: the complete human end-to-end path — gssh login --device in
// the workstation pod, the suite "clicks through" the Dex device flow
// (LDAP login as alice), then transparent ssh with strict host certificate
// checking.
func (e *env) testSSOLogin(t *testing.T) {
	login := e.startWS("gssh login --device")
	stderr, err := login.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	login.Stdout = &stdout
	if err := login.Start(); err != nil {
		t.Fatalf("starting gssh login: %v", err)
	}

	type prompt struct{ uri, code string }
	promptCh := make(chan prompt, 1)
	var stderrLog bytes.Buffer
	go func() {
		var p prompt
		scanner := bufio.NewScanner(io.TeeReader(stderr, &stderrLog))
		for scanner.Scan() {
			line := scanner.Text()
			if rest, ok := strings.CutPrefix(line, "open in browser: "); ok {
				p.uri = strings.TrimSpace(rest)
			}
			if rest, ok := strings.CutPrefix(line, "enter code: "); ok {
				p.code = strings.TrimSpace(rest)
			}
			if p.uri != "" && p.code != "" {
				promptCh <- p
				break
			}
		}
		_, _ = io.Copy(&stderrLog, stderr)
	}()

	var p prompt
	select {
	case p = <-promptCh:
	case <-time.After(60 * time.Second):
		_ = login.Process.Kill()
		t.Fatalf("device flow prompt did not appear; stderr:\n%s", stderrLog.String())
	}
	t.Logf("device-flow: %s (code %s)", p.uri, p.code)
	if err := approveDeviceFlow(e.dexPF.URL(), p.uri, p.code, "alice", alicePassword); err != nil {
		t.Fatalf("approving device flow: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- login.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gssh login: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderrLog.String())
		}
	case <-time.After(90 * time.Second):
		_ = login.Process.Kill()
		t.Fatalf("gssh login hangs; stderr:\n%s", stderrLog.String())
	}
	if !strings.Contains(stdout.String(), "signed in:") {
		t.Fatalf("unexpected login output: %s", stdout.String())
	}

	// Certificate only lives in the agent; status confirms validity.
	e.mustWS("gssh status")

	// SSH as deploy onto role=web (grant dev×web), host cert CA-verified.
	if out := strings.TrimSpace(e.mustWS(sshCmd("deploy", e.webFQDN, "whoami"))); out != "deploy" {
		t.Fatalf("whoami = %q, expected deploy", out)
	}
	// root: no grant ⇒ fail-closed.
	if _, err := e.ws(sshCmd("root", e.webFQDN, "true")); err == nil {
		t.Fatal("login as root must fail (no grant)")
	}
	// db host: no grant yet for role=db ⇒ fail-closed.
	if _, err := e.ws(sshCmd("deploy", e.dbFQDN, "true")); err == nil {
		t.Fatal("login to db host must fail (no grant for role=db)")
	}
}

// testGrantChange: add a grant declaratively (role=db) → access appears;
// revoke it → access disappears (each within the agent's cache TTL).
func (e *env) testGrantChange(t *testing.T) {
	e.adminApply(grantsWithDB)
	e.poll(120*time.Second, "new grant takes effect on db host", func() error {
		out, err := e.ws(sshCmd("deploy", e.dbFQDN, "whoami"))
		if err != nil {
			return err
		}
		if !strings.Contains(out, "deploy") {
			return fmt.Errorf("whoami: %s", out)
		}
		return nil
	})
	e.adminApply(grantsBase)
	e.waitError(120*time.Second, "grant revocation takes effect on db host", func() error {
		_, err := e.ws(sshCmd("deploy", e.dbFQDN, "true"))
		return err
	})
}

// testCIProvisioning: simulated GitLab job token → gssh ci-login (real
// binary, local ssh-agent) → Ansible provisions the test host through the
// agent; negative case unprotected ref. Go-SSH verifies the result.
func (e *env) testCIProvisioning(t *testing.T) {
	// In-process ssh-agent as a Unix socket for gssh ci-login and Ansible.
	sock := filepath.Join(e.tmp, "ci-agent.sock")
	keyring := agent.NewKeyring()
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()

	token, err := e.gitlab.jobToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runWithEnv(
		[]string{"SSH_AUTH_SOCK=" + sock, "GSSH_CI_TOKEN=" + token},
		e.gsshHost, "ci-login", "--api-url", e.apiPF.URL())
	if err != nil {
		t.Fatalf("gssh ci-login: %v\n%s", err, out)
	}

	// Certificate in the agent: KeyID maps to pipeline and job.
	keys, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	foundCert := false
	for _, key := range keys {
		parsed, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			continue
		}
		if cert, ok := parsed.(*ssh.Certificate); ok && cert.KeyId == "ci:platform/deploy:4711:815" {
			foundCert = true
		}
	}
	if !foundCert {
		t.Fatalf("no ci certificate with expected keyid in the agent (%d keys)", len(keys))
	}

	// Unprotected ref ⇒ 403 (grant requires protected_only).
	badToken, err := e.gitlab.jobToken(map[string]any{"ref_protected": "false"})
	if err != nil {
		t.Fatal(err)
	}
	if status := e.signCIStatus(badToken); status != http.StatusForbidden {
		t.Errorf("unprotected ref: status %d, expected 403", status)
	}

	// SSH access to the test host over port-forward.
	pfWeb := e.portForward("svc/testhost-web", 22)
	addr := fmt.Sprintf("127.0.0.1:%d", pfWeb.local)
	signers, err := keyring.Signers()
	if err != nil {
		t.Fatal(err)
	}
	hostCB := e.hostKeyCallback(t, e.webFQDN)

	if e.ansible {
		dir := t.TempDir()
		inventory := filepath.Join(dir, "inventory.ini")
		playbook := filepath.Join(dir, "site.yml")
		if err := os.WriteFile(inventory, []byte(fmt.Sprintf(
			"target ansible_host=127.0.0.1 ansible_port=%d ansible_user=deploy ansible_python_interpreter=/usr/bin/python3\n",
			pfWeb.local)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(playbook, []byte(`---
- hosts: all
  gather_facts: false
  tasks:
    - name: reachability
      ansible.builtin.ping:
    - name: write provisioning marker
      ansible.builtin.copy:
        content: "provisioned-by-ansible\n"
        dest: /tmp/e2e-provisioned
        mode: "0644"
`), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := runWithEnv(
			[]string{"SSH_AUTH_SOCK=" + sock, "ANSIBLE_HOST_KEY_CHECKING=False"},
			"ansible-playbook", "-i", inventory, playbook)
		if err != nil {
			t.Fatalf("ansible-playbook: %v\n%s", err, out)
		}
		if !strings.Contains(out, "failed=0") {
			t.Fatalf("ansible-playbook reported failures:\n%s", out)
		}
		if got, err := goSSH(addr, "deploy", signers, hostCB, "cat /tmp/e2e-provisioned"); err != nil ||
			!strings.Contains(got, "provisioned-by-ansible") {
			t.Fatalf("provisioning marker missing: %v %q", err, got)
		}
	} else {
		t.Log("ansible-playbook not installed — go-ssh covers the certificate path")
	}

	// The certificate path itself (always, even without Ansible).
	if got, err := goSSH(addr, "deploy", signers, hostCB, "whoami"); err != nil || strings.TrimSpace(got) != "deploy" {
		t.Fatalf("ci-ssh whoami: %v %q", err, got)
	}
}

// testHostRotation: short host certificate lifetime (3m via
// GSSH_HOST_CERT_VALIDITY) ⇒ the daemon rotates at 2/3 of the lifetime;
// sshd is reloaded via reload_command and logins keep working.
func (e *env) testHostRotation(t *testing.T) {
	serialOf := func() (uint64, *ssh.Certificate, error) {
		out, err := e.execPod("deploy/testhost-web", "cat /etc/ssh/ssh_host_ed25519_key-cert.pub")
		if err != nil {
			return 0, nil, err
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out))
		if err != nil {
			return 0, nil, fmt.Errorf("parsing host certificate: %w", err)
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			return 0, nil, fmt.Errorf("not a certificate: %T", parsed)
		}
		return cert.Serial, cert, nil
	}

	before, _, err := serialOf()
	if err != nil {
		t.Fatal(err)
	}
	var rotated *ssh.Certificate
	e.poll(4*time.Minute, "host certificate rotated", func() error {
		serial, cert, err := serialOf()
		if err != nil {
			return err
		}
		if serial == before {
			return fmt.Errorf("serial unchanged (%d)", serial)
		}
		rotated = cert
		return nil
	})
	if lifetime := time.Duration(rotated.ValidBefore-rotated.ValidAfter) * time.Second; lifetime != 3*time.Minute {
		t.Errorf("lifetime of rotated certificate = %s, expected 3m", lifetime)
	}
	// sshd has loaded the new certificate (reload_command) — login keeps working.
	if out := strings.TrimSpace(e.mustWS(sshCmd("deploy", e.webFQDN, "whoami"))); out != "deploy" {
		t.Fatalf("whoami after rotation = %q", out)
	}
}

// testChaos: API gone ⇒ existing SSH session keeps living, the agent cache
// carries new logins until the TTL (30s), then fail-closed; after restart
// everything works again.
func (e *env) testChaos(t *testing.T) {
	// Open a long-running session BEFORE the outage.
	session := e.startWS(sshCmd("deploy", e.webFQDN, "sleep 45; echo SESSION_ALIVE"))
	var sessionOut bytes.Buffer
	session.Stdout = &sessionOut
	session.Stderr = &sessionOut
	if err := session.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)

	e.mustKubectl("scale", "deployment/guided-ssh", "--replicas=0")
	e.poll(60*time.Second, "api pods terminated", func() error {
		out, err := e.kubectl("get", "pods", "-l", "app.kubernetes.io/instance=guided-ssh", "-o", "name")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "" {
			return fmt.Errorf("pods still present: %s", out)
		}
		return nil
	})
	downSince := time.Now()

	// Cache carries logins until the TTL.
	if out, err := e.ws(sshCmd("deploy", e.webFQDN, "whoami")); err != nil || !strings.Contains(out, "deploy") {
		t.Fatalf("login from agent cache during api outage: %v %q", err, out)
	}

	// Let the TTL (30s) expire ⇒ fail-closed.
	if wait := 40*time.Second - time.Since(downSince); wait > 0 {
		time.Sleep(wait)
	}
	if _, err := e.ws(sshCmd("deploy", e.webFQDN, "true")); err == nil {
		t.Fatal("login must fail after the cache TTL expires (fail-closed)")
	}

	// The existing session survived the entire outage.
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		if err != nil || !strings.Contains(sessionOut.String(), "SESSION_ALIVE") {
			t.Fatalf("existing session did not survive the api outage: %v\n%s", err, sessionOut.String())
		}
	case <-time.After(60 * time.Second):
		_ = session.Process.Kill()
		t.Fatalf("session hangs:\n%s", sessionOut.String())
	}

	// Restart: API back up, port-forward renewed (old pod is gone), login ok.
	e.mustKubectl("scale", "deployment/guided-ssh", "--replicas=1")
	e.mustKubectl("rollout", "status", "deploy/guided-ssh", "--timeout=180s")
	e.apiPF.restart()
	e.waitHealthy()
	e.poll(120*time.Second, "login after api restart", func() error {
		out, err := e.ws(sshCmd("deploy", e.webFQDN, "whoami"))
		if err != nil {
			return err
		}
		if !strings.Contains(out, "deploy") {
			return fmt.Errorf("whoami: %s", out)
		}
		return nil
	})
}

// testOffboarding: alice loses the IdP group dev ⇒ no new issuance (403) and
// the host ACL denies the still-valid certificate within the cache TTL —
// the offboarding path of the success criteria.
func (e *env) testOffboarding(t *testing.T) {
	e.applyConfigMap("glauth-config", map[string]string{
		"config.cfg": render(glauthConfig, map[string]string{"ALICE_OTHERGROUPS": "5501"}),
	})
	e.mustKubectl("rollout", "restart", "deploy/glauth")
	e.mustKubectl("rollout", "status", "deploy/glauth", "--timeout=120s")

	var freshToken string
	e.poll(120*time.Second, "fresh token without dev group", func() error {
		token, err := passwordGrant(e.dexPF.URL(), "alice", alicePassword)
		if err != nil {
			return err
		}
		groups, err := tokenGroups(token)
		if err != nil {
			return err
		}
		for _, g := range groups {
			if g == "dev" {
				return fmt.Errorf("token still contains dev: %v", groups)
			}
		}
		freshToken = token
		return nil
	})

	// No new issuance; the attempt also updates the DB groups from the
	// token claims (offboarding without admin API sync).
	if status, body := e.signUserStatus(freshToken); status != http.StatusForbidden {
		t.Fatalf("sign after group revocation: status %d (%s), expected 403", status, body)
	}

	// Still-valid certificate in the agent ⇒ host ACL denies after cache TTL.
	e.waitError(120*time.Second, "host acl revokes alice", func() error {
		_, err := e.ws(sshCmd("deploy", e.webFQDN, "true"))
		return err
	})
}

// testAudit: issuances (human + CI with pipeline mapping), enrollments, and
// grant changes are queryable and exportable via the admin API.
func (e *env) testAudit(t *testing.T) {
	token := e.adminToken()

	body, err := httpGet(e.apiPF.URL()+"/v1/admin/audit/export", token)
	if err != nil {
		t.Fatalf("audit-export: %v", err)
	}
	for _, want := range []string{
		"ca.cert_issued",                 // issuances (human + CI)
		"ci:platform/deploy:4711:815",    // CI issuance mapped to the pipeline
		"host.enrolled",                  // enrollment of both test hosts
		"grant.created", "grant.deleted", // grant change from scenario 02
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit-export missing %q", want)
		}
	}

	csv, err := httpGet(e.apiPF.URL()+"/v1/admin/audit/export?format=csv", token)
	if err != nil {
		t.Fatalf("audit-export csv: %v", err)
	}
	if !strings.HasPrefix(csv, "id,occurred_at,event_type,actor,payload") {
		t.Errorf("unexpected csv header: %q", strings.SplitN(csv, "\n", 2)[0])
	}

	// Issuances including principals are queryable via the resource view.
	certs, err := httpGet(e.apiPF.URL()+"/v1/admin/certificates", token)
	if err != nil {
		t.Fatalf("certificates: %v", err)
	}
	if !strings.Contains(certs, "alice") {
		t.Errorf("certificate list missing alice principal")
	}
}

// signUserStatus calls POST /v1/sign/user with a fresh key pair.
func (e *env) signUserStatus(idToken string) (int, string) {
	e.t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		e.t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	})
	req, err := http.NewRequest(http.MethodPost, e.apiPF.URL()+"/v1/sign/user", bytes.NewReader(payload))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("reaching sign/user: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// signCIStatus calls POST /v1/sign/ci with a fresh key pair.
func (e *env) signCIStatus(jobToken string) int {
	e.t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		e.t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	})
	req, err := http.NewRequest(http.MethodPost, e.apiPF.URL()+"/v1/sign/ci", bytes.NewReader(payload))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+jobToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("reaching sign/ci: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// hostKeyCallback verifies host certificates against the server's CA bundle
// (same pattern as the Phase 7 integration test).
func (e *env) hostKeyCallback(t *testing.T, hostname string) ssh.HostKeyCallback {
	t.Helper()
	bundle, err := httpGet(e.apiPF.URL()+"/v1/ca/bundle/host", "")
	if err != nil {
		t.Fatalf("host-ca-bundle: %v", err)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			marshaled := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(auth)))
			return strings.Contains(bundle, marshaled)
		},
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("not a host certificate: %T", key)
		}
		if !checker.IsHostAuthority(cert.SignatureKey, "") {
			return fmt.Errorf("host certificate from unknown ca")
		}
		return checker.CheckCert(hostname, cert)
	}
}

// goSSH connects using agent signers and runs a command.
func goSSH(addr, user string, signers []ssh.Signer, hostCB ssh.HostKeyCallback, command string) (string, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: hostCB,
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	out, err := session.CombinedOutput(command)
	return string(out), err
}
