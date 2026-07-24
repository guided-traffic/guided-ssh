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

// TestE2E fährt die Szenarien des Plans (Phase 13) in fester Reihenfolge auf
// einer gemeinsamen Umgebung: SSO-Login, Grant-Änderung, CI-Zertifikat +
// Ansible, Host-Rotation, Chaos (API down), Offboarding, Audit sowie die
// interne Test-Datenbank (Postgres-Sidecar, eigenes Helm-Release).
// Session-/sudo-Audit-Events sind hier bewusst nicht abgedeckt (Opt-in-Feature,
// PAM-Verhalten ist in den Phase-9-Tests verifiziert).
func TestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e übersprungen (-short)")
	}
	e := setupEnv(t)

	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.Fatalf("szenario %s fehlgeschlagen — folge-szenarien bauen darauf auf", name)
		}
	}
	step("01_SSO_Login_DeviceFlow", e.testSSOLogin)
	step("02_Grant_Aenderung", e.testGrantChange)
	step("03_CI_Zertifikat_Ansible", e.testCIProvisioning)
	step("04_Host_Rotation", e.testHostRotation)
	step("05_Chaos_API_Down", e.testChaos)
	step("06_Offboarding", e.testOffboarding)
	step("07_Audit_Vollstaendigkeit", e.testAudit)
	step("08_Interne_Datenbank", e.testInternalDatabase)
}

// testInternalDatabase: internalDatabase.enabled — zweites Helm-Release im
// selben Namespace, Postgres läuft als nativer Sidecar im Server-Pod, ohne
// DB-Secret. Geprüft wird der komplette Pfad Sidecar → Migrationen → Server
// healthy → CA gebootstrapt, die Ephemeralität (Pod-Neustart ⇒ leere
// Datenbank ⇒ NEUE CA — deshalb nur für Tests) und der Render-Guard gegen
// ein gleichzeitig gesetztes DB-Secret.
func (e *env) testInternalDatabase(t *testing.T) {
	chart := filepath.Join(e.repoRoot, "deploy/helm/guided-ssh")
	// Release-Name enthält den Chart-Namen ⇒ fullname == Release-Name.
	const release = "guided-ssh-internal"

	// CA-Secret — das einzige Pflicht-Secret bei interner Datenbank.
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
		t.Fatalf("helm install (interne datenbank): %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = run("", "", "helm", "--kube-context", e.context(), "uninstall", release, "-n", e.ns)
	})

	pf := e.portForward("svc/"+release, 80)
	e.poll(60*time.Second, "healthz (interne datenbank)", func() error {
		_, err := httpGet(pf.URL()+"/healthz", "")
		return err
	})
	bundleBefore, err := httpGet(pf.URL()+"/v1/ca/bundle/user", "")
	if err != nil {
		t.Fatalf("ca-bundle: %v", err)
	}
	if !strings.Contains(bundleBefore, "ssh-") {
		t.Fatalf("ca-bundle ohne ssh-key: %q", bundleBefore)
	}

	// Ephemeralität: Pod löschen ⇒ emptyDir weg ⇒ frische Datenbank ⇒ der
	// Server bootstrapt eine NEUE CA. Bleibt das Bundle identisch, ist die
	// Datenbank nicht pod-lokal (Persistenz oder falsche Verbindung).
	e.mustKubectl("delete", "pod", "-l", "app.kubernetes.io/instance="+release, "--wait=true")
	e.mustKubectl("rollout", "status", "deploy/"+release, "--timeout=300s")
	pf.restart()
	e.poll(60*time.Second, "healthz nach pod-neustart", func() error {
		_, err := httpGet(pf.URL()+"/healthz", "")
		return err
	})
	bundleAfter, err := httpGet(pf.URL()+"/v1/ca/bundle/user", "")
	if err != nil {
		t.Fatalf("ca-bundle nach neustart: %v", err)
	}
	if bundleAfter == bundleBefore {
		t.Error("ca-bundle nach pod-neustart unverändert — interne datenbank ist nicht ephemeral")
	}

	// Guard: internalDatabase + DB-Secret gleichzeitig ⇒ Render-Fehler mit
	// klarer Meldung (Schutz vor versehentlicher Test-Datenbank).
	out, err = run("", "", "helm", "template", release, chart,
		"-f", values, "--set", "secrets.db.existingSecret=darf-nicht-sein")
	if err == nil {
		t.Fatal("helm template mit internalDatabase + db-secret muss fehlschlagen")
	}
	if !strings.Contains(out, "schließen sich gegenseitig aus") {
		t.Errorf("guard-fehlermeldung unerwartet: %q", out)
	}
}

// startWS startet ein Workstation-Kommando asynchron (für Device-Flow und
// langlaufende SSH-Sessions).
func (e *env) startWS(command string) *exec.Cmd {
	return exec.Command("kubectl", "--context", e.context(), "-n", e.ns,
		"exec", "pod/workstation", "--", "sh", "-c",
		"export SSH_AUTH_SOCK=/tmp/agent.sock GSSH_CONFIG=/etc/gssh/config.yaml HOME=/root; "+command)
}

// testSSOLogin: kompletter Mensch-Durchstich — gssh login --device im
// Workstation-Pod, Suite "klickt" den Dex-Device-Flow (LDAP-Login alice),
// danach transparentes ssh mit striktem Host-Zertifikats-Check.
func (e *env) testSSOLogin(t *testing.T) {
	login := e.startWS("gssh login --device")
	stderr, err := login.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	login.Stdout = &stdout
	if err := login.Start(); err != nil {
		t.Fatalf("gssh login starten: %v", err)
	}

	type prompt struct{ uri, code string }
	promptCh := make(chan prompt, 1)
	var stderrLog bytes.Buffer
	go func() {
		var p prompt
		scanner := bufio.NewScanner(io.TeeReader(stderr, &stderrLog))
		for scanner.Scan() {
			line := scanner.Text()
			if rest, ok := strings.CutPrefix(line, "im browser öffnen: "); ok {
				p.uri = strings.TrimSpace(rest)
			}
			if rest, ok := strings.CutPrefix(line, "code eingeben: "); ok {
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
		t.Fatalf("device-flow-prompt nicht erschienen; stderr:\n%s", stderrLog.String())
	}
	t.Logf("device-flow: %s (code %s)", p.uri, p.code)
	if err := approveDeviceFlow(e.dexPF.URL(), p.uri, p.code, "alice", alicePassword); err != nil {
		t.Fatalf("device-flow bestätigen: %v", err)
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
		t.Fatalf("gssh login hängt; stderr:\n%s", stderrLog.String())
	}
	if !strings.Contains(stdout.String(), "angemeldet:") {
		t.Fatalf("login-ausgabe unerwartet: %s", stdout.String())
	}

	// Zertifikat liegt nur im Agenten; status bestätigt Gültigkeit.
	e.mustWS("gssh status")

	// SSH als deploy auf role=web (Grant dev×web), Host-Cert CA-verifiziert.
	if out := strings.TrimSpace(e.mustWS(sshCmd("deploy", e.webFQDN, "whoami"))); out != "deploy" {
		t.Fatalf("whoami = %q, erwartet deploy", out)
	}
	// root: kein Grant ⇒ fail-closed.
	if _, err := e.ws(sshCmd("root", e.webFQDN, "true")); err == nil {
		t.Fatal("login als root muss scheitern (kein grant)")
	}
	// db-Host: noch kein Grant für role=db ⇒ fail-closed.
	if _, err := e.ws(sshCmd("deploy", e.dbFQDN, "true")); err == nil {
		t.Fatal("login auf db-host muss scheitern (kein grant für role=db)")
	}
}

// testGrantChange: Grant deklarativ ergänzen (role=db) → Zugriff kommt;
// zurücknehmen → Zugriff geht (jeweils innerhalb der Cache-TTL des Agenten).
func (e *env) testGrantChange(t *testing.T) {
	e.adminApply(grantsWithDB)
	e.poll(120*time.Second, "neuer grant wirkt auf db-host", func() error {
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
	e.waitError(120*time.Second, "grant-entzug wirkt auf db-host", func() error {
		_, err := e.ws(sshCmd("deploy", e.dbFQDN, "true"))
		return err
	})
}

// testCIProvisioning: simuliertes GitLab-Job-Token → gssh ci-login (echtes
// Binary, lokaler ssh-agent) → Ansible provisioniert den Testhost über den
// Agenten; Negativfälle unprotected ref. Go-SSH verifiziert das Ergebnis.
func (e *env) testCIProvisioning(t *testing.T) {
	// In-Process ssh-agent als Unix-Socket für gssh ci-login und Ansible.
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

	// Zertifikat im Agenten: KeyID ordnet Pipeline und Job zu.
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
		t.Fatalf("kein ci-zertifikat mit erwarteter keyid im agenten (%d schlüssel)", len(keys))
	}

	// Unprotected Ref ⇒ 403 (Grant verlangt protected_only).
	badToken, err := e.gitlab.jobToken(map[string]any{"ref_protected": "false"})
	if err != nil {
		t.Fatal(err)
	}
	if status := e.signCIStatus(badToken); status != http.StatusForbidden {
		t.Errorf("unprotected ref: status %d, erwartet 403", status)
	}

	// SSH-Zugang zum Testhost über Port-Forward.
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
    - name: erreichbarkeit
      ansible.builtin.ping:
    - name: provisionierungs-marker schreiben
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
			t.Fatalf("ansible-playbook mit fehlern:\n%s", out)
		}
		if got, err := goSSH(addr, "deploy", signers, hostCB, "cat /tmp/e2e-provisioned"); err != nil ||
			!strings.Contains(got, "provisioned-by-ansible") {
			t.Fatalf("provisionierungs-marker fehlt: %v %q", err, got)
		}
	} else {
		t.Log("ansible-playbook nicht installiert — go-ssh deckt den zertifikatspfad ab")
	}

	// Der Zertifikatspfad selbst (immer, auch ohne Ansible).
	if got, err := goSSH(addr, "deploy", signers, hostCB, "whoami"); err != nil || strings.TrimSpace(got) != "deploy" {
		t.Fatalf("ci-ssh whoami: %v %q", err, got)
	}
}

// testHostRotation: kurze Host-Zertifikatslaufzeit (3m via
// GSSH_HOST_CERT_VALIDITY) ⇒ der Daemon rotiert bei 2/3 Laufzeit; sshd wird
// per reload_command neu geladen und Logins funktionieren weiter.
func (e *env) testHostRotation(t *testing.T) {
	serialOf := func() (uint64, *ssh.Certificate, error) {
		out, err := e.execPod("deploy/testhost-web", "cat /etc/ssh/ssh_host_ed25519_key-cert.pub")
		if err != nil {
			return 0, nil, err
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out))
		if err != nil {
			return 0, nil, fmt.Errorf("host-zertifikat parsen: %w", err)
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			return 0, nil, fmt.Errorf("kein zertifikat: %T", parsed)
		}
		return cert.Serial, cert, nil
	}

	before, _, err := serialOf()
	if err != nil {
		t.Fatal(err)
	}
	var rotated *ssh.Certificate
	e.poll(4*time.Minute, "host-zertifikat rotiert", func() error {
		serial, cert, err := serialOf()
		if err != nil {
			return err
		}
		if serial == before {
			return fmt.Errorf("serial unverändert (%d)", serial)
		}
		rotated = cert
		return nil
	})
	if lifetime := time.Duration(rotated.ValidBefore-rotated.ValidAfter) * time.Second; lifetime != 3*time.Minute {
		t.Errorf("laufzeit des rotierten zertifikats = %s, erwartet 3m", lifetime)
	}
	// sshd hat das neue Zertifikat geladen (reload_command) — Login läuft weiter.
	if out := strings.TrimSpace(e.mustWS(sshCmd("deploy", e.webFQDN, "whoami"))); out != "deploy" {
		t.Fatalf("whoami nach rotation = %q", out)
	}
}

// testChaos: API weg ⇒ bestehende SSH-Session lebt weiter, der Agent-Cache
// trägt neue Logins bis zur TTL (30s), danach fail-closed; nach Wiederanlauf
// funktioniert alles wieder.
func (e *env) testChaos(t *testing.T) {
	// Langlaufende Session VOR dem Ausfall öffnen.
	session := e.startWS(sshCmd("deploy", e.webFQDN, "sleep 45; echo SESSION_ALIVE"))
	var sessionOut bytes.Buffer
	session.Stdout = &sessionOut
	session.Stderr = &sessionOut
	if err := session.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)

	e.mustKubectl("scale", "deployment/guided-ssh", "--replicas=0")
	e.poll(60*time.Second, "api-pods beendet", func() error {
		out, err := e.kubectl("get", "pods", "-l", "app.kubernetes.io/instance=guided-ssh", "-o", "name")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "" {
			return fmt.Errorf("pods noch da: %s", out)
		}
		return nil
	})
	downSince := time.Now()

	// Cache trägt Logins bis zur TTL.
	if out, err := e.ws(sshCmd("deploy", e.webFQDN, "whoami")); err != nil || !strings.Contains(out, "deploy") {
		t.Fatalf("login aus agent-cache bei api-ausfall: %v %q", err, out)
	}

	// TTL (30s) ablaufen lassen ⇒ fail-closed.
	if wait := 40*time.Second - time.Since(downSince); wait > 0 {
		time.Sleep(wait)
	}
	if _, err := e.ws(sshCmd("deploy", e.webFQDN, "true")); err == nil {
		t.Fatal("login muss nach ablauf der cache-ttl scheitern (fail-closed)")
	}

	// Die bestehende Session hat den kompletten Ausfall überlebt.
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		if err != nil || !strings.Contains(sessionOut.String(), "SESSION_ALIVE") {
			t.Fatalf("bestehende session hat den api-ausfall nicht überlebt: %v\n%s", err, sessionOut.String())
		}
	case <-time.After(60 * time.Second):
		_ = session.Process.Kill()
		t.Fatalf("session hängt:\n%s", sessionOut.String())
	}

	// Wiederanlauf: API hoch, Port-Forward neu (alter Pod ist weg), Login ok.
	e.mustKubectl("scale", "deployment/guided-ssh", "--replicas=1")
	e.mustKubectl("rollout", "status", "deploy/guided-ssh", "--timeout=180s")
	e.apiPF.restart()
	e.waitHealthy()
	e.poll(120*time.Second, "login nach api-wiederanlauf", func() error {
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

// testOffboarding: alice verliert die IdP-Gruppe dev ⇒ keine neue Ausstellung
// (403) und die Host-ACL verweigert das noch gültige Zertifikat innerhalb der
// Cache-TTL — der Offboarding-Pfad der Erfolgskriterien.
func (e *env) testOffboarding(t *testing.T) {
	e.applyConfigMap("glauth-config", map[string]string{
		"config.cfg": render(glauthConfig, map[string]string{"ALICE_OTHERGROUPS": "5501"}),
	})
	e.mustKubectl("rollout", "restart", "deploy/glauth")
	e.mustKubectl("rollout", "status", "deploy/glauth", "--timeout=120s")

	var freshToken string
	e.poll(120*time.Second, "frisches token ohne dev-gruppe", func() error {
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
				return fmt.Errorf("token enthält noch dev: %v", groups)
			}
		}
		freshToken = token
		return nil
	})

	// Keine neue Ausstellung; der Versuch aktualisiert zugleich die
	// DB-Gruppen aus den Token-Claims (Offboarding ohne Admin-API-Sync).
	if status, body := e.signUserStatus(freshToken); status != http.StatusForbidden {
		t.Fatalf("sign nach gruppen-entzug: status %d (%s), erwartet 403", status, body)
	}

	// Noch gültiges Zertifikat im Agenten ⇒ Host-ACL verweigert nach Cache-TTL.
	e.waitError(120*time.Second, "host-acl entzieht alice", func() error {
		_, err := e.ws(sshCmd("deploy", e.webFQDN, "true"))
		return err
	})
}

// testAudit: Ausstellungen (Mensch + CI mit Pipeline-Zuordnung), Enrollments
// und Grant-Änderungen sind über die Admin-API abfragbar und exportierbar.
func (e *env) testAudit(t *testing.T) {
	token := e.adminToken()

	body, err := httpGet(e.apiPF.URL()+"/v1/admin/audit/export", token)
	if err != nil {
		t.Fatalf("audit-export: %v", err)
	}
	for _, want := range []string{
		"ca.cert_issued",                // Ausstellungen (Mensch + CI)
		"ci:platform/deploy:4711:815",   // CI-Ausstellung der Pipeline zugeordnet
		"host.enrolled",                 // Enrollment beider Testhosts
		"grant.created", "grant.deleted", // Grant-Änderung aus Szenario 02
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit-export ohne %q", want)
		}
	}

	csv, err := httpGet(e.apiPF.URL()+"/v1/admin/audit/export?format=csv", token)
	if err != nil {
		t.Fatalf("audit-export csv: %v", err)
	}
	if !strings.HasPrefix(csv, "id,occurred_at,event_type,actor,payload") {
		t.Errorf("csv-header unerwartet: %q", strings.SplitN(csv, "\n", 2)[0])
	}

	// Ausstellungen inkl. Principals sind über die Ressourcen-Ansicht abfragbar.
	certs, err := httpGet(e.apiPF.URL()+"/v1/admin/certificates", token)
	if err != nil {
		t.Fatalf("certificates: %v", err)
	}
	if !strings.Contains(certs, "alice") {
		t.Errorf("zertifikatsliste ohne alice-principal")
	}
}

// signUserStatus ruft POST /v1/sign/user mit frischem Schlüsselpaar auf.
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
		e.t.Fatalf("sign/user erreichen: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// signCIStatus ruft POST /v1/sign/ci mit frischem Schlüsselpaar auf.
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
		e.t.Fatalf("sign/ci erreichen: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// hostKeyCallback verifiziert Host-Zertifikate gegen das CA-Bundle des Servers
// (gleiches Muster wie der Phase-7-Integrationstest).
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
			return fmt.Errorf("kein host-zertifikat: %T", key)
		}
		if !checker.IsHostAuthority(cert.SignatureKey, "") {
			return fmt.Errorf("host-zertifikat von unbekannter ca")
		}
		return checker.CheckCert(hostname, cert)
	}
}

// goSSH verbindet sich mit Agent-Signern und führt ein Kommando aus.
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
