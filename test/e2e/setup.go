//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Feste Namen der E2E-Umgebung.
const (
	defaultCluster = "gssh-e2e"
	namespace      = "guided-ssh-e2e"

	serverImage      = "gssh-e2e-server:e2e"
	testhostImage    = "gssh-e2e-testhost:e2e"
	workstationImage = "gssh-e2e-workstation:e2e"

	alicePassword = "alice-password"
)

// env ist der geteilte Zustand der Szenarien.
type env struct {
	t        *testing.T
	tmp      string
	repoRoot string
	cluster  string
	ns       string

	gsshHost  string // gssh-Binary fürs Host-OS (ci-login)
	adminHost string // gssh-admin-Binary fürs Host-OS

	apiPF *portForward
	dexPF *portForward

	gitlab  *gitlabFake
	ansible bool

	webFQDN string
	dbFQDN  string
}

func (e *env) context() string { return "kind-" + e.cluster }

// runWithEnv führt ein Kommando mit zusätzlichen Env-Variablen aus.
func runWithEnv(extraEnv []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// setupEnv baut die komplette E2E-Umgebung auf (kind, Fakes, Helm-Release,
// Testhosts, Workstation) und liefert den geteilten Zustand.
func setupEnv(t *testing.T) *env {
	t.Helper()
	requireTools(t, "docker", "kind", "kubectl", "helm")

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		t:        t,
		tmp:      t.TempDir(),
		repoRoot: repoRoot,
		cluster:  envOrDefault("E2E_CLUSTER", defaultCluster),
		ns:       namespace,
	}
	e.webFQDN = "testhost-web." + e.ns + ".svc.cluster.local"
	e.dbFQDN = "testhost-db." + e.ns + ".svc.cluster.local"
	_, err = exec.LookPath("ansible-playbook")
	e.ansible = err == nil

	if os.Getenv("E2E_SKIP_BUILD") == "" {
		e.buildArtifacts()
	} else {
		e.hostBinaries() // Host-Binaries sind billig und immer aktuell nötig
	}
	e.ensureCluster()
	e.loadImages()
	e.deployInfra()
	e.deployServer()
	e.apiPF = e.portForward("svc/guided-ssh", 80)
	e.dexPF = e.portForward("svc/dex", 5556)
	e.waitHealthy()
	e.adminApply(grantsBase)
	e.setupTesthost("testhost-web", e.webFQDN, "role=web,env=e2e")
	e.setupTesthost("testhost-db", e.dbFQDN, "role=db,env=e2e")
	e.setupWorkstation()
	return e
}

// hostBinaries baut gssh und gssh-admin fürs Host-OS (Treiber der Suite).
func (e *env) hostBinaries() {
	e.t.Helper()
	bin := filepath.Join(e.tmp, "bin")
	e.gsshHost = filepath.Join(bin, "gssh")
	e.adminHost = filepath.Join(bin, "gssh-admin")
	e.goBuild(e.gsshHost, "./cmd/gssh", nil)
	e.goBuild(e.adminHost, "./cmd/gssh-admin", nil)
}

// buildArtifacts baut alle Binaries und Docker-Images und lädt sie später
// via kind in den Cluster.
func (e *env) buildArtifacts() {
	e.t.Helper()
	e.hostBinaries()

	linuxEnv := []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + runtime.GOARCH}

	testhostCtx := filepath.Join(e.tmp, "testhost")
	e.copyTestdata("testdata/testhost", testhostCtx)
	e.goBuild(filepath.Join(testhostCtx, "gssh-agentd"), "./cmd/gssh-agentd", linuxEnv)
	e.dockerBuild(testhostImage, testhostCtx, nil)

	wsCtx := filepath.Join(e.tmp, "workstation")
	e.copyTestdata("testdata/workstation", wsCtx)
	e.goBuild(filepath.Join(wsCtx, "gssh"), "./cmd/gssh", linuxEnv)
	e.dockerBuild(workstationImage, wsCtx, nil)

	// Server-Image über das produktive Dockerfile (inkl. Web-UI-Build).
	e.dockerBuild(serverImage, e.repoRoot, []string{"--build-arg", "VERSION=e2e"})
}

func (e *env) goBuild(out, pkg string, extraEnv []string) {
	e.t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = e.repoRoot
	cmd.Env = append(os.Environ(), extraEnv...)
	if raw, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("go build %s: %v\n%s", pkg, err, raw)
	}
}

func (e *env) dockerBuild(tag, dir string, extraArgs []string) {
	e.t.Helper()
	args := append([]string{"build", "-t", tag}, extraArgs...)
	args = append(args, dir)
	if out, err := run("", "", "docker", args...); err != nil {
		e.t.Fatalf("docker build %s: %v\n%s", tag, err, out)
	}
}

func (e *env) copyTestdata(src, dst string) {
	e.t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		e.t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(src, entry.Name()))
		if err != nil {
			e.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, entry.Name()), raw, 0o644); err != nil {
			e.t.Fatal(err)
		}
	}
}

// ensureCluster legt den kind-Cluster an (bzw. nutzt einen vorhandenen) und
// registriert das Aufräumen (E2E_KEEP=1 lässt ihn stehen).
func (e *env) ensureCluster() {
	e.t.Helper()
	out, err := run("", "", "kind", "get", "clusters")
	if err != nil {
		e.t.Fatalf("kind get clusters: %v", err)
	}
	exists := false
	for _, line := range strings.Fields(out) {
		if line == e.cluster {
			exists = true
		}
	}
	e.t.Cleanup(func() {
		if os.Getenv("E2E_KEEP") != "" {
			e.t.Logf("E2E_KEEP gesetzt — cluster %s bleibt stehen", e.cluster)
			return
		}
		_, _ = run("", "", "kind", "delete", "cluster", "--name", e.cluster)
	})
	if exists {
		return
	}
	if out, err := run("", "", "kind", "create", "cluster", "--name", e.cluster, "--wait", "120s"); err != nil {
		e.t.Fatalf("kind create cluster: %v\n%s", err, out)
	}
}

func (e *env) loadImages() {
	e.t.Helper()
	if out, err := run("", "", "kind", "load", "docker-image", "--name", e.cluster,
		serverImage, testhostImage, workstationImage); err != nil {
		e.t.Fatalf("kind load (E2E_SKIP_BUILD gesetzt, aber images fehlen lokal?): %v\n%s", err, out)
	}
}

// applyConfigMap erzeugt/aktualisiert eine ConfigMap aus Datei-Inhalten.
func (e *env) applyConfigMap(name string, files map[string]string) {
	e.t.Helper()
	dir := filepath.Join(e.tmp, "cm-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	args := []string{"create", "configmap", name, "--dry-run=client", "-o", "yaml"}
	for fname, content := range files {
		path := filepath.Join(dir, fname)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			e.t.Fatal(err)
		}
		args = append(args, "--from-file="+fname+"="+path)
	}
	manifest := e.mustKubectl(args...)
	e.applyYAML(manifest)
}

// deployInfra bringt Namespace, Postgres, GLAuth, Dex, das simulierte
// GitLab-OIDC und das Pflicht-Secret in den Cluster.
func (e *env) deployInfra() {
	e.t.Helper()
	e.applyYAML("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + e.ns + "\n")

	vars := map[string]string{"NS": e.ns}

	// Simuliertes GitLab-OIDC: Schlüssel gehört der Suite, Discovery+JWKS
	// liegen als statisches JSON hinter nginx.
	gitlab, err := newGitLabFake("http://gitlab-fake." + e.ns + ".svc.cluster.local")
	if err != nil {
		e.t.Fatal(err)
	}
	e.gitlab = gitlab
	e.applyConfigMap("gitlab-fake", map[string]string{
		"default.conf":   gitlabFakeNginx,
		"discovery.json": gitlab.discoveryJSON(),
		"jwks.json":      gitlab.jwksJSON(),
	})
	e.applyConfigMap("glauth-config", map[string]string{
		"config.cfg": render(glauthConfig, map[string]string{"ALICE_OTHERGROUPS": "5501, 5502"}),
	})
	e.applyConfigMap("dex-config", map[string]string{
		"config.yaml": render(dexConfig, vars),
	})
	e.applyYAML(postgresYAML)
	e.applyYAML(glauthYAML)
	e.applyYAML(render(dexYAML, vars))
	e.applyYAML(gitlabFakeYAML)

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		e.t.Fatal(err)
	}
	// Postgres-Zugang als einzelne Keys (kein DSN) — dieselbe Struktur, die
	// das Chart per secrets.db.keys erwartet; ca-master-key liegt im selben
	// Secret (secrets.db und secrets.ca dürfen auf dasselbe Secret zeigen).
	secret := e.mustKubectl("create", "secret", "generic", "guided-ssh-e2e",
		"--from-literal=host=postgres."+e.ns+".svc.cluster.local",
		"--from-literal=port=5432",
		"--from-literal=username=gssh",
		"--from-literal=password=gssh-e2e-pw",
		"--from-literal=database=gssh",
		"--from-literal=sslmode=disable",
		"--from-literal=ca-master-key="+base64.StdEncoding.EncodeToString(masterKey),
		"--dry-run=client", "-o", "yaml")
	e.applyYAML(secret)

	for _, deploy := range []string{"postgres", "glauth", "dex", "gitlab-fake"} {
		e.mustKubectl("rollout", "status", "deploy/"+deploy, "--timeout=300s")
	}
}

// deployServer installiert das produktive Helm-Chart mit E2E-Werten.
func (e *env) deployServer() {
	e.t.Helper()
	chart := filepath.Join(e.repoRoot, "deploy/helm/guided-ssh")
	// charts/ ist nicht eingecheckt (.gitignore); das postgresql-Subchart muss
	// gemäß Chart.lock nachgeladen werden, sonst scheitert der Install.
	if out, err := run("", "", "helm", "dependency", "build", chart); err != nil {
		e.t.Fatalf("helm dependency build: %v\n%s", err, out)
	}
	values := filepath.Join(e.tmp, "values-e2e.yaml")
	if err := os.WriteFile(values, []byte(render(helmValues, map[string]string{"NS": e.ns})), 0o644); err != nil {
		e.t.Fatal(err)
	}
	out, err := run("", "", "helm", "--kube-context", e.context(),
		"upgrade", "--install", "guided-ssh", chart,
		"-n", e.ns, "-f", values, "--wait", "--timeout", "5m")
	if err != nil {
		e.t.Fatalf("helm install: %v\n%s", err, out)
	}
}

func (e *env) waitHealthy() {
	e.t.Helper()
	e.poll(60*time.Second, "healthz", func() error {
		_, err := httpGet(e.apiPF.URL()+"/healthz", "")
		return err
	})
}

// adminToken holt ein frisches ID-Token für alice (Gruppe admins) per
// Password-Grant über den Dex-Port-Forward.
func (e *env) adminToken() string {
	e.t.Helper()
	var token string
	e.poll(120*time.Second, "admin-token via dex", func() error {
		var err error
		token, err = passwordGrant(e.dexPF.URL(), "alice", alicePassword)
		return err
	})
	return token
}

// adminApply gleicht die Zugriffsregeln deklarativ ab (gssh-admin apply).
func (e *env) adminApply(grantsYAML string) {
	e.t.Helper()
	cfg := filepath.Join(e.tmp, "gssh-host-config.yaml")
	content := "api_url: " + e.apiPF.URL() + "\n" +
		"issuer: http://dex." + e.ns + ".svc.cluster.local:5556/dex\n" +
		"client_id: gssh-cli\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		e.t.Fatal(err)
	}
	grantsPath := filepath.Join(e.tmp, "grants.yaml")
	if err := os.WriteFile(grantsPath, []byte(grantsYAML), 0o600); err != nil {
		e.t.Fatal(err)
	}
	token := e.adminToken()
	out, err := runWithEnv([]string{"GSSH_ID_TOKEN=" + token},
		e.adminHost, "apply", "--config", cfg, "-f", grantsPath)
	if err != nil {
		e.t.Fatalf("gssh-admin apply: %v\n%s", err, out)
	}
	e.t.Logf("gssh-admin apply:\n%s", out)
}

// setupTesthost deployt einen sshd-Testhost, enrollt ihn über die echte API
// und dreht die Agent-Intervalle E2E-tauglich (Cache 30s, Renew-Check 10s).
func (e *env) setupTesthost(name, fqdn, tags string) {
	e.t.Helper()
	e.applyYAML(render(testhostYAML, map[string]string{"NAME": name}))
	e.mustKubectl("rollout", "status", "deploy/"+name, "--timeout=180s")

	// Einmal-Token über das Server-Binary im Pod (distroless — kein sh).
	out := e.mustKubectl("exec", "deploy/guided-ssh", "--",
		"/usr/local/bin/gssh-server", "enroll-token", "-name", fqdn, "-tags", tags, "-ttl", "1h")
	token := ""
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "gssh-et-") {
			token = field
		}
	}
	if token == "" {
		e.t.Fatalf("kein enroll-token in ausgabe: %s", out)
	}

	e.mustKubectl("exec", "deploy/"+name, "--",
		"/usr/local/bin/gssh-agentd", "enroll",
		"--server", "http://guided-ssh."+e.ns+".svc.cluster.local",
		"--agent-url", "https://guided-ssh-agent."+e.ns+".svc.cluster.local:8443",
		"--token", token,
		"--hostname", fqdn)

	// Agent-Konfiguration für E2E-Zeitmaße anpassen, dann den Entrypoint
	// weiterlaufen lassen (startet agentd + sshd).
	e.mustExecPod("deploy/"+name,
		"sed -i 's/^cache_ttl:.*/cache_ttl: 30s/; s/^renew_interval:.*/renew_interval: 10s/' /var/lib/guided-ssh/config.yaml"+
			" && printf 'reload_command: kill -HUP 1\\n' >> /var/lib/guided-ssh/config.yaml"+
			" && touch /var/lib/guided-ssh/.e2e-ready")
	e.poll(60*time.Second, name+" sshd", func() error {
		logs, err := e.kubectl("logs", "deploy/"+name)
		if err != nil {
			return err
		}
		if !strings.Contains(logs, "starte sshd") {
			return fmt.Errorf("sshd noch nicht gestartet")
		}
		return nil
	})
}

// setupWorkstation startet den "Mensch"-Pod und hinterlegt das
// CA-verankerte known_hosts (@cert-authority) für striktes Host-Checking.
func (e *env) setupWorkstation() {
	e.t.Helper()
	e.applyConfigMap("gssh-config", map[string]string{
		"config.yaml": render(gsshConfig, map[string]string{"NS": e.ns}),
	})
	e.applyYAML(workstationYAML)
	e.mustKubectl("wait", "--for=condition=Ready", "pod/workstation", "--timeout=180s")

	bundle, err := httpGet(e.apiPF.URL()+"/v1/ca/bundle/host", "")
	if err != nil {
		e.t.Fatalf("host-ca-bundle: %v", err)
	}
	var knownHosts strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(bundle), "\n") {
		if strings.TrimSpace(line) != "" {
			knownHosts.WriteString("@cert-authority * " + line + "\n")
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(knownHosts.String()))
	e.mustExecPod("pod/workstation", "echo "+encoded+" | base64 -d > /root/known_hosts")
}

// httpGet holt eine URL (optional mit Bearer-Token) und liefert den Body.
func httpGet(url, bearer string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return string(body), fmt.Errorf("GET %s: %s: %s", url, resp.Status, body)
	}
	return string(body), nil
}
