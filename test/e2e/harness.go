//go:build e2e

// Package e2e enthält die End-to-End-Suite (Plan Phase 13): kind-Cluster,
// Helm-Deployment, Dex+GLAuth als IdP, simuliertes GitLab-OIDC und zwei
// sshd-Testhosts als Pods. Die Szenarien fahren den kompletten Durchstich
// Mensch (gssh login --device im Workstation-Pod) und CI (gssh ci-login +
// Ansible) und decken Offboarding, Grant-Änderung, Host-Rotation, Chaos
// (API down) und Audit-Vollständigkeit ab.
//
// Aufruf: make e2e (bzw. go test -tags e2e ./test/e2e). Benötigt Docker,
// kind, kubectl, helm; ansible optional (sonst Go-SSH-Fallback).
//
// Env-Schalter:
//
//	E2E_KEEP=1        Cluster nach dem Lauf stehen lassen (Debugging)
//	E2E_SKIP_BUILD=1  Docker-Builds überspringen (Images bereits geladen)
//	E2E_CLUSTER=name  kind-Cluster-Name (Default gssh-e2e)
package e2e

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// run führt ein Kommando aus und liefert kombinierte Ausgabe + Fehler.
func run(stdin, dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// kubectl führt kubectl im Cluster-Kontext und Test-Namespace aus.
func (e *env) kubectl(args ...string) (string, error) {
	full := append([]string{"--context", e.context(), "-n", e.ns}, args...)
	return run("", "", "kubectl", full...)
}

// mustKubectl wie kubectl, bricht den Test bei Fehlern ab.
func (e *env) mustKubectl(args ...string) string {
	e.t.Helper()
	out, err := e.kubectl(args...)
	if err != nil {
		e.t.Fatalf("kubectl: %v", err)
	}
	return out
}

// applyYAML wendet ein Manifest über stdin an.
func (e *env) applyYAML(yaml string) {
	e.t.Helper()
	full := []string{"--context", e.context(), "-n", e.ns, "apply", "-f", "-"}
	if out, err := run(yaml, "", "kubectl", full...); err != nil {
		e.t.Fatalf("kubectl apply: %v\n--- manifest ---\n%s\n--- output ---\n%s", err, yaml, out)
	}
}

// execPod führt ein Shell-Kommando in einem Pod/Deployment aus
// (target z. B. "deploy/testhost-web" oder ein Pod-Name).
func (e *env) execPod(target, command string) (string, error) {
	return e.kubectl("exec", target, "--", "sh", "-c", command)
}

// mustExecPod wie execPod, bricht bei Fehlern ab.
func (e *env) mustExecPod(target, command string) string {
	e.t.Helper()
	out, err := e.execPod(target, command)
	if err != nil {
		e.t.Fatalf("exec %s %q: %v", target, command, err)
	}
	return out
}

// ws führt ein Kommando im Workstation-Pod aus — mit ssh-agent-Socket und
// gssh-Konfiguration im Environment (der komplette "Mensch"-Pfad läuft dort).
func (e *env) ws(command string) (string, error) {
	return e.execPod("pod/workstation",
		"export SSH_AUTH_SOCK=/tmp/agent.sock GSSH_CONFIG=/etc/gssh/config.yaml HOME=/root; "+command)
}

// mustWS wie ws, bricht bei Fehlern ab.
func (e *env) mustWS(command string) string {
	e.t.Helper()
	out, err := e.ws(command)
	if err != nil {
		e.t.Fatalf("workstation %q: %v", command, err)
	}
	return out
}

// sshCmd baut das ssh-Kommando der Workstation gegen einen Testhost:
// striktes Host-Key-Checking gegen die CA (known_hosts mit @cert-authority).
func sshCmd(user, host, remote string) string {
	return fmt.Sprintf(
		"ssh -o UserKnownHostsFile=/root/known_hosts -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o BatchMode=yes %s@%s %q",
		user, host, remote)
}

// poll wiederholt fn bis Erfolg oder Timeout (Abbruch via t.Fatalf).
func (e *env) poll(timeout time.Duration, desc string, fn func() error) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = fn(); last == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	e.t.Fatalf("%s: timeout nach %s, letzter fehler: %v", desc, timeout, last)
}

// waitError wiederholt fn bis es FEHLSCHLÄGT (für fail-closed-Erwartungen).
func (e *env) waitError(timeout time.Duration, desc string, fn func() error) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := fn(); err != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	e.t.Fatalf("%s: schlägt nach %s immer noch nicht fehl", desc, timeout)
}

// portForward hält einen kubectl port-forward-Prozess und seinen lokalen Port.
type portForward struct {
	e      *env
	target string // z. B. svc/dex
	remote int
	local  int
	cmd    *exec.Cmd
}

var forwardRe = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

// portForward startet kubectl port-forward auf einen zufälligen lokalen Port.
func (e *env) portForward(target string, remote int) *portForward {
	e.t.Helper()
	pf := &portForward{e: e, target: target, remote: remote}
	pf.start()
	e.t.Cleanup(pf.stop)
	return pf
}

func (p *portForward) start() {
	p.e.t.Helper()
	cmd := exec.Command("kubectl", "--context", p.e.context(), "-n", p.e.ns,
		"port-forward", p.target, fmt.Sprintf(":%d", p.remote))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		p.e.t.Fatalf("port-forward pipe: %v", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		p.e.t.Fatalf("port-forward %s: %v", p.target, err)
	}
	portCh := make(chan int, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if m := forwardRe.FindStringSubmatch(scanner.Text()); m != nil {
				var port int
				fmt.Sscanf(m[1], "%d", &port)
				portCh <- port
				break
			}
		}
		// Restliche Ausgabe verwerfen, damit der Prozess nicht blockiert.
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case p.local = <-portCh:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		p.e.t.Fatalf("port-forward %s: kein lokaler port nach 30s", p.target)
	}
	p.cmd = cmd
}

func (p *portForward) stop() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
}

// restart beendet den Forward und startet ihn neu (nach Pod-Neustarts nötig —
// port-forward pinnt den Pod, der beim Start ausgewählt wurde).
func (p *portForward) restart() {
	p.stop()
	p.start()
}

// URL liefert die lokale Basis-URL des Forwards.
func (p *portForward) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", p.local)
}

// render ersetzt {{KEY}}-Platzhalter in einem Manifest-Template.
func render(template string, vars map[string]string) string {
	pairs := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(pairs...).Replace(template)
}

// envOrDefault liest eine Env-Variable mit Fallback.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// requireTools bricht ab, wenn ein benötigtes Werkzeug fehlt.
func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("benötigtes werkzeug fehlt: %s", tool)
		}
	}
}
