//go:build e2e

// Package e2e contains the end-to-end suite (plan Phase 13): kind cluster,
// Helm deployment, Dex+GLAuth as IdP, simulated GitLab OIDC, and two sshd
// test hosts as pods. The scenarios drive the complete path for humans
// (gssh login --device in the workstation pod) and CI (gssh ci-login +
// Ansible), and cover offboarding, grant changes, host rotation, chaos
// (API down), and audit completeness.
//
// Invocation: make e2e (or go test -tags e2e ./test/e2e). Requires Docker,
// kind, kubectl, helm; ansible is optional (otherwise falls back to Go-SSH).
//
// Env switches:
//
//	E2E_KEEP=1        keep the cluster running after the test (debugging)
//	E2E_SKIP_BUILD=1  skip Docker builds (images already loaded)
//	E2E_CLUSTER=name  kind cluster name (default gssh-e2e)
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

// run executes a command and returns combined output + error.
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

// kubectl runs kubectl in the cluster context and test namespace.
func (e *env) kubectl(args ...string) (string, error) {
	full := append([]string{"--context", e.context(), "-n", e.ns}, args...)
	return run("", "", "kubectl", full...)
}

// mustKubectl like kubectl, aborts the test on error.
func (e *env) mustKubectl(args ...string) string {
	e.t.Helper()
	out, err := e.kubectl(args...)
	if err != nil {
		e.t.Fatalf("kubectl: %v", err)
	}
	return out
}

// applyYAML applies a manifest via stdin.
func (e *env) applyYAML(yaml string) {
	e.t.Helper()
	full := []string{"--context", e.context(), "-n", e.ns, "apply", "-f", "-"}
	if out, err := run(yaml, "", "kubectl", full...); err != nil {
		e.t.Fatalf("kubectl apply: %v\n--- manifest ---\n%s\n--- output ---\n%s", err, yaml, out)
	}
}

// execPod runs a shell command in a pod/deployment (target e.g.
// "deploy/testhost-web" or a pod name).
func (e *env) execPod(target, command string) (string, error) {
	return e.kubectl("exec", target, "--", "sh", "-c", command)
}

// mustExecPod like execPod, aborts on error.
func (e *env) mustExecPod(target, command string) string {
	e.t.Helper()
	out, err := e.execPod(target, command)
	if err != nil {
		e.t.Fatalf("exec %s %q: %v", target, command, err)
	}
	return out
}

// ws runs a command in the workstation pod — with the ssh-agent socket and
// gssh configuration in the environment (the entire "human" path runs there).
func (e *env) ws(command string) (string, error) {
	return e.execPod("pod/workstation",
		"export SSH_AUTH_SOCK=/tmp/agent.sock GSSH_CONFIG=/etc/gssh/config.yaml HOME=/root; "+command)
}

// mustWS like ws, aborts on error.
func (e *env) mustWS(command string) string {
	e.t.Helper()
	out, err := e.ws(command)
	if err != nil {
		e.t.Fatalf("workstation %q: %v", command, err)
	}
	return out
}

// sshCmd builds the workstation's ssh command against a test host: strict
// host key checking against the CA (known_hosts with @cert-authority).
func sshCmd(user, host, remote string) string {
	return fmt.Sprintf(
		"ssh -o UserKnownHostsFile=/root/known_hosts -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o BatchMode=yes %s@%s %q",
		user, host, remote)
}

// poll retries fn until success or timeout (aborts via t.Fatalf).
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
	e.t.Fatalf("%s: timeout after %s, last error: %v", desc, timeout, last)
}

// waitError retries fn until it FAILS (for fail-closed expectations).
func (e *env) waitError(timeout time.Duration, desc string, fn func() error) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := fn(); err != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	e.t.Fatalf("%s: still not failing after %s", desc, timeout)
}

// portForward holds a kubectl port-forward process and its local port.
type portForward struct {
	e      *env
	target string // e.g. svc/dex
	remote int
	local  int
	cmd    *exec.Cmd
}

var forwardRe = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

// portForward starts kubectl port-forward on a random local port.
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
		// Discard remaining output so the process does not block.
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case p.local = <-portCh:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		p.e.t.Fatalf("port-forward %s: no local port after 30s", p.target)
	}
	p.cmd = cmd
}

func (p *portForward) stop() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
}

// restart stops the forward and starts it again (needed after pod restarts —
// port-forward pins the pod that was selected at start).
func (p *portForward) restart() {
	p.stop()
	p.start()
}

// URL returns the forward's local base URL.
func (p *portForward) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", p.local)
}

// render replaces {{KEY}} placeholders in a manifest template.
func render(template string, vars map[string]string) string {
	pairs := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(pairs...).Replace(template)
}

// envOrDefault reads an env variable with a fallback.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// requireTools aborts if a required tool is missing.
func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required tool missing: %s", tool)
		}
	}
}
