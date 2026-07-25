package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/ca"
)

// writeTestSSHCAKey writes an unencrypted OpenSSH ed25519 key — what an operator
// produces with ssh-keygen and an empty passphrase for the SSH CAs.
func writeTestSSHCAKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "guided-ssh test")
	if err != nil {
		t.Fatalf("marshal openssh key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
}

// TestRunGenMTLSCA: the helper writes a usable mTLS CA, and the real contract is
// that its output loads through the self-managed key loader unchanged.
func TestRunGenMTLSCA(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "mtls-ca")

	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"gen-mtls-ca", "-out", prefix}); got != 0 {
		t.Fatalf("gen-mtls-ca = %d, want 0 (stderr: %s)", got, stderr.String())
	}

	keyPath, certPath := prefix+".key", prefix+".crt"
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %04o, want 0600 (ca private key)", perm)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("certificate file: %v", err)
	}
	if !strings.Contains(stdout.String(), keyPath) || !strings.Contains(stdout.String(), certPath) {
		t.Errorf("stdout %q does not name both output files", stdout.String())
	}

	userPath, hostPath := filepath.Join(dir, "user-ca"), filepath.Join(dir, "host-ca")
	writeTestSSHCAKey(t, userPath)
	writeTestSSHCAKey(t, hostPath)
	keys, err := ca.LoadExternalKeys(ca.ExternalKeyPaths{
		UserKeyFile:  userPath,
		HostKeyFile:  hostPath,
		MTLSKeyFile:  keyPath,
		MTLSCertFile: certPath,
	})
	if err != nil {
		t.Fatalf("generated material does not load in self-managed mode: %v", err)
	}
	if !keys.MTLS.Certificate.IsCA {
		t.Error("generated certificate is not a ca certificate")
	}
}

// TestRunGenMTLSCARefusesOverwrite: re-running the helper must never replace a
// CA that hosts already trust.
func TestRunGenMTLSCARefusesOverwrite(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "mtls-ca")
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"gen-mtls-ca", "-out", prefix}); got != 0 {
		t.Fatalf("gen-mtls-ca = %d, want 0 (stderr: %s)", got, stderr.String())
	}
	before, err := os.ReadFile(prefix + ".key")
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if got := run(&stdout, &stderr, []string{"gen-mtls-ca", "-out", prefix}); got != 1 {
		t.Fatalf("second gen-mtls-ca = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Errorf("stderr %q does not explain the refusal", stderr.String())
	}
	after, err := os.ReadFile(prefix + ".key")
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("existing ca key was overwritten")
	}
}

// TestRunGenMTLSCALeavesNoOrphanKey: if only the certificate exists, the freshly
// written key must not be left behind — a key without its certificate is useless
// and would look like valid CA material in the secret.
func TestRunGenMTLSCALeavesNoOrphanKey(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "mtls-ca")
	if err := os.WriteFile(prefix+".crt", []byte("existing certificate\n"), 0o600); err != nil {
		t.Fatalf("prepare certificate: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"gen-mtls-ca", "-out", prefix}); got != 1 {
		t.Fatalf("gen-mtls-ca = %d, want 1 (stderr: %s)", got, stderr.String())
	}
	if _, err := os.Stat(prefix + ".key"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("orphaned key file left behind: %v", err)
	}
}

// TestRunGenMTLSCAWithoutOut: a missing -out is a usage error (exit code 2).
func TestRunGenMTLSCAWithoutOut(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"gen-mtls-ca"}); got != 2 {
		t.Fatalf("gen-mtls-ca without -out = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "-out") {
		t.Errorf("stderr %q does not mention -out", stderr.String())
	}
}

// TestRunGenMTLSCAUnknownFlag: unparsable flags are usage errors too.
func TestRunGenMTLSCAUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"gen-mtls-ca", "-nope"}); got != 2 {
		t.Fatalf("gen-mtls-ca -nope = %d, want 2", got)
	}
}
