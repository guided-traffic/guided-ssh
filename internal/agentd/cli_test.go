package agentd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeTestHostKey writes an ssh host public key and returns the path;
// without it enrollment would fail before the request is even made.
func writeTestHostKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestEnrollRequirePin: --require-pin (or GSSH_ENROLL_REQUIRE_PIN) aborts
// without --pin before any request goes out — the token stays unused.
// Without the flag, the existing (manual, deb/rpm) path stays unchanged.
func TestEnrollRequirePin(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unknown token", http.StatusUnauthorized)
	}))
	defer server.Close()

	keyPath := writeTestHostKey(t)
	validPin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	tests := map[string]struct {
		env          string
		args         []string
		wantCode     int
		wantRequests int64
	}{
		"require-pin without pin aborts": {
			args:         []string{"--require-pin"},
			wantCode:     2,
			wantRequests: 0,
		},
		"env acts like flag": {
			env:          "1",
			wantCode:     2,
			wantRequests: 0,
		},
		"env false changes nothing": {
			env:          "false",
			wantCode:     1,
			wantRequests: 1,
		},
		"require-pin with pin runs": {
			args:         []string{"--require-pin", "--pin", validPin},
			wantCode:     1,
			wantRequests: 1,
		},
		"without require-pin it runs unpinned": {
			wantCode:     1,
			wantRequests: 1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv(envRequirePin, tc.env)
			requests.Store(0)

			args := append([]string{
				"enroll",
				"--server", server.URL,
				"--agent-url", "https://agent.example.com",
				"--token", "gssh-et-test",
				"--hostname", "testhost",
				"--ssh-key", keyPath,
				"--state-dir", t.TempDir(),
				"--ssh-dir", t.TempDir(),
			}, tc.args...)

			var stdout, stderr bytes.Buffer
			if code := Run(&stdout, &stderr, args); code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, tc.wantCode, stderr.String())
			}
			if got := requests.Load(); got != tc.wantRequests {
				t.Fatalf("requests = %d, want %d", got, tc.wantRequests)
			}
			if tc.wantRequests == 0 && !strings.Contains(stderr.String(), "--pin") {
				t.Errorf("stderr does not mention the reason: %q", stderr.String())
			}
		})
	}
}
