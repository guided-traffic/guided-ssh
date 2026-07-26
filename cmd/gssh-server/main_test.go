package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"-version"}); got != 0 {
		t.Fatalf("run(-version) = %d, want 0 (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "guided-ssh") {
		t.Errorf("version output %q does not contain %q", stdout.String(), "guided-ssh")
	}
}

func TestRunWithoutListen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, nil); got != 2 {
		t.Fatalf("run() = %d, want 2 (configuration error)", got)
	}
	if !strings.Contains(stderr.String(), "-listen") {
		t.Errorf("stderr %q does not mention -listen", stderr.String())
	}
}

func TestRunUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"-does-not-exist"}); got != 2 {
		t.Fatalf("run(-does-not-exist) = %d, want 2", got)
	}
}

// clearDBEnv clears all GSSH_DB_* variables, so tests run independently of
// the developer's environment.
func clearDBEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{envDBHost, envDBPort, envDBUser, envDBPassword, envDBName, envDBSSLMode} {
		t.Setenv(v, "")
	}
}

func TestRunListenWithoutDBConfig(t *testing.T) {
	clearDBEnv(t)
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"-listen", "127.0.0.1:0"}); got != 1 {
		t.Fatalf("run(-listen) without db configuration = %d, want 1", got)
	}
	if !strings.Contains(stdout.String(), "GSSH_DB_HOST") {
		t.Errorf("log %q does not mention GSSH_DB_HOST", stdout.String())
	}
}

func TestRunMigrateWithoutDBConfig(t *testing.T) {
	clearDBEnv(t)
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"migrate"}); got != 2 {
		t.Fatalf("migrate without db configuration = %d, want 2 (configuration error)", got)
	}
	if !strings.Contains(stderr.String(), "GSSH_DB_HOST") {
		t.Errorf("stderr %q without a mention of GSSH_DB_HOST", stderr.String())
	}
}

func TestRunEnrollTokenWithoutDBConfig(t *testing.T) {
	clearDBEnv(t)
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"enroll-token"}); got != 1 {
		t.Fatalf("enroll-token without db configuration = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "GSSH_DB_HOST") {
		t.Errorf("stderr %q without a mention of GSSH_DB_HOST", stderr.String())
	}
}

func TestRunEnrollTokenFlagError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"enroll-token", "-does-not-exist"}); got != 2 {
		t.Fatalf("run = %d, want 2", got)
	}
}

func TestRunEnrollTokenBrokenTags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"enroll-token", "-tags", "without-equals-sign"}); got != 2 {
		t.Fatalf("run = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "tag") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestParseTags(t *testing.T) {
	tags, err := parseTags("env=prod,role=web,empty=")
	if err != nil {
		t.Fatalf("parseTags: %v", err)
	}
	if tags["env"] != "prod" || tags["role"] != "web" || tags["empty"] != "" {
		t.Errorf("tags = %v", tags)
	}
	if got, err := parseTags(""); err != nil || len(got) != 0 {
		t.Errorf("empty: %v, %v", got, err)
	}
	if _, err := parseTags("=value"); err == nil {
		t.Error("expected an error (empty key)")
	}
}

func TestSetupInvalidMasterKey(t *testing.T) {
	// The master key is checked before the DB configuration — DB env is irrelevant.
	t.Setenv("GSSH_CA_MASTER_KEY", "not-base64!")
	if _, _, err := setup(context.Background()); err == nil {
		t.Fatal("expected an error (master key not base64)")
	}
}
