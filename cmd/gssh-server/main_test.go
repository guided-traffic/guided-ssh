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
		t.Fatalf("run(-version) = %d, erwartet 0 (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "guided-ssh") {
		t.Errorf("Versionsausgabe %q enthält nicht %q", stdout.String(), "guided-ssh")
	}
}

func TestRunOhneListen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, nil); got != 2 {
		t.Fatalf("run() = %d, erwartet 2 (Konfigurationsfehler)", got)
	}
	if !strings.Contains(stderr.String(), "-listen") {
		t.Errorf("stderr %q enthält keinen Hinweis auf -listen", stderr.String())
	}
}

func TestRunUnbekanntesFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"-gibt-es-nicht"}); got != 2 {
		t.Fatalf("run(-gibt-es-nicht) = %d, erwartet 2", got)
	}
}

func TestRunListenOhneDSN(t *testing.T) {
	t.Setenv("GSSH_DB_DSN", "")
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"-listen", "127.0.0.1:0"}); got != 1 {
		t.Fatalf("run(-listen) ohne DSN = %d, erwartet 1", got)
	}
	if !strings.Contains(stdout.String(), "GSSH_DB_DSN") {
		t.Errorf("Log %q enthält keinen Hinweis auf GSSH_DB_DSN", stdout.String())
	}
}

func TestSetupUngueltigerMasterKey(t *testing.T) {
	t.Setenv("GSSH_DB_DSN", "postgres://irrelevant")
	t.Setenv("GSSH_CA_MASTER_KEY", "kein-base64!")
	if _, _, err := setup(context.Background()); err == nil {
		t.Fatal("Fehler erwartet (Master-Key kein Base64)")
	}
}
