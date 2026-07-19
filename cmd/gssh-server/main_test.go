package main

import (
	"bytes"
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

func TestRunOhneArgumente(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, nil); got != 1 {
		t.Fatalf("run() = %d, erwartet 1 (noch nicht implementiert)", got)
	}
	if !strings.Contains(stderr.String(), "nicht implementiert") {
		t.Errorf("stderr %q enthält keinen Hinweis auf fehlende Implementierung", stderr.String())
	}
}

func TestRunUnbekanntesFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"-gibt-es-nicht"}); got != 2 {
		t.Fatalf("run(-gibt-es-nicht) = %d, erwartet 2", got)
	}
}
