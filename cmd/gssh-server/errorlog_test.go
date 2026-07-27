package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// errorLogger builds the server error log over a JSON handler at the given
// level, so a test can assert what a real deployment would actually see.
func errorLogger(buf *bytes.Buffer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: level}))
}

func TestServerErrorLogSilencesTransportAborts(t *testing.T) {
	// The exact line net/http emits when an ingress TCP health check opens a
	// connection to the agent listener and resets it.
	const line = "http: TLS handshake error from 100.64.2.29:39094: " +
		"read tcp 100.64.0.87:8443->100.64.2.29:39094: read: connection reset by peer"

	var buf bytes.Buffer
	serverErrorLog(errorLogger(&buf, slog.LevelInfo), "agent").Print(line)

	if buf.Len() != 0 {
		t.Errorf("transport abort logged at info level: %s", buf.String())
	}
}

func TestServerErrorLogKeepsTransportAbortsAtDebug(t *testing.T) {
	const line = "http: TLS handshake error from 100.64.2.29:39094: EOF"

	var buf bytes.Buffer
	serverErrorLog(errorLogger(&buf, slog.LevelDebug), "agent").Print(line)

	out := buf.String()
	if !strings.Contains(out, `"level":"DEBUG"`) {
		t.Errorf("transport abort not logged at debug level: %s", out)
	}
	if !strings.Contains(out, `"listener":"agent"`) {
		t.Errorf("listener label missing: %s", out)
	}
}

func TestServerErrorLogWarnsOnRealHandshakeFailure(t *testing.T) {
	// A client without a certificate is a genuine mTLS rejection and must
	// stay visible at the default level.
	const line = "http: TLS handshake error from 10.0.0.5:5555: " +
		"tls: client didn't provide a certificate"

	var buf bytes.Buffer
	serverErrorLog(errorLogger(&buf, slog.LevelInfo), "agent").Print(line)

	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("mTLS rejection not logged at warn level: %s", out)
	}
	if !strings.Contains(out, "client didn't provide a certificate") {
		t.Errorf("handshake reason lost: %s", out)
	}
	if strings.Contains(out, tlsHandshakePrefix) {
		t.Errorf("net/http prefix not stripped: %s", out)
	}
}

func TestLogLevelFromEnv(t *testing.T) {
	for value, want := range map[string]slog.Level{
		"":      slog.LevelInfo,
		"info":  slog.LevelInfo,
		"DEBUG": slog.LevelDebug,
		" warn": slog.LevelWarn,
		"error": slog.LevelError,
	} {
		t.Setenv(envLogLevel, value)
		got, err := logLevelFromEnv()
		if err != nil {
			t.Fatalf("logLevelFromEnv(%q) failed: %v", value, err)
		}
		if got != want {
			t.Errorf("logLevelFromEnv(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestLogLevelFromEnvRejectsUnknown(t *testing.T) {
	t.Setenv(envLogLevel, "verbose")
	if _, err := logLevelFromEnv(); err == nil {
		t.Error("logLevelFromEnv(verbose) accepted an unknown level")
	}
}

func TestServerErrorLogWarnsOnOtherServerErrors(t *testing.T) {
	const line = "http: superfluous response.WriteHeader call"

	var buf bytes.Buffer
	serverErrorLog(errorLogger(&buf, slog.LevelInfo), "api").Print(line)

	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("server error not logged at warn level: %s", out)
	}
	if !strings.Contains(out, "superfluous") {
		t.Errorf("message lost: %s", out)
	}
}
