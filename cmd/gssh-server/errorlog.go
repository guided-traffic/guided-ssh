package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/guided-traffic/guided-ssh/internal/metrics"
)

// logLevelFromEnv reads the minimum log level from GSSH_LOG_LEVEL. An
// unknown value is a configuration error rather than a silent fallback —
// a typo would otherwise hide exactly the detail it was set to reveal.
func logLevelFromEnv() (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envLogLevel))) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("%s: unknown level %q (debug|info|warn|error)", envLogLevel, os.Getenv(envLogLevel))
	}
}

// serverErrorLog routes net/http's internal error output into the structured
// logger. Without it the server falls back to the stdlib default logger,
// which writes plain text to stderr while every other line of the process is
// slog JSON on stdout — a single connection reset then breaks the log stream
// for whatever ingests it.
//
// The dominant error inside a cluster is a peer that opens a connection and
// drops it before speaking TLS: TCP health checks of the ingress or load
// balancer do exactly that, once per check interval per proxy replica. Those
// are transport noise and land on Debug (invisible at the default level).
// Handshake failures with an actual TLS reason — missing or invalid client
// certificate, protocol mismatch — stay on Warn, because on the mTLS agent
// listener they are the security-relevant signal. Both classes increment
// gssh_tls_handshake_errors_total, so the silenced one remains observable in
// monitoring instead of disappearing.
func serverErrorLog(logger *slog.Logger, listener string) *log.Logger {
	return log.New(&errorLogWriter{logger: logger, listener: listener}, "", 0)
}

type errorLogWriter struct {
	logger   *slog.Logger
	listener string
}

// tlsHandshakePrefix is how net/http formats a failed handshake
// ("http: TLS handshake error from <addr>: <err>"); only the rendered text is
// available here, so the cause has to be classified by its message.
const tlsHandshakePrefix = "http: TLS handshake error from "

// transportAborts are the error texts of a connection that died at the TCP
// layer without the peer ever attempting TLS.
var transportAborts = []string{
	"connection reset by peer",
	"broken pipe",
	"i/o timeout",
	"use of closed network connection",
	"EOF",
}

func (w *errorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")

	detail, isHandshake := strings.CutPrefix(msg, tlsHandshakePrefix)
	if !isHandshake {
		w.logger.Warn("http server error", "listener", w.listener, "detail", msg)
		return len(p), nil
	}

	if isTransportAbort(detail) {
		metrics.TLSHandshakeErrors.WithLabelValues(w.listener, "transport").Inc()
		w.logger.Debug("tls handshake aborted by peer", "listener", w.listener, "detail", detail)
		return len(p), nil
	}

	metrics.TLSHandshakeErrors.WithLabelValues(w.listener, "tls").Inc()
	w.logger.Warn("tls handshake failed", "listener", w.listener, "detail", detail)
	return len(p), nil
}

func isTransportAbort(detail string) bool {
	for _, abort := range transportAborts {
		if strings.Contains(detail, abort) {
			return true
		}
	}
	return false
}
