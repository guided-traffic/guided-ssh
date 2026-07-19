package agentd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Deckt RenewMTLS, SendSessions und setClientCert des apiClient ab (mTLS-
// Harness aus client_test.go).
func TestAPIClientRenewMTLSUndSessions(t *testing.T) {
	var gotEvents atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/renew-mtls", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CSR == "" {
			http.Error(w, "csr fehlt", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"})
	})
	mux.HandleFunc("POST /v1/agent/sessions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Events []sessionEventWire `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		gotEvents.Add(int64(len(req.Events)))
		w.WriteHeader(http.StatusNoContent)
	})
	client := newTestAgentAPI(t, mux)
	ctx := context.Background()

	cert, err := client.RenewMTLS(ctx, "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----")
	if err != nil || cert == "" {
		t.Errorf("RenewMTLS: %q %v", cert, err)
	}
	if err := client.SendSessions(ctx, []sessionEventWire{
		{Phase: "open", Service: "sshd", LocalUser: "deploy", OccurredAt: time.Now()},
		{Phase: "close", Service: "sshd", LocalUser: "deploy", OccurredAt: time.Now()},
	}); err != nil {
		t.Errorf("SendSessions: %v", err)
	}
	if gotEvents.Load() != 2 {
		t.Errorf("server hat %d events erhalten (2 erwartet)", gotEvents.Load())
	}

	// setClientCert schaltet das Zertifikat für künftige Handshakes um
	// (die Rotation nutzt das ohne Neustart) — hier nur der Umschalt-Pfad.
	client.setClientCert(tls.Certificate{})
}

func TestAPIClientRenewMTLSOhneZertifikat(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/renew-mtls", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{})
	})
	mux.HandleFunc("POST /v1/agent/sessions", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "kaputt", http.StatusInternalServerError)
	})
	client := newTestAgentAPI(t, mux)
	ctx := context.Background()

	if _, err := client.RenewMTLS(ctx, "csr"); err == nil {
		t.Error("renew-mtls ohne zertifikat: fehler erwartet")
	}
	if err := client.SendSessions(ctx, nil); err == nil {
		t.Error("sessions 500: fehler erwartet")
	}
}
