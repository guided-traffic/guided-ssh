// Package metrics stellt die Prometheus-Metriken des gssh-servers bereit
// (Plan Phase 11): ausgestellte Zertifikate, HTTP-Fehlerraten und
// Agent-Heartbeats. Die Metriken landen in der Default-Registry und werden
// über Handler() (Endpoint /metrics, eigener Listener) ausgeliefert.
package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// CertificatesIssued zählt erfolgreich ausgestellte Zertifikate nach
	// Requester (user/ci/host) und Zertifikatstyp (user/host).
	CertificatesIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gssh_certificates_issued_total",
		Help: "Erfolgreich ausgestellte SSH-Zertifikate.",
	}, []string{"requester", "cert_type"})

	// HTTPResponses zählt HTTP-Antworten nach Status-Code; Fehlerraten
	// ergeben sich aus rate() über die 4xx/5xx-Codes.
	HTTPResponses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gssh_http_responses_total",
		Help: "HTTP-Antworten nach Status-Code (API- und Agent-Endpunkte).",
	}, []string{"code"})

	// AgentHeartbeats zählt Agent-Kontakte (mTLS-Requests, die last_seen_at
	// stempeln).
	AgentHeartbeats = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gssh_agent_heartbeats_total",
		Help: "Heartbeats der Host-Agents (erfolgreiche mTLS-Kontakte).",
	})
)

// Handler liefert den Prometheus-Exposition-Handler (/metrics).
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware zählt die Antworten des umschlossenen Handlers nach Status-Code.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		HTTPResponses.WithLabelValues(strconv.Itoa(rec.status)).Inc()
	})
}

// statusRecorder merkt sich den geschriebenen Status-Code; ohne explizites
// WriteHeader gilt 200 (net/http-Konvention).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
