// Package metrics provides the Prometheus metrics for the gssh server
// (plan phase 11): certificates issued, HTTP error rates, and agent
// heartbeats. The metrics land in the default registry and are served via
// Handler() (endpoint /metrics, dedicated listener).
package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// CertificatesIssued counts successfully issued certificates by
	// requester (user/ci/host) and certificate type (user/host).
	CertificatesIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gssh_certificates_issued_total",
		Help: "Successfully issued SSH certificates.",
	}, []string{"requester", "cert_type"})

	// HTTPResponses counts HTTP responses by status code; error rates
	// follow from rate() over the 4xx/5xx codes.
	HTTPResponses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gssh_http_responses_total",
		Help: "HTTP responses by status code (API and agent endpoints).",
	}, []string{"code"})

	// RulesFileSyncErrors counts failed reconciliations of a declarative
	// rules file (parse or apply errors) by domain (host/ci). The server
	// keeps the last applied state on error, so a rising counter means the
	// rules in the database are older than the file's source of truth.
	RulesFileSyncErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gssh_rules_file_sync_errors_total",
		Help: "Failed reconciliations of a declarative rules file (GitOps).",
	}, []string{"domain"})

	// AgentHeartbeats counts agent contacts (mTLS requests that stamp
	// last_seen_at).
	AgentHeartbeats = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gssh_agent_heartbeats_total",
		Help: "Heartbeats from host agents (successful mTLS contacts).",
	})
)

// Handler returns the Prometheus exposition handler (/metrics).
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware counts the wrapped handler's responses by status code.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		HTTPResponses.WithLabelValues(strconv.Itoa(rec.status)).Inc()
	})
}

// statusRecorder remembers the written status code; without an explicit
// WriteHeader, 200 applies (net/http convention).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
