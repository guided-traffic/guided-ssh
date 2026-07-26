package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMiddlewareCountsStatusCodes(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		_, _ = w.Write([]byte("ok")) // implicit 200
	}))

	before200 := testutil.ToFloat64(HTTPResponses.WithLabelValues("200"))
	before418 := testutil.ToFloat64(HTTPResponses.WithLabelValues("418"))

	for _, path := range []string{"/", "/error"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	}

	if got := testutil.ToFloat64(HTTPResponses.WithLabelValues("200")) - before200; got != 1 {
		t.Errorf("200 counter increased by %v, expected 1", got)
	}
	if got := testutil.ToFloat64(HTTPResponses.WithLabelValues("418")) - before418; got != 1 {
		t.Errorf("418 counter increased by %v, expected 1", got)
	}
}

func TestHandlerReturnsMetrics(t *testing.T) {
	CertificatesIssued.WithLabelValues("user", "user").Inc()
	// CounterVecs only appear in the exposition once they have at least one child.
	HTTPResponses.WithLabelValues("200").Add(0)

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d, expected 200", rec.Code)
	}
	body := rec.Body.String()
	for _, name := range []string{"gssh_certificates_issued_total", "gssh_http_responses_total", "gssh_agent_heartbeats_total"} {
		if !strings.Contains(body, name) {
			t.Errorf("exposition does not contain %q", name)
		}
	}
}
