package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestLimiter builds a limiter with a controllable clock.
func newTestLimiter(cfg RateLimiterConfig) (*RateLimiter, *time.Time) {
	l := NewRateLimiter(cfg)
	now := time.Now()
	l.now = func() time.Time { return now }
	return l, &now
}

func TestRateLimitBurstAndRefill(t *testing.T) {
	l, now := newTestLimiter(RateLimiterConfig{RequestsPerMinute: 60, Burst: 3})

	for i := range 3 {
		if !l.allow("ip") {
			t.Fatalf("request %d rejected within burst", i+1)
		}
	}
	if l.allow("ip") {
		t.Fatal("request beyond burst allowed")
	}
	// 60/min ⇒ after 1s exactly one token has been refilled.
	*now = now.Add(time.Second)
	if !l.allow("ip") {
		t.Fatal("request after refill rejected")
	}
	if l.allow("ip") {
		t.Fatal("second request after one token allowed")
	}
}

func TestRateLimitClientsSeparated(t *testing.T) {
	l, _ := newTestLimiter(RateLimiterConfig{RequestsPerMinute: 60, Burst: 1})
	if !l.allow("a") || !l.allow("b") {
		t.Fatal("clients share one budget")
	}
	if l.allow("a") {
		t.Fatal("a's budget not exhausted")
	}
}

func TestRateLimitFailureBudgetBlocks(t *testing.T) {
	l, now := newTestLimiter(RateLimiterConfig{
		RequestsPerMinute: 600, Burst: 100, // request budget deliberately generous
		FailuresPerMinute: 60, FailureBurst: 2,
	})
	unauthorized := l.limit(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rejected", http.StatusUnauthorized)
	})

	status := func() int {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign/user", nil)
		req.RemoteAddr = "203.0.113.7:4711"
		rec := httptest.NewRecorder()
		unauthorized(rec, req)
		return rec.Code
	}

	// FailureBurst=2: two failed attempts get through, then 429 despite a
	// free request budget.
	for i := range 2 {
		if got := status(); got != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d: status %d, expected 401", i+1, got)
		}
	}
	if got := status(); got != http.StatusTooManyRequests {
		t.Fatalf("after exhausted failure budget: status %d, expected 429", got)
	}
	// 60 failed attempts/min ⇒ after 1s a token is available again.
	*now = now.Add(time.Second)
	if got := status(); got != http.StatusUnauthorized {
		t.Fatalf("after refill: status %d, expected 401", got)
	}
}

func TestRateLimitSuccessDoesNotConsumeFailureBudget(t *testing.T) {
	l, _ := newTestLimiter(RateLimiterConfig{
		RequestsPerMinute: 600, Burst: 100,
		FailuresPerMinute: 60, FailureBurst: 1,
	})
	okHandler := l.limit(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for i := range 5 {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign/user", nil)
		req.RemoteAddr = "203.0.113.8:4711"
		rec := httptest.NewRecorder()
		okHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("successful request %d: status %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitNilLimiterPermissive(t *testing.T) {
	var l *RateLimiter
	handler := l.limit(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("nil limiter blocks: status %d", rec.Code)
	}
}

func TestClientKey(t *testing.T) {
	direct, _ := newTestLimiter(RateLimiterConfig{})
	proxied, _ := newTestLimiter(RateLimiterConfig{TrustProxyHeader: true})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.9:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.50")

	if got := direct.clientKey(req); got != "198.51.100.9" {
		t.Errorf("without proxy trust: %q, expected remote-addr host", got)
	}
	// Trusted proxy: last entry (appended by the nearest proxy).
	if got := proxied.clientKey(req); got != "203.0.113.50" {
		t.Errorf("with proxy trust: %q, expected last xff entry", got)
	}
}

func TestRateLimitMapStaysBounded(t *testing.T) {
	l, _ := newTestLimiter(RateLimiterConfig{RequestsPerMinute: 60, Burst: 1})
	for i := range maxClients + 100 {
		l.allow(string(rune(i)) + "-client")
	}
	if len(l.clients) > maxClients {
		t.Fatalf("client map over limit: %d", len(l.clients))
	}
}
