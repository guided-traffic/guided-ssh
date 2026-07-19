package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestLimiter baut einen Limiter mit steuerbarer Uhr.
func newTestLimiter(cfg RateLimiterConfig) (*RateLimiter, *time.Time) {
	l := NewRateLimiter(cfg)
	now := time.Now()
	l.now = func() time.Time { return now }
	return l, &now
}

func TestRateLimitBurstUndRefill(t *testing.T) {
	l, now := newTestLimiter(RateLimiterConfig{RequestsPerMinute: 60, Burst: 3})

	for i := range 3 {
		if !l.allow("ip") {
			t.Fatalf("request %d im burst abgelehnt", i+1)
		}
	}
	if l.allow("ip") {
		t.Fatal("request über burst erlaubt")
	}
	// 60/min ⇒ nach 1 s ist genau ein Token nachgefüllt.
	*now = now.Add(time.Second)
	if !l.allow("ip") {
		t.Fatal("request nach refill abgelehnt")
	}
	if l.allow("ip") {
		t.Fatal("zweiter request nach einem token erlaubt")
	}
}

func TestRateLimitClientsGetrennt(t *testing.T) {
	l, _ := newTestLimiter(RateLimiterConfig{RequestsPerMinute: 60, Burst: 1})
	if !l.allow("a") || !l.allow("b") {
		t.Fatal("clients teilen sich ein budget")
	}
	if l.allow("a") {
		t.Fatal("budget von a nicht erschöpft")
	}
}

func TestRateLimitFailureBudgetSperrt(t *testing.T) {
	l, now := newTestLimiter(RateLimiterConfig{
		RequestsPerMinute: 600, Burst: 100, // Request-Budget bewusst großzügig
		FailuresPerMinute: 60, FailureBurst: 2,
	})
	unauthorized := l.limit(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "abgelehnt", http.StatusUnauthorized)
	})

	status := func() int {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign/user", nil)
		req.RemoteAddr = "203.0.113.7:4711"
		rec := httptest.NewRecorder()
		unauthorized(rec, req)
		return rec.Code
	}

	// FailureBurst=2: zwei Fehlversuche kommen durch, danach 429 trotz
	// freiem Request-Budget.
	for i := range 2 {
		if got := status(); got != http.StatusUnauthorized {
			t.Fatalf("fehlversuch %d: status %d, erwartet 401", i+1, got)
		}
	}
	if got := status(); got != http.StatusTooManyRequests {
		t.Fatalf("nach erschöpftem failure-budget: status %d, erwartet 429", got)
	}
	// 60 Fehlversuche/min ⇒ nach 1 s ist wieder ein Token da.
	*now = now.Add(time.Second)
	if got := status(); got != http.StatusUnauthorized {
		t.Fatalf("nach refill: status %d, erwartet 401", got)
	}
}

func TestRateLimitErfolgVerbrauchtKeinFailureBudget(t *testing.T) {
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
			t.Fatalf("erfolgreicher request %d: status %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitNilLimiterDurchlaessig(t *testing.T) {
	var l *RateLimiter
	handler := l.limit(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("nil-limiter blockiert: status %d", rec.Code)
	}
}

func TestClientKey(t *testing.T) {
	direct, _ := newTestLimiter(RateLimiterConfig{})
	proxied, _ := newTestLimiter(RateLimiterConfig{TrustProxyHeader: true})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.9:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.50")

	if got := direct.clientKey(req); got != "198.51.100.9" {
		t.Errorf("ohne proxy-vertrauen: %q, erwartet remote-addr-host", got)
	}
	// Vertrauenswürdiger Proxy: letzter (vom nächsten Proxy angehängter) Eintrag.
	if got := proxied.clientKey(req); got != "203.0.113.50" {
		t.Errorf("mit proxy-vertrauen: %q, erwartet letzten xff-eintrag", got)
	}
}

func TestRateLimitMapBleibtBegrenzt(t *testing.T) {
	l, _ := newTestLimiter(RateLimiterConfig{RequestsPerMinute: 60, Burst: 1})
	for i := range maxClients + 100 {
		l.allow(string(rune(i)) + "-client")
	}
	if len(l.clients) > maxClients {
		t.Fatalf("client-map über limit: %d", len(l.clients))
	}
}
