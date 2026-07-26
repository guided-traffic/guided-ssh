package api

import (
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiterConfig configures rate limiting of the unauthenticated
// endpoints (/v1/sign/user, /v1/sign/ci, /v1/enroll). Two budgets per
// client IP: a request budget against load spikes and a much smaller
// failure budget against brute force (only 401/403 responses count).
type RateLimiterConfig struct {
	// RequestsPerMinute is the sustained request rate per client IP.
	RequestsPerMinute float64
	// Burst is the maximum number of requests without a wait.
	Burst float64
	// FailuresPerMinute is the allowed rate of rejected requests (401/403);
	// once the budget is used up, further requests get a 429 response.
	FailuresPerMinute float64
	// FailureBurst is the maximum number of failed attempts without a wait.
	FailureBurst float64
	// TrustProxyHeader: behind a trusted proxy/ingress, the client IP is
	// read from the last X-Forwarded-For entry (the one appended by the
	// nearest proxy). Leave off without a proxy — the header is otherwise
	// freely forgeable.
	TrustProxyHeader bool
}

// DefaultRateLimiterConfig are the default limits: generous for legitimate
// use (humans sign rarely, CI once per job), tight for failed attempts.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             20,
		FailuresPerMinute: 10,
		FailureBurst:      10,
	}
}

// maxClients bounds the number of tracked client IPs (memory protection);
// beyond it, inactive entries are evicted first, arbitrary ones if needed.
const maxClients = 65536

// clientIdleTTL: entries without activity for longer than this duration
// are fully refilled and can be evicted.
const clientIdleTTL = 5 * time.Minute

// RateLimiter is a token bucket limiter per client IP.
type RateLimiter struct {
	cfg RateLimiterConfig
	now func() time.Time // injectable for tests

	mu      sync.Mutex
	clients map[string]*clientBuckets
}

// clientBuckets are the two budgets of a client IP.
type clientBuckets struct {
	requests bucket
	failures bucket
	lastSeen time.Time
}

// bucket is a token bucket with lazy refill.
type bucket struct {
	tokens float64
	last   time.Time
}

// refill tops up proportionally to elapsed time (capped at burst).
func (b *bucket) refill(now time.Time, perMinute, burst float64) {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Minutes()*perMinute)
	}
	b.last = now
}

// take withdraws one token, if available.
func (b *bucket) take() bool {
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// NewRateLimiter builds the limiter; rates ≤ 0 in the configuration are
// filled in with the defaults.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	defaults := DefaultRateLimiterConfig()
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = defaults.RequestsPerMinute
	}
	if cfg.Burst <= 0 {
		cfg.Burst = defaults.Burst
	}
	if cfg.FailuresPerMinute <= 0 {
		cfg.FailuresPerMinute = defaults.FailuresPerMinute
	}
	if cfg.FailureBurst <= 0 {
		cfg.FailureBurst = defaults.FailureBurst
	}
	return &RateLimiter{cfg: cfg, now: time.Now, clients: map[string]*clientBuckets{}}
}

// limit wraps a handler with rate limiting: check the request budget,
// observe the response status, and deduct 401/403 from the failure budget.
func (l *RateLimiter) limit(next http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		key := l.clientKey(r)
		if !l.allow(key) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests — please try again later", http.StatusTooManyRequests)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		if rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden {
			l.recordFailure(key)
		}
	}
}

// allow checks both budgets: the request budget gets debited, the failure
// budget merely needs to still have coverage (it only gets debited by a
// 401/403 response).
func (l *RateLimiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.client(key, now)
	c.lastSeen = now
	c.requests.refill(now, l.cfg.RequestsPerMinute, l.cfg.Burst)
	c.failures.refill(now, l.cfg.FailuresPerMinute, l.cfg.FailureBurst)
	return c.failures.tokens >= 1 && c.requests.take()
}

// recordFailure debits the failure budget of the client IP.
func (l *RateLimiter) recordFailure(key string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.client(key, now)
	c.failures.refill(now, l.cfg.FailuresPerMinute, l.cfg.FailureBurst)
	c.failures.take()
}

// client returns the budgets of an IP (creating them if needed) and keeps
// the map under maxClients.
func (l *RateLimiter) client(key string, now time.Time) *clientBuckets {
	if c, ok := l.clients[key]; ok {
		return c
	}
	if len(l.clients) >= maxClients {
		l.evict(now)
	}
	c := &clientBuckets{lastSeen: now}
	l.clients[key] = c
	return c
}

// evict removes inactive entries; if there's still no room afterward, an
// arbitrary entry (map iteration order) is dropped so new clients never
// get blocked.
func (l *RateLimiter) evict(now time.Time) {
	for key, c := range l.clients {
		if now.Sub(c.lastSeen) > clientIdleTTL {
			delete(l.clients, key)
		}
	}
	for key := range l.clients {
		if len(l.clients) < maxClients {
			break
		}
		delete(l.clients, key)
	}
}

// clientKey determines the client IP from RemoteAddr; behind a trusted
// proxy, from the last X-Forwarded-For entry.
func (l *RateLimiter) clientKey(r *http.Request) string {
	if l.cfg.TrustProxyHeader {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// statusRecorder remembers the written status code for the limiter's
// failure detection.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader implements http.ResponseWriter.
func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
