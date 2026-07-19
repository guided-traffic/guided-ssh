package api

import (
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiterConfig konfiguriert das Rate-Limiting der unauthentifizierten
// Endpunkte (/v1/sign/user, /v1/sign/ci, /v1/enroll). Zwei Budgets pro
// Client-IP: ein Request-Budget gegen Lastspitzen und ein deutlich kleineres
// Failure-Budget gegen Brute-Force (nur 401/403-Antworten zählen).
type RateLimiterConfig struct {
	// RequestsPerMinute ist die nachhaltige Request-Rate pro Client-IP.
	RequestsPerMinute float64
	// Burst ist die maximale Anzahl Requests ohne Wartezeit.
	Burst float64
	// FailuresPerMinute ist die erlaubte Rate abgelehnter Anfragen (401/403);
	// ist das Budget aufgebraucht, werden weitere Anfragen mit 429 beantwortet.
	FailuresPerMinute float64
	// FailureBurst ist die maximale Anzahl Fehlversuche ohne Wartezeit.
	FailureBurst float64
	// TrustProxyHeader: hinter einem vertrauenswürdigen Proxy/Ingress wird die
	// Client-IP aus dem letzten X-Forwarded-For-Eintrag gelesen (der vom
	// nächstgelegenen Proxy angehängte). Ohne Proxy aus lassen — der Header
	// ist sonst frei fälschbar.
	TrustProxyHeader bool
}

// DefaultRateLimiterConfig sind die Standard-Limits: großzügig für legitime
// Nutzung (Menschen signieren selten, CI einmal pro Job), eng für Fehlversuche.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		RequestsPerMinute: 60,
		Burst:             20,
		FailuresPerMinute: 10,
		FailureBurst:      10,
	}
}

// maxClients begrenzt die Anzahl getrackter Client-IPs (Speicherschutz);
// darüber werden zuerst inaktive, notfalls beliebige Einträge verdrängt.
const maxClients = 65536

// clientIdleTTL: Einträge ohne Aktivität länger als diese Dauer sind voll
// aufgefüllt und können verdrängt werden.
const clientIdleTTL = 5 * time.Minute

// RateLimiter ist ein Token-Bucket-Limiter pro Client-IP.
type RateLimiter struct {
	cfg RateLimiterConfig
	now func() time.Time // injizierbar für Tests

	mu      sync.Mutex
	clients map[string]*clientBuckets
}

// clientBuckets sind die beiden Budgets einer Client-IP.
type clientBuckets struct {
	requests bucket
	failures bucket
	lastSeen time.Time
}

// bucket ist ein Token-Bucket mit Lazy-Refill.
type bucket struct {
	tokens float64
	last   time.Time
}

// refill füllt anteilig der vergangenen Zeit auf (gedeckelt auf burst).
func (b *bucket) refill(now time.Time, perMinute, burst float64) {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Minutes()*perMinute)
	}
	b.last = now
}

// take entnimmt ein Token, falls verfügbar.
func (b *bucket) take() bool {
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// NewRateLimiter baut den Limiter; Raten ≤ 0 in der Konfiguration werden mit
// den Defaults aufgefüllt.
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

// limit wickelt einen Handler in das Rate-Limiting ein: Request-Budget prüfen,
// Antwortstatus beobachten und 401/403 vom Failure-Budget abziehen.
func (l *RateLimiter) limit(next http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		key := l.clientKey(r)
		if !l.allow(key) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "zu viele anfragen — bitte später erneut versuchen", http.StatusTooManyRequests)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		if rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden {
			l.recordFailure(key)
		}
	}
}

// allow prüft beide Budgets: das Request-Budget wird belastet, das
// Failure-Budget muss lediglich noch Deckung haben (belastet wird es erst
// durch eine 401/403-Antwort).
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

// recordFailure belastet das Failure-Budget der Client-IP.
func (l *RateLimiter) recordFailure(key string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.client(key, now)
	c.failures.refill(now, l.cfg.FailuresPerMinute, l.cfg.FailureBurst)
	c.failures.take()
}

// client liefert die Budgets einer IP (legt sie bei Bedarf an) und hält die
// Map unter maxClients.
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

// evict entfernt inaktive Einträge; ist danach immer noch kein Platz, fliegt
// ein beliebiger Eintrag (Map-Iteration), damit neue Clients nie blockieren.
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

// clientKey ermittelt die Client-IP aus RemoteAddr; hinter vertrauenswürdigem
// Proxy aus dem letzten X-Forwarded-For-Eintrag.
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

// statusRecorder merkt sich den geschriebenen Statuscode für die
// Failure-Erkennung des Limiters.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader implementiert http.ResponseWriter.
func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
