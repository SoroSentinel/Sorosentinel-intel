package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultRateLimit is the default allowed requests per second per IP.
	DefaultRateLimit = 10.0
	// DefaultBurstLimit is the default maximum burst capacity per IP.
	DefaultBurstLimit = 30
)

type clientBucket struct {
	tokens     float64
	lastUpdate time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientBucket
	rate    float64
	burst   float64
	now     func() time.Time
	lastGC  time.Time
}

func newIPRateLimiter(rate float64, burst int, now func() time.Time) *ipRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &ipRateLimiter{
		clients: make(map[string]*clientBucket),
		rate:    rate,
		burst:   float64(burst),
		now:     now,
		lastGC:  now(),
	}
}

func (rl *ipRateLimiter) allow(ip string) bool {
	if rl == nil || rl.rate <= 0 || rl.burst <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()

	// Periodic cleanup every 5 minutes to prevent unbound memory growth
	if now.Sub(rl.lastGC) > 5*time.Minute {
		for k, v := range rl.clients {
			if now.Sub(v.lastUpdate) > 10*time.Minute {
				delete(rl.clients, k)
			}
		}
		rl.lastGC = now
	}

	b, ok := rl.clients[ip]
	if !ok {
		rl.clients[ip] = &clientBucket{
			tokens:     rl.burst - 1,
			lastUpdate: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.lastUpdate = now
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}

	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	return strings.Trim(ip, "[]")
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter != nil {
			ip := clientIP(r)
			if !s.limiter.allow(ip) {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, codeRateLimited)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
