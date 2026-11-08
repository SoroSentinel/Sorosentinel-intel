package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultRateLimit is the default allowed requests per second per client.
	DefaultRateLimit = 10.0
	// DefaultBurstLimit is the default maximum burst capacity per client.
	DefaultBurstLimit = 30
	// MaxRateLimitClients bounds the limiter's memory. When it is full and no
	// idle bucket can be dropped, new clients are refused (429) rather than
	// letting an address-rotating client grow the map without limit.
	MaxRateLimitClients = 100_000
	// BatchEntitiesPerToken is how many batchGet entities one token pays for:
	// a 100-entity batch costs 10 tokens, a single lookup 1.
	BatchEntitiesPerToken = 10

	idleBucketTTL = 10 * time.Minute
	gcInterval    = 5 * time.Minute
)

type clientBucket struct {
	tokens     float64
	lastUpdate time.Time
}

type ipRateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*clientBucket
	rate       float64
	burst      float64
	maxClients int
	now        func() time.Time
	lastGC     time.Time
}

func newIPRateLimiter(rate float64, burst int, now func() time.Time) *ipRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &ipRateLimiter{
		clients:    make(map[string]*clientBucket),
		rate:       rate,
		burst:      float64(burst),
		maxClients: MaxRateLimitClients,
		now:        now,
		lastGC:     now(),
	}
}

// allow takes one token for key.
func (rl *ipRateLimiter) allow(key string) bool { return rl.allowN(key, 1) }

// allowN takes n tokens for key, or none if the bucket holds fewer than n.
func (rl *ipRateLimiter) allowN(key string, n float64) bool {
	if rl == nil || rl.rate <= 0 || rl.burst <= 0 {
		return true
	}
	if n > rl.burst {
		n = rl.burst // a request larger than the burst is still possible on a full bucket
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	if now.Sub(rl.lastGC) > gcInterval {
		rl.dropIdle(now)
	}

	b, ok := rl.clients[key]
	if !ok {
		if len(rl.clients) >= rl.maxClients {
			rl.dropIdle(now)
			if len(rl.clients) >= rl.maxClients {
				return false
			}
		}
		b = &clientBucket{tokens: rl.burst, lastUpdate: now}
		rl.clients[key] = b
	}

	b.tokens += now.Sub(b.lastUpdate).Seconds() * rl.rate
	b.lastUpdate = now
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

func (rl *ipRateLimiter) dropIdle(now time.Time) {
	for k, v := range rl.clients {
		if now.Sub(v.lastUpdate) > idleBucketTTL {
			delete(rl.clients, k)
		}
	}
	rl.lastGC = now
}

// clientKey identifies the client a request is charged to.
//
// Behind a load balancer every connection comes from the proxy, so keying on
// RemoteAddr alone would put all clients in one bucket. X-Forwarded-For is
// honored only when the connection comes from a configured trusted proxy, and
// then the rightmost address not itself a trusted proxy is the client (the
// leftmost entries are whatever the client chose to send). IPv6 clients are
// keyed by their /64, since one subscriber typically holds a whole /64.
func clientKey(r *http.Request, trusted []netip.Prefix) string {
	peer := remoteAddr(r)
	if peer.IsValid() && inPrefixes(peer, trusted) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break // a malformed hop: stop and charge the last good peer
			}
			a = a.Unmap()
			peer = a
			if !inPrefixes(a, trusted) {
				break
			}
		}
	}
	if !peer.IsValid() {
		return "unknown"
	}
	if peer.Is6() {
		p, _ := peer.Prefix(64)
		return p.String()
	}
	return peer.String()
}

func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies parses a comma-separated list of CIDR prefixes or single
// addresses, such as the load balancer's ranges.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter != nil && !s.limiter.allow(clientKey(r, s.cfg.TrustedProxies)) {
			rateLimited(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// chargeBatch takes the extra tokens a batch of n entities costs beyond the one
// the middleware already took. It reports whether the request may proceed.
func (s *Server) chargeBatch(r *http.Request, n int) bool {
	if s.limiter == nil {
		return true
	}
	cost := (n + BatchEntitiesPerToken - 1) / BatchEntitiesPerToken
	if cost <= 1 {
		return true
	}
	return s.limiter.allowN(clientKey(r, s.cfg.TrustedProxies), float64(cost-1))
}

func rateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusTooManyRequests, codeRateLimited)
}
