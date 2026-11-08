package api

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func keyFor(t *testing.T, remote string, trusted []netip.Prefix, xff ...string) string {
	t.Helper()
	r := httptest.NewRequest("GET", "/v1/snapshots/latest", nil)
	r.RemoteAddr = remote
	for _, h := range xff {
		r.Header.Add("X-Forwarded-For", h)
	}
	return clientKey(r, trusted)
}

func TestClientKeyTrustsForwardedForOnlyFromProxies(t *testing.T) {
	lb, err := ParseTrustedProxies("10.0.0.0/8, 35.191.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote string
		trusted      []netip.Prefix
		xff          []string
		want         string
	}{
		{"direct client, no proxies configured", "198.51.100.7:4000", nil, nil, "198.51.100.7"},
		{"spoofed header without a trusted peer is ignored", "198.51.100.7:4000", lb, []string{"203.0.113.9"}, "198.51.100.7"},
		{"behind the load balancer", "10.1.2.3:4000", lb, []string{"203.0.113.9"}, "203.0.113.9"},
		{"client-sent prefix entries are not believed", "10.1.2.3:4000", lb, []string{"1.2.3.4, 203.0.113.9"}, "203.0.113.9"},
		{"chained trusted proxies are skipped", "10.1.2.3:4000", lb, []string{"203.0.113.9, 35.191.4.4"}, "203.0.113.9"},
		{"header split across lines", "10.1.2.3:4000", lb, []string{"203.0.113.9", "35.191.4.4"}, "203.0.113.9"},
		{"malformed hop stops at the last good address", "10.1.2.3:4000", lb, []string{"203.0.113.9, not-an-ip"}, "10.1.2.3"},
		{"trusted peer with no header", "10.1.2.3:4000", lb, nil, "10.1.2.3"},
		{"IPv6 clients share their /64", "[2001:db8:1:2:aaaa::1]:4000", nil, nil, "2001:db8:1:2::/64"},
		{"IPv4-mapped IPv6 is IPv4", "[::ffff:198.51.100.7]:4000", nil, nil, "198.51.100.7"},
	}
	for _, c := range cases {
		if got := keyFor(t, c.remote, c.trusted, c.xff...); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if keyFor(t, "[2001:db8:1:2::1]:1", nil) != keyFor(t, "[2001:db8:1:2:ffff:ffff:ffff:ffff]:1", nil) {
		t.Error("addresses in one /64 must share a bucket")
	}
}

func TestParseTrustedProxiesRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "not-a-cidr", "10.0.0.1/8/8"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	got, err := ParseTrustedProxies(" 10.0.0.1 , 2001:db8::/32,")
	if err != nil || len(got) != 2 || got[0].Bits() != 32 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestLimiterCapsClientCount(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	rl := newIPRateLimiter(10, 30, func() time.Time { return now })
	rl.maxClients = 3
	for _, k := range []string{"a", "b", "c"} {
		if !rl.allow(k) {
			t.Fatalf("%s should be admitted", k)
		}
	}
	if rl.allow("d") {
		t.Fatal("a new client beyond the cap must be refused while every bucket is active")
	}
	if !rl.allow("a") {
		t.Fatal("an existing client keeps its bucket at the cap")
	}
	now = now.Add(idleBucketTTL + time.Second)
	if !rl.allow("d") {
		t.Fatal("idle buckets are dropped to make room")
	}
}

func TestLimiterChargesBatchesMore(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	rl := newIPRateLimiter(1, 30, func() time.Time { return now })
	if !rl.allowN("x", 10) || !rl.allowN("x", 10) || !rl.allowN("x", 10) {
		t.Fatal("three 10-token batches fit a 30-token burst")
	}
	if rl.allowN("x", 10) {
		t.Fatal("a fourth batch must wait for refill")
	}
	if !rl.allowN("y", 100) {
		t.Fatal("a cost above the burst is capped at the burst, not impossible")
	}
}
