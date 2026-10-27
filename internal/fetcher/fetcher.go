// Package fetcher is the only path for fetching attacker-controlled URLs
// (stellar.toml today). HTTPS only, no proxies, no cookies, size and time caps,
// and every connection's resolved IP must be public: the check runs at dial
// time, so it applies after DNS resolution and on every redirect (ARCHITECTURE §9).
package fetcher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

const (
	// MaxBodyBytes caps a response body. stellar.toml files are small. TODO(verify) against SEP-1 guidance.
	MaxBodyBytes = 100 << 10
	// Timeout covers the whole request, including redirects and the body.
	Timeout      = 10 * time.Second
	maxRedirects = 3
	userAgent    = "SoroSentinel-fetcher/1"
)

// ErrBlocked is returned when a URL or a resolved address is not allowed.
var ErrBlocked = errors.New("fetcher: blocked")

// ErrTooLarge is returned when the body exceeds MaxBodyBytes.
var ErrTooLarge = errors.New("fetcher: response too large")

// Result is a fetched body plus the facts needed to store it as evidence.
type Result struct {
	FinalURL string
	Status   int
	Body     []byte
}

// Fetcher fetches untrusted URLs under a fixed egress policy.
type Fetcher struct {
	client  *http.Client
	allowIP func(netip.Addr) bool
	// anyPort lifts the port-443 rule and dialTo pins every connection to one
	// address; both are set only by WithTestServer.
	anyPort bool
	dialTo  string
}

// Option adjusts a Fetcher; used by tests to trust a local TLS server.
type Option func(*Fetcher, *http.Transport)

// WithRootCAs trusts the given certificate pool instead of the system roots.
func WithRootCAs(cfg *tls.Config) Option {
	return func(_ *Fetcher, t *http.Transport) { t.TLSClientConfig = cfg }
}

// WithTestServer pins every connection to dialTo (a local httptest server),
// allows any port, and replaces the address policy. The policy still runs on
// the pinned address. Never use outside tests.
func WithTestServer(dialTo string, allow func(netip.Addr) bool) Option {
	return func(f *Fetcher, _ *http.Transport) {
		f.allowIP = allow
		f.anyPort = true
		f.dialTo = dialTo
	}
}

// New returns a Fetcher with the production policy unless options override it.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{allowIP: IsPublic}
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		// Control sees the exact address being connected to, after resolution.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !f.allowIP(ap.Addr().Unmap()) || (ap.Port() != 443 && !f.anyPort) {
				return fmt.Errorf("%w: address %s", ErrBlocked, address)
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if f.dialTo != "" {
				addr = f.dialTo
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DisableCompression:     true,
	}
	for _, o := range opts {
		o(f, transport)
	}
	f.client = &http.Client{
		Transport: transport,
		Timeout:   Timeout,
		Jar:       nil,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("%w: too many redirects", ErrBlocked)
			}
			return checkURL(req.URL)
		},
	}
	return f
}

// StellarTOMLURL returns https://<domain>/.well-known/stellar.toml for a canonical domain.
func StellarTOMLURL(domain string) (string, error) {
	d, err := entity.NormalizeKey(entity.Domain, domain)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBlocked, err)
	}
	return "https://" + d + "/.well-known/stellar.toml", nil
}

// Get fetches rawURL. Any policy violation, redirect problem, timeout or
// oversized body is an error; a partial body is never returned.
func (f *Fetcher) Get(ctx context.Context, rawURL string) (Result, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Result{}, fmt.Errorf("%w: unparsable URL", ErrBlocked)
	}
	if err := checkURL(u); err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrBlocked, err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := f.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return Result{}, err
	}
	if len(body) > MaxBodyBytes {
		return Result{}, ErrTooLarge
	}
	return Result{FinalURL: resp.Request.URL.String(), Status: resp.StatusCode, Body: body}, nil
}

// checkURL allows only https URLs with a DNS host name: no userinfo, no IP
// literals (they would skip the domain checks), default or explicit port only.
func checkURL(u *url.URL) error {
	if u.Scheme != "https" || u.User != nil || u.Host == "" {
		return fmt.Errorf("%w: only plain https URLs", ErrBlocked)
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return fmt.Errorf("%w: IP literal host", ErrBlocked)
	}
	if p := u.Port(); p != "" {
		if _, err := strconv.Atoi(p); err != nil {
			return fmt.Errorf("%w: bad port", ErrBlocked)
		}
	}
	return nil
}

// IsPublic reports whether addr is a globally routable unicast address.
// Blocks loopback, private, link-local (incl. 169.254.169.254 metadata),
// CGNAT, unique-local, multicast, unspecified, benchmarking and documentation ranges.
func IsPublic(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 can reach IPv4 private space
	netip.MustParsePrefix("2002::/16"),       // 6to4 can embed private IPv4
}
