package fetcher

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// newServer starts a TLS server and a Fetcher pinned to it. httptest's
// certificate is valid for example.com, so requests use that host name.
func newServer(t *testing.T, h http.HandlerFunc, allow func(netip.Addr) bool) *Fetcher {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig
	return New(WithRootCAs(tlsCfg), WithTestServer(srv.Listener.Addr().String(), allow))
}

func loopbackOnly(a netip.Addr) bool { return a.IsLoopback() }

func TestGetFetchesStellarTOML(t *testing.T) {
	f := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != userAgent || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected headers: %v", r.Header)
		}
		w.Write([]byte(`NETWORK_PASSPHRASE="Test SDF Network ; September 2015"`))
	}, loopbackOnly)
	u, err := StellarTOMLURL("Example.COM.")
	if err != nil || u != "https://example.com/.well-known/stellar.toml" {
		t.Fatalf("url = %q, %v", u, err)
	}
	res, err := f.Get(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || !strings.Contains(string(res.Body), "NETWORK_PASSPHRASE") {
		t.Fatalf("result = %+v", res)
	}
}

// With the production policy, a host that resolves to a private or loopback
// address (including DNS rebinding) is refused at connect time.
func TestProductionPolicyRefusesPrivateTarget(t *testing.T) {
	f := newServer(t, func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("secret")) }, IsPublic)
	_, err := f.Get(context.Background(), "https://example.com/.well-known/stellar.toml")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

func TestURLPolicy(t *testing.T) {
	f := New()
	for _, u := range []string{
		"http://example.com/.well-known/stellar.toml",
		"https://user:pass@example.com/",
		"https://127.0.0.1/",
		"https://[::1]/",
		"https://169.254.169.254/latest/meta-data/",
		"file:///etc/passwd",
		"gopher://example.com/",
		"https://example.com:notaport/",
		"",
	} {
		if _, err := f.Get(context.Background(), u); !errors.Is(err, ErrBlocked) {
			t.Errorf("%q: want ErrBlocked, got %v", u, err)
		}
	}
}

func TestRedirects(t *testing.T) {
	cases := map[string]string{
		"downgrade to http": "http://example.com/x",
		"to an IP literal":  "https://10.0.0.1/x",
		"to userinfo":       "https://a:b@example.com/x",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			f := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}, loopbackOnly)
			if _, err := f.Get(context.Background(), "https://example.com/"); !errors.Is(err, ErrBlocked) {
				t.Fatalf("want ErrBlocked, got %v", err)
			}
		})
	}
	t.Run("loop", func(t *testing.T) {
		f := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/again", http.StatusFound)
		}, loopbackOnly)
		if _, err := f.Get(context.Background(), "https://example.com/"); !errors.Is(err, ErrBlocked) {
			t.Fatalf("want ErrBlocked, got %v", err)
		}
	})
}

func TestBodyCap(t *testing.T) {
	f := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("a", MaxBodyBytes+1)))
	}, loopbackOnly)
	if _, err := f.Get(context.Background(), "https://example.com/"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	g := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("a", MaxBodyBytes)))
	}, loopbackOnly)
	if res, err := g.Get(context.Background(), "https://example.com/"); err != nil || len(res.Body) != MaxBodyBytes {
		t.Fatalf("exactly at the cap: %d bytes, %v", len(res.Body), err)
	}
}

func TestSlowServerTimesOut(t *testing.T) {
	f := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}, loopbackOnly)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := f.Get(ctx, "https://example.com/"); err == nil {
		t.Fatal("slow server did not time out")
	}
}

func TestIsPublic(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "0.1.2.3", "224.0.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1", "255.255.255.255",
		"::1", "::", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "64:ff9b::a00:1", "2002:a00:1::",
		"::ffff:10.0.0.1",
	}
	for _, s := range blocked {
		if IsPublic(netip.MustParseAddr(s).Unmap()) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
}

func TestStellarTOMLURLRejectsBadDomains(t *testing.T) {
	for _, d := range []string{"", "localhost", "exаmple.com", "a..b", "example.com/evil", "user@example.com"} {
		if _, err := StellarTOMLURL(d); !errors.Is(err, ErrBlocked) {
			t.Errorf("%q: want ErrBlocked, got %v", d, err)
		}
	}
}
