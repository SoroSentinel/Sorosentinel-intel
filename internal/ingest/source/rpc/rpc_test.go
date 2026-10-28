package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serve starts a TLS server whose handler gets the decoded request and
// writes the raw response body. Requests use the server's own URL.
func serve(t *testing.T, cfg Config, h func(w http.ResponseWriter, req request, raw map[string]any)) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("method %s, content-type %q", r.Method, r.Header.Get("Content-Type"))
		}
		var raw map[string]any
		var req request
		body := json.NewDecoder(r.Body)
		if err := body.Decode(&raw); err != nil {
			t.Errorf("request: %v", err)
		}
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &req)
		h(w, req, raw)
	}))
	t.Cleanup(srv.Close)
	cfg.URL = srv.URL
	cfg.TLSConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func reply(w http.ResponseWriter, id uint64, result string) {
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, id, result)
}

func TestLedgersRequestAndResponse(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	c := serve(t, Config{}, func(w http.ResponseWriter, req request, raw map[string]any) {
		if req.Method != "getLedgers" || raw["jsonrpc"] != "2.0" {
			t.Errorf("request = %v", raw)
		}
		p, _ := json.Marshal(raw["params"])
		if string(p) != `{"pagination":{"limit":3},"startLedger":42,"xdrFormat":"base64"}` {
			t.Errorf("params = %s", p)
		}
		reply(w, req.ID, `{"ledgers":[{"hash":"`+hash+`","sequence":42,"ledgerCloseTime":"1","headerXdr":"AA==","metadataXdr":"AAECAw==","newField":true}],
			"latestLedger":50,"latestLedgerCloseTime":1,"oldestLedger":1,"oldestLedgerCloseTime":1,"cursor":"42"}`)
	})
	got, err := c.Ledgers(context.Background(), 42, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Sequence != 42 || got[0].Hash != hash || string(got[0].Meta) != "\x00\x01\x02\x03" {
		t.Fatalf("got %+v", got)
	}
}

func TestRangeAndNetwork(t *testing.T) {
	c := serve(t, Config{}, func(w http.ResponseWriter, req request, _ map[string]any) {
		switch req.Method {
		case "getHealth":
			reply(w, req.ID, `{"status":"healthy","latestLedger":200,"latestLedgerCloseTime":"1","oldestLedger":80,"oldestLedgerCloseTime":"1","ledgerRetentionWindow":120960}`)
		case "getNetwork":
			reply(w, req.ID, `{"passphrase":"Test SDF Network ; September 2015","protocolVersion":29}`)
		}
	})
	r, err := c.Range(context.Background())
	if err != nil || r.Oldest != 80 || r.Latest != 200 {
		t.Fatalf("range = %+v, %v", r, err)
	}
	p, err := c.NetworkPassphrase(context.Background())
	if err != nil || p != "Test SDF Network ; September 2015" {
		t.Fatalf("passphrase = %q, %v", p, err)
	}
}

func TestHostileResponses(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	cases := []struct {
		name string
		body func(id uint64) string
		want error
	}{
		{"malformed JSON", func(id uint64) string { return `{"jsonrpc":"2.0","id":` }, ErrBadResponse},
		{"trailing data", func(id uint64) string { return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"ledgers":[]}} {}`, id) }, ErrBadResponse},
		{"wrong id", func(id uint64) string { return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"ledgers":[]}}`, id+1) }, ErrBadResponse},
		{"wrong version", func(id uint64) string { return fmt.Sprintf(`{"jsonrpc":"1.0","id":%d,"result":{"ledgers":[]}}`, id) }, ErrBadResponse},
		{"null result", func(id uint64) string { return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":null}`, id) }, ErrBadResponse},
		{"missing ledgers", func(id uint64) string { return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{}}`, id) }, ErrBadResponse},
		{"missing metadataXdr", func(id uint64) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"ledgers":[{"hash":"%s","sequence":1}]}}`, id, hash)
		}, ErrBadResponse},
		{"negative sequence", func(id uint64) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"ledgers":[{"hash":"%s","sequence":-1,"metadataXdr":""}]}}`, id, hash)
		}, ErrBadResponse},
		{"short hash", func(id uint64) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"ledgers":[{"hash":"abcd","sequence":1,"metadataXdr":""}]}}`, id)
		}, ErrBadResponse},
		{"uppercase hash", func(id uint64) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"ledgers":[{"hash":"%s","sequence":1,"metadataXdr":""}]}}`, id, strings.ToUpper(hash))
		}, ErrBadResponse},
		{"bad base64", func(id uint64) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"ledgers":[{"hash":"%s","sequence":1,"metadataXdr":"!!"}]}}`, id, hash)
		}, ErrBadResponse},
		{"oversized body", func(id uint64) string { return strings.Repeat(" ", 2048) }, ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := serve(t, Config{MaxBodyBytes: 1024}, func(w http.ResponseWriter, req request, _ map[string]any) {
				w.Write([]byte(tc.body(req.ID)))
			})
			if _, err := c.Ledgers(context.Background(), 1, 1); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestServerError(t *testing.T) {
	c := serve(t, Config{}, func(w http.ResponseWriter, req request, _ map[string]any) {
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":-32600,"message":"start ledger must be between the oldest and latest ledger"}}`, req.ID)
	})
	_, err := c.Ledgers(context.Background(), 1, 1)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32600 {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPFailures(t *testing.T) {
	t.Run("status 503", func(t *testing.T) {
		c := serve(t, Config{}, func(w http.ResponseWriter, _ request, _ map[string]any) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		if _, err := c.Range(context.Background()); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("redirect refused", func(t *testing.T) {
		c := serve(t, Config{}, func(w http.ResponseWriter, _ request, _ map[string]any) {
			w.Header().Set("Location", "https://example.com/")
			w.WriteHeader(http.StatusTemporaryRedirect)
		})
		if _, err := c.Range(context.Background()); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unhealthy", func(t *testing.T) {
		c := serve(t, Config{}, func(w http.ResponseWriter, req request, _ map[string]any) {
			reply(w, req.ID, `{"status":"unhealthy","latestLedger":2,"oldestLedger":1}`)
		})
		if _, err := c.Range(context.Background()); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		c := serve(t, Config{Timeout: 100 * time.Millisecond}, func(w http.ResponseWriter, req request, _ map[string]any) {
			<-release
		})
		defer close(release)
		start := time.Now()
		_, err := c.Range(context.Background())
		if err == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("err = %v after %v", err, time.Since(start))
		}
	})
}

func TestNewRejectsNonHTTPS(t *testing.T) {
	for _, u := range []string{"http://rpc.example.com", "https://user:pw@rpc.example.com", "rpc.example.com", "https://"} {
		if _, err := New(Config{URL: u}); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
}

func TestLimitBounds(t *testing.T) {
	c, _ := New(Config{URL: DefaultTestnetURL})
	for _, l := range []uint32{0, 201} {
		if _, err := c.Ledgers(context.Background(), 1, l); err == nil {
			t.Errorf("limit %d accepted", l)
		}
	}
}
