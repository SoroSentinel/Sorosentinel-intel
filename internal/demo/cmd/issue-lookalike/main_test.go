package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func fakeRPC(t *testing.T, body string) (*client, *atomic.Int32) {
	t.Helper()
	var friendbot atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			friendbot.Add(1)
			return
		}
		w.Write([]byte(body)) //nolint:errcheck // test server
	}))
	t.Cleanup(srv.Close)
	return &client{rpcURL: srv.URL, friendbot: srv.URL, http: srv.Client()}, &friendbot
}

func TestRunRefusesNonTestnet(t *testing.T) {
	c, friendbot := fakeRPC(t, `{"jsonrpc":"2.0","id":1,"result":{"passphrase":"`+network.PublicNetworkPassphrase+`"}}`)
	_, err := run(context.Background(), c, "USDC", "example.com", defaultReferenceIssuer)
	if err == nil || !strings.Contains(err.Error(), "testnet only") {
		t.Fatalf("want a testnet-only refusal, got %v", err)
	}
	if friendbot.Load() != 0 {
		t.Fatal("funded accounts before checking the network")
	}
}

func TestCallRejectsHostileResponses(t *testing.T) {
	for name, body := range map[string]string{
		"rpc error":       `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"<script>"}}`,
		"no result":       `{"jsonrpc":"2.0","id":1}`,
		"malformed":       `{"result":`,
		"wrong type":      `{"result":{"passphrase":7}}`,
		"too large":       `{"result":{"passphrase":"` + strings.Repeat("a", maxResponseBytes) + `"}}`,
		"not json at all": "\x00\xff",
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := fakeRPC(t, body)
			if _, err := c.passphrase(context.Background()); err == nil {
				t.Fatal("accepted a hostile response")
			}
		})
	}
}

func TestChangeTrustRejectsBadAssets(t *testing.T) {
	for _, code := range []string{"", "THIRTEENCHARS", "US DC"} {
		if _, err := changeTrust(code, defaultReferenceIssuer); err == nil {
			t.Errorf("accepted asset code %q", code)
		}
	}
	if _, err := changeTrust("USDC", "not-an-account"); err == nil {
		t.Error("accepted a bad issuer")
	}
	op, err := changeTrust("USDC", defaultReferenceIssuer)
	if err != nil || op.Type != xdr.OperationTypeChangeTrust || op.ChangeTrustOp.Limit != xdr.Int64(maxTrustlineLimit) {
		t.Fatalf("changeTrust: %+v %v", op, err)
	}
}
