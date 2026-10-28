package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
)

func TestHomeDomain(t *testing.T) {
	acct := xdrtest.Address(7)
	key, err := xdrcompat.AccountKey(acct)
	if err != nil {
		t.Fatal(err)
	}
	data := func(n byte, domain string) string {
		s, err := xdr.MarshalBase64(xdrtest.Account(n, domain).Data)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := map[string]struct {
		result     string
		wantDomain string
		wantFound  bool
		wantErr    bool
	}{
		"found":         {`{"entries":[{"key":"` + key + `","xdr":"` + data(7, "example.org") + `","lastModifiedLedgerSeq":5,"extXdr":"AAAAAA=="}],"latestLedger":9}`, "example.org", true, false},
		"unset":         {`{"entries":[{"key":"` + key + `","xdr":"` + data(7, "") + `","lastModifiedLedgerSeq":5}],"latestLedger":9}`, "", true, false},
		"missing":       {`{"entries":[],"latestLedger":9}`, "", false, false},
		"missing null":  {`{"entries":null,"latestLedger":9}`, "", false, false},
		"no latest":     {`{"entries":[]}`, "", false, true},
		"two entries":   {`{"entries":[{"key":"` + key + `","xdr":"` + data(7, "") + `"},{"key":"` + key + `","xdr":"` + data(7, "") + `"}],"latestLedger":9}`, "", false, true},
		"other key":     {`{"entries":[{"key":"AAAA","xdr":"` + data(7, "") + `"}],"latestLedger":9}`, "", false, true},
		"other account": {`{"entries":[{"key":"` + key + `","xdr":"` + data(8, "example.org") + `"}],"latestLedger":9}`, "", false, true},
		"no xdr":        {`{"entries":[{"key":"` + key + `"}],"latestLedger":9}`, "", false, true},
		"garbage xdr":   {`{"entries":[{"key":"` + key + `","xdr":"AAAA"}],"latestLedger":9}`, "", false, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cl := serve(t, Config{}, func(w http.ResponseWriter, req request, raw map[string]any) {
				p, _ := json.Marshal(raw["params"])
				if req.Method != "getLedgerEntries" || string(p) != `{"keys":["`+key+`"],"xdrFormat":"base64"}` {
					t.Errorf("request = %s %s", req.Method, p)
				}
				reply(w, req.ID, c.result)
			})
			d, found, err := cl.HomeDomain(context.Background(), acct)
			if (err != nil) != c.wantErr || d != c.wantDomain || found != c.wantFound {
				t.Errorf("got (%q, %v, %v)", d, found, err)
			}
		})
	}
}

func TestHomeDomainRejectsBadAccount(t *testing.T) {
	cl := serve(t, Config{}, func(w http.ResponseWriter, req request, _ map[string]any) {
		t.Error("request sent for an invalid account")
	})
	if _, _, err := cl.HomeDomain(context.Background(), "M"+xdrtest.Address(7)[1:]); !errors.Is(err, xdrcompat.ErrInvalidData) {
		t.Errorf("err = %v", err)
	}
}
