package xdrcompat_test

import (
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
)

func entryData(t *testing.T, e xdr.LedgerEntry) string {
	t.Helper()
	s, err := xdr.MarshalBase64(e.Data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAccountKeyRoundTrips(t *testing.T) {
	k, err := xdrcompat.AccountKey(xdrtest.Address(7))
	if err != nil {
		t.Fatal(err)
	}
	var key xdr.LedgerKey
	if err := xdr.SafeUnmarshalBase64(k, &key); err != nil || key.Type != xdr.LedgerEntryTypeAccount {
		t.Fatalf("key = %v, %v", key, err)
	}
	if got := key.MustAccount().AccountId.Address(); got != xdrtest.Address(7) {
		t.Errorf("key account = %s", got)
	}
	for _, bad := range []string{"", "M" + xdrtest.Address(7)[1:], "CAAAA", xdrtest.Address(7)[:55] + "A"} {
		if _, err := xdrcompat.AccountKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAccountHomeDomain(t *testing.T) {
	d, err := xdrcompat.AccountHomeDomain(xdrtest.Address(7), entryData(t, xdrtest.Account(7, "example.org")))
	if err != nil || d != "example.org" {
		t.Fatalf("domain = %q, %v", d, err)
	}
	if d, err := xdrcompat.AccountHomeDomain(xdrtest.Address(7), entryData(t, xdrtest.Account(7, ""))); err != nil || d != "" {
		t.Errorf("unset domain = %q, %v", d, err)
	}
	cases := map[string]struct {
		data string
		want error
	}{
		"other account": {entryData(t, xdrtest.Account(8, "example.org")), xdrcompat.ErrInvalidData},
		"trustline":     {entryData(t, xdrtest.Trustline(7, "USDC", 1)), xdrcompat.ErrInvalidData},
		"garbage":       {"AAAA", xdrcompat.ErrUnknownXDR},
		"not base64":    {"%%%", xdrcompat.ErrUnknownXDR},
		"trailing":      {entryData(t, xdrtest.Account(7, "")) + "AAAA", xdrcompat.ErrUnknownXDR},
	}
	for name, c := range cases {
		if _, err := xdrcompat.AccountHomeDomain(xdrtest.Address(7), c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}
