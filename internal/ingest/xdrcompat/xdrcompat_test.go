package xdrcompat_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
)

func TestDecodeExtractsAssetsAndHomeDomains(t *testing.T) {
	l := xdrtest.Ledger{Seq: 100, Prev: xdrtest.Hash(99), Ops: []xdr.LedgerEntryChanges{
		// Two trustlines to USDC:issuer3 and one to a 12-char code: deduped.
		{xdrtest.Created(xdrtest.Trustline(1, "USDC", 3))},
		{xdrtest.Created(xdrtest.Trustline(2, "USDC", 3)), xdrtest.Created(xdrtest.Trustline(2, "LONGCODE1234", 4))},
		// Home domain changed, unchanged, newly created, cleared.
		{xdrtest.State(xdrtest.Account(3, "old.example")), xdrtest.Updated(xdrtest.Account(3, "new.example"))},
		{xdrtest.State(xdrtest.Account(5, "same.example")), xdrtest.Updated(xdrtest.Account(5, "same.example"))},
		{xdrtest.Created(xdrtest.Account(6, "fresh.example")), xdrtest.Created(xdrtest.Account(7, ""))},
		{xdrtest.State(xdrtest.Account(8, "gone.example")), xdrtest.Updated(xdrtest.Account(8, ""))},
		// Updated trustlines and pool shares are not asset sightings.
		{xdrtest.Updated(xdrtest.Trustline(1, "EURC", 3)), xdrtest.Created(xdrtest.PoolShareTrustline(1))},
	}}
	got, err := xdrcompat.Decode(l.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 100 || got.Hash != xdrtest.Hash(100) || got.PreviousHash != xdrtest.Hash(99) || got.Protocol != 29 {
		t.Fatalf("header = %+v", got)
	}
	wantAssets := []xdrcompat.Asset{
		{Code: "USDC", Issuer: xdrtest.Address(3)},
		{Code: "LONGCODE1234", Issuer: xdrtest.Address(4)},
	}
	if !reflect.DeepEqual(got.Facts.Assets, wantAssets) {
		t.Errorf("assets = %+v", got.Facts.Assets)
	}
	wantDomains := []xdrcompat.HomeDomain{
		{Account: xdrtest.Address(3), Domain: "new.example"},
		{Account: xdrtest.Address(6), Domain: "fresh.example"},
		{Account: xdrtest.Address(8), Domain: ""},
	}
	if !reflect.DeepEqual(got.Facts.HomeDomains, wantDomains) {
		t.Errorf("home domains = %+v", got.Facts.HomeDomains)
	}
}

func TestDecodeHalts(t *testing.T) {
	good := xdrtest.Ledger{Seq: 7, Prev: xdrtest.Hash(6)}.Bytes()

	unknownMeta := append([]byte{}, good...)
	unknownMeta[3] = 9 // LedgerCloseMeta v9

	unknownTxMeta := xdrtest.Ledger{Seq: 7, Ops: []xdr.LedgerEntryChanges{{}}}.Meta()
	unknownTxMeta.V2.TxProcessing[0].TxApplyProcessing.V = 5
	unknownTxMetaBytes := encodeLoosely(t, unknownTxMeta)

	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, xdrcompat.ErrUnknownXDR},
		{"truncated", good[:len(good)-4], xdrcompat.ErrUnknownXDR},
		{"trailing bytes", append(append([]byte{}, good...), 0, 0, 0, 0), xdrcompat.ErrUnknownXDR},
		{"unknown LedgerCloseMeta version", unknownMeta, xdrcompat.ErrUnknownXDR},
		{"unknown TransactionMeta version", unknownTxMetaBytes, xdrcompat.ErrUnknownXDR},
		{"protocol 30", xdrtest.Ledger{Seq: 7, Protocol: 30}.Bytes(), xdrcompat.ErrUnsupportedProtocol},
		{"asset code with embedded NUL", xdrtest.Ledger{Seq: 7, Ops: []xdr.LedgerEntryChanges{
			{xdrtest.Created(xdrtest.Trustline(1, "U\x00SD", 3))}}}.Bytes(), xdrcompat.ErrInvalidData},
		{"asset code with non-alphanumeric", xdrtest.Ledger{Seq: 7, Ops: []xdr.LedgerEntryChanges{
			{xdrtest.Created(xdrtest.Trustline(1, "US-D", 3))}}}.Bytes(), xdrcompat.ErrInvalidData},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := xdrcompat.Decode(c.raw)
			t.Log(err)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// encodeLoosely encodes meta with its TransactionMeta version patched after
// encoding, since the encoder refuses unknown union arms.
func encodeLoosely(t *testing.T, meta xdr.LedgerCloseMeta) []byte {
	t.Helper()
	tm := &meta.V2.TxProcessing[0].TxApplyProcessing
	bad := tm.V
	tm.V = 4
	b, err := meta.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Find the encoded TransactionMeta and patch its discriminant.
	inner, _ := tm.MarshalBinary()
	for i := 0; i+len(inner) <= len(b); i++ {
		if string(b[i:i+len(inner)]) == string(inner) {
			b[i+3] = byte(bad)
			return b
		}
	}
	t.Fatal("TransactionMeta not found in encoding")
	return nil
}
