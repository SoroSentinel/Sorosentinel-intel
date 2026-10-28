// Package xdrtest builds small synthetic LedgerCloseMeta values for tests.
// Accounts are derived from a single byte, so fixtures hold no real data.
package xdrtest

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Address is the G... strkey of synthetic account n.
func Address(n byte) string {
	var k [32]byte
	for i := range k {
		k[i] = n
	}
	s, err := strkey.Encode(strkey.VersionByteAccountID, k[:])
	if err != nil {
		panic(err)
	}
	return s
}

func accountID(n byte) xdr.AccountId { return xdr.MustAddress(Address(n)) }

// Account is an account entry for synthetic account n.
func Account(n byte, homeDomain string) xdr.LedgerEntry {
	return xdr.LedgerEntry{Data: xdr.LedgerEntryData{
		Type: xdr.LedgerEntryTypeAccount,
		Account: &xdr.AccountEntry{
			AccountId:  accountID(n),
			Balance:    100_0000000,
			HomeDomain: xdr.String32(homeDomain),
			Thresholds: xdr.Thresholds{1, 0, 0, 0},
		},
	}}
}

// Trustline is holder's trustline to code issued by issuer. Codes of 1-4
// bytes use AlphaNum4, longer ones AlphaNum12; bytes are copied verbatim.
func Trustline(holder byte, code string, issuer byte) xdr.LedgerEntry {
	a := xdr.TrustLineAsset{}
	if len(code) <= 4 {
		var c xdr.AssetCode4
		copy(c[:], code)
		a.Type, a.AlphaNum4 = xdr.AssetTypeAssetTypeCreditAlphanum4, &xdr.AlphaNum4{AssetCode: c, Issuer: accountID(issuer)}
	} else {
		var c xdr.AssetCode12
		copy(c[:], code)
		a.Type, a.AlphaNum12 = xdr.AssetTypeAssetTypeCreditAlphanum12, &xdr.AlphaNum12{AssetCode: c, Issuer: accountID(issuer)}
	}
	return xdr.LedgerEntry{Data: xdr.LedgerEntryData{
		Type:      xdr.LedgerEntryTypeTrustline,
		TrustLine: &xdr.TrustLineEntry{AccountId: accountID(holder), Asset: a, Limit: 1_000_0000000},
	}}
}

// PoolShareTrustline is a liquidity-pool-share trustline (no code/issuer).
func PoolShareTrustline(holder byte) xdr.LedgerEntry {
	return xdr.LedgerEntry{Data: xdr.LedgerEntryData{
		Type: xdr.LedgerEntryTypeTrustline,
		TrustLine: &xdr.TrustLineEntry{
			AccountId: accountID(holder),
			Asset:     xdr.TrustLineAsset{Type: xdr.AssetTypeAssetTypePoolShare, LiquidityPoolId: &xdr.PoolId{1}},
		},
	}}
}

func Created(e xdr.LedgerEntry) xdr.LedgerEntryChange {
	return xdr.LedgerEntryChange{Type: xdr.LedgerEntryChangeTypeLedgerEntryCreated, Created: &e}
}

func Updated(e xdr.LedgerEntry) xdr.LedgerEntryChange {
	return xdr.LedgerEntryChange{Type: xdr.LedgerEntryChangeTypeLedgerEntryUpdated, Updated: &e}
}

func State(e xdr.LedgerEntry) xdr.LedgerEntryChange {
	return xdr.LedgerEntryChange{Type: xdr.LedgerEntryChangeTypeLedgerEntryState, State: &e}
}

// Ledger describes one synthetic ledger. Each element of Ops becomes one
// successful transaction with a single operation carrying those changes.
type Ledger struct {
	Seq      uint32
	Prev     xdr.Hash
	Protocol uint32
	Ops      []xdr.LedgerEntryChanges
}

// Hash is the synthetic header hash for seq.
func Hash(seq uint32) xdr.Hash {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], seq)
	return sha256.Sum256(b[:])
}

// Meta returns the LedgerCloseMeta (v2, TransactionMeta v4) for l.
func (l Ledger) Meta() xdr.LedgerCloseMeta {
	if l.Protocol == 0 {
		l.Protocol = 29
	}
	var txs []xdr.TransactionResultMetaV1
	for _, ch := range l.Ops {
		txs = append(txs, xdr.TransactionResultMetaV1{
			Result: xdr.TransactionResultPair{Result: xdr.TransactionResult{
				Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}},
			}},
			TxApplyProcessing: xdr.TransactionMeta{V: 4, V4: &xdr.TransactionMetaV4{
				Operations: []xdr.OperationMetaV2{{Changes: ch}},
			}},
		})
	}
	return xdr.LedgerCloseMeta{V: 2, V2: &xdr.LedgerCloseMetaV2{
		LedgerHeader: xdr.LedgerHeaderHistoryEntry{
			Hash: Hash(l.Seq),
			Header: xdr.LedgerHeader{
				LedgerVersion:      xdr.Uint32(l.Protocol),
				PreviousLedgerHash: l.Prev,
				LedgerSeq:          xdr.Uint32(l.Seq),
				ScpValue:           xdr.StellarValue{CloseTime: xdr.TimePoint(1_790_000_000 + uint64(l.Seq)*5)},
			},
		},
		TxSet:        xdr.GeneralizedTransactionSet{V: 1, V1TxSet: &xdr.TransactionSetV1{}},
		TxProcessing: txs,
	}}
}

// Bytes is the XDR encoding of l.Meta().
func (l Ledger) Bytes() []byte {
	b, err := l.Meta().MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

// Chain returns ledgers from..to linked by previous-hash, with ops[seq]
// as each ledger's changes.
func Chain(from, to uint32, ops map[uint32][]xdr.LedgerEntryChanges) []Ledger {
	var out []Ledger
	for s := from; s <= to; s++ {
		out = append(out, Ledger{Seq: s, Prev: Hash(s - 1), Ops: ops[s]})
	}
	return out
}
