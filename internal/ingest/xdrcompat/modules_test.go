package xdrcompat_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
)

func TestModulesReturnsContractCodeWrittenToTheLedger(t *testing.T) {
	first, second := []byte("\x00asm\x01\x00\x00\x00first"), []byte("\x00asm\x01\x00\x00\x00second")
	l := xdrtest.Ledger{Seq: 100, Prev: xdrtest.Hash(99), Ops: []xdr.LedgerEntryChanges{
		{xdrtest.Created(xdrtest.ContractModule(first))},
		// An account update and a repeated module: ignored and deduped.
		{xdrtest.State(xdrtest.Account(1, "a.example")),
			xdrtest.Updated(xdrtest.Account(1, "b.example")),
			xdrtest.Created(xdrtest.ContractModule(first))},
		{xdrtest.Created(xdrtest.ContractModule(second))},
	}}
	got, err := xdrcompat.Modules(l.Bytes())
	if err != nil {
		t.Fatalf("Modules: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("modules = %d, want 2 (deduplicated, first-seen order)", len(got))
	}
	want := [][]byte{first, second}
	for i, m := range got {
		if !reflect.DeepEqual(m.Code, want[i]) {
			t.Errorf("module %d code = %q, want %q", i, m.Code, want[i])
		}
		if m.Ledger != 100 {
			t.Errorf("module %d ledger = %d, want 100", i, m.Ledger)
		}
	}
	if again, err := xdrcompat.Modules(l.Bytes()); err != nil || !reflect.DeepEqual(again, got) {
		t.Errorf("second call differs: %v / %v", again, err)
	}
}

func TestModulesRejectsABadHash(t *testing.T) {
	code := []byte("\x00asm\x01\x00\x00\x00payload")
	other := xdr.Hash{9, 9, 9} // not sha256(code)
	l := xdrtest.Ledger{Seq: 5, Prev: xdrtest.Hash(4), Ops: []xdr.LedgerEntryChanges{
		{xdrtest.Created(xdrtest.ContractModuleWith(other, code))},
	}}
	if _, err := xdrcompat.Modules(l.Bytes()); !errors.Is(err, xdrcompat.ErrInvalidData) {
		t.Fatalf("err = %v, want ErrInvalidData", err)
	}
}

func TestModulesRejectsAnEmptyCode(t *testing.T) {
	l := xdrtest.Ledger{Seq: 5, Prev: xdrtest.Hash(4), Ops: []xdr.LedgerEntryChanges{
		{xdrtest.Created(xdrtest.ContractModuleWith(xdr.Hash{}, nil))},
	}}
	if _, err := xdrcompat.Modules(l.Bytes()); !errors.Is(err, xdrcompat.ErrInvalidData) {
		t.Fatalf("err = %v, want ErrInvalidData", err)
	}
}

func TestModulesHaltsOnMalformedXDR(t *testing.T) {
	full := xdrtest.Ledger{Seq: 5, Prev: xdrtest.Hash(4), Ops: []xdr.LedgerEntryChanges{
		{xdrtest.Created(xdrtest.ContractModule([]byte("\x00asm\x01\x00\x00\x00x")))},
	}}.Bytes()
	for _, cut := range []int{len(full) / 2, len(full) - 1} {
		if _, err := xdrcompat.Modules(full[:cut]); !errors.Is(err, xdrcompat.ErrUnknownXDR) {
			t.Errorf("truncated to %d: err = %v, want ErrUnknownXDR", cut, err)
		}
	}
	if _, err := xdrcompat.Modules(nil); !errors.Is(err, xdrcompat.ErrUnknownXDR) {
		t.Errorf("nil: err = %v, want ErrUnknownXDR", err)
	}
}

// A ledger newer than the pinned XDR must be refused, not partially decoded:
// the same gate ingestion uses, so seeds can never be built from a protocol
// this build cannot read.
func TestModulesRefusesNewerProtocols(t *testing.T) {
	l := xdrtest.Ledger{Seq: 5, Prev: xdrtest.Hash(4), Protocol: xdrcompat.MaxProtocol + 1,
		Ops: []xdr.LedgerEntryChanges{{xdrtest.Created(xdrtest.ContractModule([]byte("\x00asm\x01\x00\x00\x00x")))}}}
	if _, err := xdrcompat.Modules(l.Bytes()); !errors.Is(err, xdrcompat.ErrUnsupportedProtocol) {
		t.Fatalf("err = %v, want ErrUnsupportedProtocol", err)
	}
}

// A ledger that wrote no contract must yield nothing and no error, so a long
// run over quiet ledgers is normal, not a failure.
func TestModulesOnLedgerWithoutContracts(t *testing.T) {
	l := xdrtest.Ledger{Seq: 5, Prev: xdrtest.Hash(4), Ops: []xdr.LedgerEntryChanges{
		{xdrtest.Created(xdrtest.Trustline(1, "USDC", 2))},
	}}
	got, err := xdrcompat.Modules(l.Bytes())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %d modules, err %v; want 0, nil", len(got), err)
	}
}
