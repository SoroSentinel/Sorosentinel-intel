// Package xdrcompat is the only place ingestion touches Stellar XDR. It pins
// the XDR library (go.mod), refuses ledgers from protocols it was not checked
// against, and turns LedgerCloseMeta into the few facts the Phase 1 detectors
// need. Anything it does not recognize is an error, never a skip or a guess
// (ARCHITECTURE §12 step 5).
package xdrcompat

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

// MaxProtocol is the highest ledger protocol version this build accepts.
// The pinned go-stellar-sdk v0.7.3 carries Protocol 28 XDR; on 2026-10-28 it
// decoded 50 live testnet Protocol 29 ledgers and re-encoded them byte for
// byte. Protocol 30 needs v0.8.0+ and the ARCHITECTURE §12 runbook.
const MaxProtocol = 29

// ErrUnknownXDR means the ledger could not be decoded completely and exactly
// by the pinned XDR definitions. Ingestion must halt.
var ErrUnknownXDR = errors.New("xdrcompat: unknown or malformed XDR")

// ErrUnsupportedProtocol means the ledger is from a protocol newer than
// MaxProtocol. Ingestion must halt until the XDR library is upgraded.
var ErrUnsupportedProtocol = errors.New("xdrcompat: unsupported protocol version")

// ErrInvalidData means the XDR decoded but a value breaks a ledger rule this
// package relies on (for example a non-alphanumeric asset code). Halt.
var ErrInvalidData = errors.New("xdrcompat: invalid ledger data")

// Ledger is a decoded ledger's identity plus the extracted facts.
type Ledger struct {
	Sequence     uint32
	Hash         [32]byte
	PreviousHash [32]byte
	Protocol     uint32
	CloseTime    int64 // unix seconds, from the ledger header
	Facts        Facts
}

// Facts are the Phase 1 detector inputs found in one ledger.
type Facts struct {
	// Assets lists each distinct credit asset that gained a trustline in this
	// ledger, in first-seen order. Trustline creation is when a code/issuer
	// pair first becomes holdable, which is what the look-alike detector needs.
	Assets []Asset
	// HomeDomains lists accounts whose home_domain was set or changed, with
	// the final value in this ledger (empty means cleared).
	HomeDomains []HomeDomain
}

// Asset is a classic credit asset. Code is ASCII alphanumeric, 1-12 chars.
type Asset struct {
	Code   string
	Issuer string // G... strkey
}

// HomeDomain is an account's home_domain as written to the ledger. The value
// is untrusted: consumers must normalize and escape it before any use.
type HomeDomain struct {
	Account string // G... strkey
	Domain  string
}

// Decode parses one base64-decoded LedgerCloseMeta, requires every byte to be
// consumed and the re-encoding to match exactly, checks the protocol version
// and extracts facts.
func Decode(raw []byte) (Ledger, error) {
	meta, l, err := decodeMeta(raw)
	if err != nil {
		return Ledger{}, err
	}
	x := newExtractor()
	if err := x.ledger(meta); err != nil {
		return Ledger{}, fmt.Errorf("ledger %d: %w", l.Sequence, err)
	}
	l.Facts = x.facts()
	return l, nil
}

// decodeMeta applies the checks every caller of this package must pass before
// trusting a decoded ledger: exact re-encoding (nothing dropped or normalized
// away) and the protocol gate. It returns the meta and the ledger's identity.
func decodeMeta(raw []byte) (xdr.LedgerCloseMeta, Ledger, error) {
	var meta xdr.LedgerCloseMeta
	if err := xdr.SafeUnmarshal(raw, &meta); err != nil {
		return meta, Ledger{}, fmt.Errorf("%w: %v", ErrUnknownXDR, err)
	}
	// A clean round trip shows nothing was dropped or normalized away.
	again, err := meta.MarshalBinary()
	if err != nil || !bytes.Equal(again, raw) {
		return meta, Ledger{}, fmt.Errorf("%w: re-encoding differs", ErrUnknownXDR)
	}
	hdr, err := header(meta)
	if err != nil {
		return meta, Ledger{}, err
	}
	l := Ledger{
		Sequence:     uint32(hdr.Header.LedgerSeq),
		Hash:         hdr.Hash,
		PreviousHash: hdr.Header.PreviousLedgerHash,
		Protocol:     uint32(hdr.Header.LedgerVersion),
		CloseTime:    int64(hdr.Header.ScpValue.CloseTime),
	}
	if l.Protocol > MaxProtocol {
		return meta, Ledger{}, fmt.Errorf("%w: ledger %d is protocol %d, max %d", ErrUnsupportedProtocol, l.Sequence, l.Protocol, MaxProtocol)
	}
	return meta, l, nil
}

// Module is one deployed contract's WASM as it was written to the ledger.
type Module struct {
	Hash   [32]byte // sha256 of Code, which is also the ContractCode ledger key
	Code   []byte
	Ledger uint32 // sequence of the ledger that wrote it
}

// Modules decodes one LedgerCloseMeta with the same strictness as Decode and
// returns every contract WASM written to that ledger, deduplicated by hash and
// in first-seen order. It exists for the fuzz-seed exporter (cmd/intel-fuzz-seeds):
// the modules are public ledger data used as parser inputs, and nothing here
// analyzes them.
func Modules(raw []byte) ([]Module, error) {
	meta, l, err := decodeMeta(raw)
	if err != nil {
		return nil, err
	}
	lists, err := changeLists(meta)
	if err != nil {
		return nil, err
	}
	var out []Module
	seen := map[[32]byte]bool{}
	for _, list := range lists {
		for _, c := range list {
			e, wrote, err := changedEntry(c)
			if err != nil {
				return nil, err
			}
			if !wrote || e.Data.Type != xdr.LedgerEntryTypeContractCode {
				continue
			}
			cc := e.Data.MustContractCode()
			if len(cc.Code) == 0 {
				return nil, fmt.Errorf("%w: contract code entry without code", ErrInvalidData)
			}
			if got := sha256.Sum256(cc.Code); got != [32]byte(cc.Hash) {
				return nil, fmt.Errorf("%w: contract code sha256 mismatch", ErrInvalidData)
			}
			h := [32]byte(cc.Hash)
			if seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, Module{Hash: h, Code: cc.Code, Ledger: l.Sequence})
		}
	}
	return out, nil
}

// changedEntry reports the entry a change wrote. wrote=false is an entry the
// ledger read or removed, not one it created; an unknown change type is an
// error, never a skip.
func changedEntry(c xdr.LedgerEntryChange) (entry xdr.LedgerEntry, wrote bool, err error) {
	switch c.Type {
	case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
		if c.Created == nil {
			return entry, false, fmt.Errorf("%w: Created without an entry", ErrUnknownXDR)
		}
		return *c.Created, true, nil
	case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
		if c.Updated == nil {
			return entry, false, fmt.Errorf("%w: Updated without an entry", ErrUnknownXDR)
		}
		return *c.Updated, true, nil
	case xdr.LedgerEntryChangeTypeLedgerEntryRestored:
		if c.Restored == nil {
			return entry, false, fmt.Errorf("%w: Restored without an entry", ErrUnknownXDR)
		}
		return *c.Restored, true, nil
	case xdr.LedgerEntryChangeTypeLedgerEntryState, xdr.LedgerEntryChangeTypeLedgerEntryRemoved:
		return entry, false, nil
	default:
		return entry, false, fmt.Errorf("%w: LedgerEntryChangeType %d", ErrUnknownXDR, c.Type)
	}
}

func header(meta xdr.LedgerCloseMeta) (xdr.LedgerHeaderHistoryEntry, error) {
	switch meta.V {
	case 0:
		return meta.MustV0().LedgerHeader, nil
	case 1:
		return meta.MustV1().LedgerHeader, nil
	case 2:
		return meta.MustV2().LedgerHeader, nil
	default:
		return xdr.LedgerHeaderHistoryEntry{}, fmt.Errorf("%w: LedgerCloseMeta v%d", ErrUnknownXDR, meta.V)
	}
}

type extractor struct {
	assets     []Asset
	seenAsset  map[Asset]bool
	domains    map[string]string
	domainSeen []string // accounts in first-seen order
}

func newExtractor() *extractor {
	return &extractor{seenAsset: map[Asset]bool{}, domains: map[string]string{}}
}

func (x *extractor) facts() Facts {
	f := Facts{Assets: x.assets}
	for _, a := range x.domainSeen {
		f.HomeDomains = append(f.HomeDomains, HomeDomain{Account: a, Domain: x.domains[a]})
	}
	return f
}

// ledger walks every LedgerEntryChanges list in the meta. Fee and upgrade
// changes cannot touch trustlines or home domains today, but walking them
// keeps the walk exhaustive if that ever changes.
func (x *extractor) ledger(meta xdr.LedgerCloseMeta) error {
	lists, err := changeLists(meta)
	if err != nil {
		return err
	}
	for _, l := range lists {
		if err := x.changes(l); err != nil {
			return err
		}
	}
	return nil
}

// changeLists returns every LedgerEntryChanges list in one meta, in the order
// the ledger applied them: fee processing, transaction apply (each version's
// own layout), post-transaction fee, then upgrades.
func changeLists(meta xdr.LedgerCloseMeta) ([]xdr.LedgerEntryChanges, error) {
	var lists []xdr.LedgerEntryChanges
	var txMetas []xdr.TransactionMeta
	var upgrades []xdr.UpgradeEntryMeta
	switch meta.V {
	case 0:
		v := meta.MustV0()
		for _, t := range v.TxProcessing {
			lists = append(lists, t.FeeProcessing)
			txMetas = append(txMetas, t.TxApplyProcessing)
		}
		upgrades = v.UpgradesProcessing
	case 1:
		v := meta.MustV1()
		for _, t := range v.TxProcessing {
			lists = append(lists, t.FeeProcessing)
			txMetas = append(txMetas, t.TxApplyProcessing)
		}
		upgrades = v.UpgradesProcessing
	case 2:
		v := meta.MustV2()
		for _, t := range v.TxProcessing {
			lists = append(lists, t.FeeProcessing, t.PostTxApplyFeeProcessing)
			txMetas = append(txMetas, t.TxApplyProcessing)
		}
		upgrades = v.UpgradesProcessing
	default:
		return nil, fmt.Errorf("%w: LedgerCloseMeta v%d", ErrUnknownXDR, meta.V)
	}
	for _, tm := range txMetas {
		l, err := txChanges(tm)
		if err != nil {
			return nil, err
		}
		lists = append(lists, l...)
	}
	for _, u := range upgrades {
		lists = append(lists, u.Changes)
	}
	return lists, nil
}

func txChanges(tm xdr.TransactionMeta) ([]xdr.LedgerEntryChanges, error) {
	var out []xdr.LedgerEntryChanges
	switch tm.V {
	case 0:
		for _, op := range tm.MustOperations() {
			out = append(out, op.Changes)
		}
	case 1:
		v := tm.MustV1()
		out = append(out, v.TxChanges)
		for _, op := range v.Operations {
			out = append(out, op.Changes)
		}
	case 2:
		v := tm.MustV2()
		out = append(out, v.TxChangesBefore)
		for _, op := range v.Operations {
			out = append(out, op.Changes)
		}
		out = append(out, v.TxChangesAfter)
	case 3:
		v := tm.MustV3()
		out = append(out, v.TxChangesBefore)
		for _, op := range v.Operations {
			out = append(out, op.Changes)
		}
		out = append(out, v.TxChangesAfter)
	case 4:
		v := tm.MustV4()
		out = append(out, v.TxChangesBefore)
		for _, op := range v.Operations {
			out = append(out, op.Changes)
		}
		out = append(out, v.TxChangesAfter)
	default:
		return nil, fmt.Errorf("%w: TransactionMeta v%d", ErrUnknownXDR, tm.V)
	}
	return out, nil
}

// changes handles one list. stellar-core writes an entry's prior State (or
// Restored) right before its Updated, so prior home domains are tracked per list.
func (x *extractor) changes(list xdr.LedgerEntryChanges) error {
	prior := map[string]string{}
	for _, c := range list {
		switch c.Type {
		case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
			if err := x.entry(*c.Created, nil); err != nil {
				return err
			}
		case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
			if err := x.entry(*c.Updated, prior); err != nil {
				return err
			}
		case xdr.LedgerEntryChangeTypeLedgerEntryState:
			if err := remember(*c.State, prior); err != nil {
				return err
			}
		case xdr.LedgerEntryChangeTypeLedgerEntryRestored:
			if err := remember(*c.Restored, prior); err != nil {
				return err
			}
		case xdr.LedgerEntryChangeTypeLedgerEntryRemoved:
			// Removals (merged accounts, deleted trustlines) are not Phase 1 inputs.
		default:
			return fmt.Errorf("%w: LedgerEntryChangeType %d", ErrUnknownXDR, c.Type)
		}
	}
	return nil
}

func remember(e xdr.LedgerEntry, prior map[string]string) error {
	if e.Data.Type != xdr.LedgerEntryTypeAccount {
		return nil
	}
	acct := e.Data.MustAccount()
	addr, err := address(acct.AccountId)
	if err != nil {
		return err
	}
	prior[addr] = string(acct.HomeDomain)
	return nil
}

// entry records facts from a created (prior == nil) or updated entry.
func (x *extractor) entry(e xdr.LedgerEntry, prior map[string]string) error {
	switch e.Data.Type {
	case xdr.LedgerEntryTypeAccount:
		acct := e.Data.MustAccount()
		addr, err := address(acct.AccountId)
		if err != nil {
			return err
		}
		d := string(acct.HomeDomain)
		if prior == nil {
			if d == "" {
				return nil
			}
		} else if old, ok := prior[addr]; ok && old == d {
			return nil
		}
		// An update with no prior State is reported, not assumed unchanged.
		if _, ok := x.domains[addr]; !ok {
			x.domainSeen = append(x.domainSeen, addr)
		}
		x.domains[addr] = d
	case xdr.LedgerEntryTypeTrustline:
		if prior != nil {
			return nil
		}
		a, ok, err := trustlineAsset(e.Data.MustTrustLine().Asset)
		if err != nil || !ok {
			return err
		}
		if !x.seenAsset[a] {
			x.seenAsset[a] = true
			x.assets = append(x.assets, a)
		}
	}
	return nil
}

// trustlineAsset returns ok=false for pool-share trustlines, which have no code.
func trustlineAsset(t xdr.TrustLineAsset) (Asset, bool, error) {
	var code []byte
	var issuer xdr.AccountId
	switch t.Type {
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		a := t.MustAlphaNum4()
		code, issuer = a.AssetCode[:], a.Issuer
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		a := t.MustAlphaNum12()
		code, issuer = a.AssetCode[:], a.Issuer
	case xdr.AssetTypeAssetTypePoolShare:
		return Asset{}, false, nil
	case xdr.AssetTypeAssetTypeNative:
		return Asset{}, false, fmt.Errorf("%w: native trustline", ErrInvalidData)
	default:
		return Asset{}, false, fmt.Errorf("%w: AssetType %d", ErrUnknownXDR, t.Type)
	}
	iss, err := address(issuer)
	if err != nil {
		return Asset{}, false, err
	}
	c := string(bytes.TrimRight(code, "\x00"))
	// The canonical key check rejects embedded NULs and non-alphanumerics.
	if _, err := entity.NormalizeKey(entity.Asset, c+":"+iss); err != nil {
		return Asset{}, false, fmt.Errorf("%w: asset code: %v", ErrInvalidData, err)
	}
	return Asset{Code: c, Issuer: iss}, true, nil
}

func address(id xdr.AccountId) (string, error) {
	a, err := id.GetAddress()
	if err != nil || a == "" {
		return "", fmt.Errorf("%w: account id: %v", ErrUnknownXDR, err)
	}
	return a, nil
}

// AccountKey returns the base64 XDR LedgerKey of a G... account, for RPC
// getLedgerEntries.
func AccountKey(account string) (string, error) {
	if _, err := entity.NormalizeKey(entity.Account, account); err != nil {
		return "", fmt.Errorf("%w: account: %v", ErrInvalidData, err)
	}
	var id xdr.AccountId
	if err := id.SetAddress(account); err != nil {
		return "", fmt.Errorf("%w: account: %v", ErrInvalidData, err)
	}
	var key xdr.LedgerKey
	if err := key.SetAccount(id); err != nil {
		return "", fmt.Errorf("%w: account key: %v", ErrInvalidData, err)
	}
	return xdr.MarshalBase64(key)
}

// AccountHomeDomain decodes a base64 LedgerEntryData (getLedgerEntries
// `xdr`), requires it to be the given account's entry and returns its
// home_domain (empty when unset). The value is untrusted.
func AccountHomeDomain(account, entryData string) (string, error) {
	var d xdr.LedgerEntryData
	if err := xdr.SafeUnmarshalBase64(entryData, &d); err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnknownXDR, err)
	}
	again, err := xdr.MarshalBase64(d)
	if err != nil || again != entryData {
		return "", fmt.Errorf("%w: re-encoding differs", ErrUnknownXDR)
	}
	if d.Type != xdr.LedgerEntryTypeAccount {
		return "", fmt.Errorf("%w: entry is not an account", ErrInvalidData)
	}
	acct := d.MustAccount()
	addr, err := address(acct.AccountId)
	if err != nil {
		return "", err
	}
	if addr != account {
		return "", fmt.Errorf("%w: entry is for another account", ErrInvalidData)
	}
	return string(acct.HomeDomain), nil
}
