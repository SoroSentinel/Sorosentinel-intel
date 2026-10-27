package wording

import (
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

// SlotType is the only kind of value a template slot accepts. There is no
// free-text slot type, by design.
type SlotType string

const (
	SlotTimestamp SlotType = "timestamp"
	SlotAccount   SlotType = "account"
	SlotAssetKey  SlotType = "asset_key"
	SlotContract  SlotType = "contract"
	SlotWasmHash  SlotType = "wasm_hash"
	SlotDomain    SlotType = "domain"
	SlotLedger    SlotType = "ledger"
	SlotSignerKey SlotType = "signer_key"
	SlotWeight    SlotType = "weight"
)

func (t SlotType) valid() bool {
	switch t {
	case SlotTimestamp, SlotAccount, SlotAssetKey, SlotContract, SlotWasmHash, SlotDomain, SlotLedger, SlotSignerKey, SlotWeight:
		return true
	}
	return false
}

var signerKeyRe = regexp.MustCompile(`^(?:[GTX][A-Z2-7]{55}|P[A-Z2-7]{60,200})$`)

// displayTime is the human form of a timestamp in rendered text; facts keep RFC 3339.
const displayTime = "2006-01-02 15:04 UTC"

// Value is a validated, typed slot value. Construct with NewValue or Timestamp.
type Value struct {
	typ     SlotType
	display string
	fact    string
}

func (v Value) Type() SlotType { return v.typ }

// Timestamp builds a timestamp slot value.
func Timestamp(t time.Time) (Value, error) {
	if t.IsZero() {
		return Value{}, &Error{Code: ErrInvalidSlotValue, Detail: "zero timestamp"}
	}
	u := t.UTC()
	return Value{typ: SlotTimestamp, display: u.Format(displayTime), fact: u.Format(time.RFC3339)}, nil
}

// NewValue validates raw as typ. Untrusted strings with control or bidi
// characters are rejected, and every accepted value matches a strict ASCII shape.
func NewValue(typ SlotType, raw string) (Value, error) {
	if !utf8.ValidString(raw) || hasUnsafeRune(raw) {
		return Value{}, &Error{Code: ErrInvalidSlotValue, Detail: "control or bidi character"}
	}
	switch typ {
	case SlotTimestamp:
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return Value{}, &Error{Code: ErrInvalidSlotValue, Detail: "timestamp must be RFC 3339"}
		}
		return Timestamp(t)
	case SlotSignerKey:
		// Shape only: G (ed25519), T (pre-auth tx), X (hash-x), P (signed payload).
		// TODO(verify): strkey checksums need the Stellar SDK.
		if !signerKeyRe.MatchString(raw) {
			return Value{}, &Error{Code: ErrInvalidSlotValue, Detail: "not a signer strkey"}
		}
		return Value{typ: typ, display: raw, fact: raw}, nil
	case SlotWeight:
		n, err := strconv.ParseUint(raw, 10, 8)
		if err != nil {
			return Value{}, &Error{Code: ErrInvalidSlotValue, Detail: "weight must be an integer from 0 to 255"}
		}
		s := strconv.FormatUint(n, 10)
		return Value{typ: typ, display: s, fact: s}, nil
	case SlotLedger:
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || n == 0 {
			return Value{}, &Error{Code: ErrInvalidSlotValue, Detail: "ledger must be a positive 32-bit integer"}
		}
		s := strconv.FormatUint(n, 10)
		return Value{typ: typ, display: s, fact: s}, nil
	case SlotAccount, SlotAssetKey, SlotContract, SlotWasmHash, SlotDomain:
		norm, err := entity.NormalizeKey(entityType(typ), raw)
		if err != nil {
			return Value{}, &Error{Code: ErrInvalidSlotValue, Detail: err.Error()}
		}
		return Value{typ: typ, display: norm, fact: norm}, nil
	default:
		return Value{}, &Error{Code: ErrSlotTypeMismatch, Detail: "unknown slot type " + string(typ)}
	}
}

func entityType(t SlotType) entity.Type {
	switch t {
	case SlotAccount:
		return entity.Account
	case SlotAssetKey:
		return entity.Asset
	case SlotContract:
		return entity.Contract
	case SlotWasmHash:
		return entity.WasmHash
	default:
		return entity.Domain
	}
}

func hasUnsafeRune(s string) bool {
	for _, r := range s {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0:
			return true
		case r == 0x061c, r == 0x200e, r == 0x200f,
			r >= 0x202a && r <= 0x202e,
			r >= 0x2066 && r <= 0x2069:
			return true
		}
	}
	return false
}
