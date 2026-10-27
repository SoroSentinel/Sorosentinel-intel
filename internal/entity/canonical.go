// Package entity implements the canonical entity-key encoding
// (schemas/canonical-key.md). Go, Rust and TypeScript must agree byte-for-byte,
// which the shared vectors in schemas/vectors/canonical_keys.json enforce.
package entity

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

type Network string

const (
	Public  Network = "public"
	Testnet Network = "testnet"
)

type Type string

const (
	Account  Type = "account"
	Asset    Type = "asset"
	Contract Type = "contract"
	WasmHash Type = "wasm_hash"
	Domain   Type = "domain"
)

// ErrorCode values are shared with the other repos through the vectors.
type ErrorCode string

const (
	ErrUnknownNetwork     ErrorCode = "unknown_network"
	ErrUnknownType        ErrorCode = "unknown_type"
	ErrInvalidKey         ErrorCode = "invalid_key"
	ErrMuxedNotNormalized ErrorCode = "muxed_not_normalized"
	ErrNonASCII           ErrorCode = "non_ascii"
)

type Error struct {
	Code ErrorCode
}

func (e *Error) Error() string { return "entity key: " + string(e.Code) }

const maxKeyLen = 300

var (
	// TODO(verify): shape only; strkey CRC16 checksum needs the Stellar SDK.
	accountRe   = regexp.MustCompile(`^G[A-Z2-7]{55}$`)
	contractRe  = regexp.MustCompile(`^C[A-Z2-7]{55}$`)
	assetCodeRe = regexp.MustCompile(`^[A-Za-z0-9]{1,12}$`)
	wasmHashRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	labelRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Canonical returns "<network>|<type>|<normalized key>".
func Canonical(network Network, typ Type, key string) (string, error) {
	if network != Public && network != Testnet {
		return "", &Error{ErrUnknownNetwork}
	}
	norm, err := NormalizeKey(typ, key)
	if err != nil {
		return "", err
	}
	return string(network) + "|" + string(typ) + "|" + norm, nil
}

// SnapshotHash returns the first 128 bits of SHA-256(canonical), lowercase hex.
func SnapshotHash(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:16])
}

// NormalizeKey validates key for typ and returns its canonical form.
func NormalizeKey(typ Type, key string) (string, error) {
	if len(key) == 0 || len(key) > maxKeyLen {
		return "", &Error{ErrInvalidKey}
	}
	switch typ {
	case Account:
		return normalizeAccount(key)
	case Asset:
		return normalizeAsset(key)
	case Contract:
		if !contractRe.MatchString(key) {
			return "", &Error{ErrInvalidKey}
		}
		return key, nil
	case WasmHash:
		k := strings.ToLower(key)
		if !wasmHashRe.MatchString(k) {
			return "", &Error{ErrInvalidKey}
		}
		return k, nil
	case Domain:
		return normalizeDomain(key)
	default:
		return "", &Error{ErrUnknownType}
	}
}

func normalizeAccount(key string) (string, error) {
	if strings.HasPrefix(key, "M") {
		return "", &Error{ErrMuxedNotNormalized}
	}
	if !accountRe.MatchString(key) {
		return "", &Error{ErrInvalidKey}
	}
	return key, nil
}

func normalizeAsset(key string) (string, error) {
	if key == "native" {
		return key, nil
	}
	code, issuer, ok := strings.Cut(key, ":")
	if !ok || !assetCodeRe.MatchString(code) {
		return "", &Error{ErrInvalidKey}
	}
	issuer, err := normalizeAccount(issuer)
	if err != nil {
		return "", err
	}
	return code + ":" + issuer, nil
}

func normalizeDomain(key string) (string, error) {
	for i := 0; i < len(key); i++ {
		if key[i] >= 0x80 {
			return "", &Error{ErrNonASCII}
		}
	}
	d := strings.TrimSuffix(strings.ToLower(key), ".")
	if len(d) > 253 {
		return "", &Error{ErrInvalidKey}
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", &Error{ErrInvalidKey}
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", &Error{ErrInvalidKey}
		}
	}
	return d, nil
}
