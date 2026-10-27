// Package signal maps internal verdict levels to public signal names.
// This is the single mapping function; internal names never serialize publicly.
package signal

import "fmt"

// Internal levels. Never leave the system.
type Internal string

const (
	Benign     Internal = "benign"
	Unknown    Internal = "unknown"
	Suspicious Internal = "suspicious"
	Malicious  Internal = "malicious"
)

// Public signal names. Consistent means "matches the entity's own published
// data"; it never implies trustworthiness.
type Public string

const (
	Consistent  Public = "consistent"
	NoSignals   Public = "no_signals"
	Caution     Public = "caution"
	HighCaution Public = "high_caution"
)

// ToPublic maps an internal level. Unrecognized input is an error, never a
// default to a reassuring level.
func ToPublic(l Internal) (Public, error) {
	switch l {
	case Benign:
		return Consistent, nil
	case Unknown:
		return NoSignals, nil
	case Suspicious:
		return Caution, nil
	case Malicious:
		return HighCaution, nil
	default:
		return "", fmt.Errorf("signal: unrecognized internal level %q", string(l))
	}
}

// Valid reports whether p is a known public signal name.
func (p Public) Valid() bool {
	switch p {
	case Consistent, NoSignals, Caution, HighCaution:
		return true
	}
	return false
}
