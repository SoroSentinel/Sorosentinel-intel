// Package snapshot builds and verifies the v1 signed snapshot: the sorted list
// of 128-bit entry hashes Guard checks offline (schemas/jsonschema/Snapshot.json,
// signed bytes defined in schemas/snapshot-signing.md).
package snapshot

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

const (
	FormatVersion = 1
	// MaxEntries bounds a snapshot (ARCHITECTURE §17 OE4: at most ~10^7 entries).
	MaxEntries = 10_000_000
	magic      = "SOROSENTINEL-SNAPSHOT-V1\n"
)

var (
	keyIDRe   = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	rulesetRe = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]+$`)
	entryRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Snapshot mirrors Snapshot.json field for field.
type Snapshot struct {
	FormatVersion  int      `json:"format_version"`
	Network        string   `json:"network"`
	Version        uint64   `json:"version"`
	GeneratedAt    string   `json:"generated_at"`
	RulesetVersion string   `json:"ruleset_version"`
	KeyID          string   `json:"key_id"`
	Entries        []string `json:"entries"`
	Signature      string   `json:"signature"`
}

// Entity is one flagged entity to include, before canonicalization.
type Entity struct {
	Type entity.Type
	Key  string
}

// Input is everything a snapshot is built from. GeneratedAt is passed in;
// the builder never reads the clock.
type Input struct {
	Network        entity.Network
	Version        uint64
	GeneratedAt    time.Time
	RulesetVersion string
	Entities       []Entity
}

// Signer signs snapshot payloads. Production uses a KMS-backed signer; tests use Ed25519Signer.
type Signer interface {
	KeyID() string
	Sign(payload []byte) ([]byte, error)
}

// Ed25519Signer signs with an in-memory key. For tests and local development only.
type Ed25519Signer struct {
	id  string
	key ed25519.PrivateKey
}

func NewEd25519Signer(keyID string, key ed25519.PrivateKey) (*Ed25519Signer, error) {
	if !keyIDRe.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("snapshot: invalid key id or key")
	}
	return &Ed25519Signer{id: keyID, key: key}, nil
}

func (s *Ed25519Signer) KeyID() string { return s.id }

func (s *Ed25519Signer) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(s.key, payload), nil
}

// Build canonicalizes and hashes every entity, removes duplicates, sorts the
// entries, and signs the payload. Any invalid input is an error; nothing is skipped.
func Build(in Input, signer Signer) (Snapshot, error) {
	if in.Version < 1 || in.GeneratedAt.IsZero() || !rulesetRe.MatchString(in.RulesetVersion) {
		return Snapshot{}, errors.New("snapshot: version, generated_at and ruleset_version are required")
	}
	if !keyIDRe.MatchString(signer.KeyID()) {
		return Snapshot{}, errors.New("snapshot: invalid key id")
	}
	if len(in.Entities) > MaxEntries {
		return Snapshot{}, fmt.Errorf("snapshot: more than %d entities", MaxEntries)
	}
	seen := make(map[string]bool, len(in.Entities))
	entries := make([]string, 0, len(in.Entities))
	for _, e := range in.Entities {
		c, err := entity.Canonical(in.Network, e.Type, e.Key)
		if err != nil {
			return Snapshot{}, fmt.Errorf("snapshot: %w", err)
		}
		h := entity.SnapshotHash(c)
		if !seen[h] {
			seen[h] = true
			entries = append(entries, h)
		}
	}
	slices.Sort(entries)

	s := Snapshot{
		FormatVersion:  FormatVersion,
		Network:        string(in.Network),
		Version:        in.Version,
		GeneratedAt:    in.GeneratedAt.UTC().Format(time.RFC3339),
		RulesetVersion: in.RulesetVersion,
		KeyID:          signer.KeyID(),
		Entries:        entries,
	}
	payload, err := Payload(s)
	if err != nil {
		return Snapshot{}, err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: sign: %w", err)
	}
	s.Signature = base64.StdEncoding.EncodeToString(sig)
	return s, nil
}

// Payload returns exactly the bytes that are signed (schemas/snapshot-signing.md).
// It re-validates every field, so a tampered snapshot cannot produce a payload.
func Payload(s Snapshot) ([]byte, error) {
	if s.FormatVersion != FormatVersion || (s.Network != string(entity.Public) && s.Network != string(entity.Testnet)) ||
		s.Version < 1 || !rulesetRe.MatchString(s.RulesetVersion) || !keyIDRe.MatchString(s.KeyID) {
		return nil, errors.New("snapshot: invalid header")
	}
	if _, err := time.Parse(time.RFC3339, s.GeneratedAt); err != nil || len(s.GeneratedAt) != len("2006-01-02T15:04:05Z") {
		return nil, errors.New("snapshot: generated_at must be RFC 3339 UTC with seconds")
	}
	if len(s.Entries) > MaxEntries {
		return nil, errors.New("snapshot: too many entries")
	}
	var b bytes.Buffer
	b.WriteString(magic)
	for _, kv := range [][2]string{
		{"network", s.Network},
		{"version", strconv.FormatUint(s.Version, 10)},
		{"generated_at", s.GeneratedAt},
		{"ruleset_version", s.RulesetVersion},
		{"key_id", s.KeyID},
		{"entries", strconv.Itoa(len(s.Entries))},
	} {
		b.WriteString(kv[0] + ":" + kv[1] + "\n")
	}
	prev := ""
	for _, e := range s.Entries {
		if !entryRe.MatchString(e) || e <= prev {
			return nil, errors.New("snapshot: entries must be 32 lowercase hex characters, sorted, without duplicates")
		}
		raw, _ := hex.DecodeString(e)
		b.Write(raw)
		prev = e
	}
	return b.Bytes(), nil
}

// Verify checks a snapshot's structure and signature against a pinned public key.
func Verify(s Snapshot, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("snapshot: invalid public key")
	}
	payload, err := Payload(s)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, payload, sig) {
		return errors.New("snapshot: bad signature")
	}
	return nil
}
