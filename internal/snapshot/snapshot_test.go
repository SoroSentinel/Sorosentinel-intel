package snapshot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/schemas"
)

type vector struct {
	SeedHex       string   `json:"seed_hex"`
	PublicKeyHex  string   `json:"public_key_hex"`
	PayloadSHA256 string   `json:"payload_sha256"`
	Snapshot      Snapshot `json:"snapshot"`
	InputEntities []struct {
		Type string `json:"type"`
		Key  string `json:"key"`
	} `json:"input_entities"`
}

func loadVector(t *testing.T) (vector, ed25519.PrivateKey) {
	t.Helper()
	raw, err := schemas.FS.ReadFile("vectors/snapshot_signing.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.SeedHex)
	return v, ed25519.NewKeyFromSeed(seed)
}

func TestSnapshotSigningVector(t *testing.T) {
	v, key := loadVector(t)
	signer, err := NewEd25519Signer(v.Snapshot.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{
		Network:        entity.Public,
		Version:        v.Snapshot.Version,
		GeneratedAt:    time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC),
		RulesetVersion: v.Snapshot.RulesetVersion,
	}
	for _, e := range v.InputEntities {
		in.Entities = append(in.Entities, Entity{Type: entity.Type(e.Type), Key: e.Key})
	}
	got, err := Build(in, signer)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, v.Snapshot) {
		t.Fatalf("snapshot:\n got %+v\nwant %+v", got, v.Snapshot)
	}
	p, err := Payload(got)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(p); hex.EncodeToString(sum[:]) != v.PayloadSHA256 {
		t.Fatalf("payload hash mismatch")
	}
	pub, _ := hex.DecodeString(v.PublicKeyHex)
	if err := Verify(v.Snapshot, pub); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	v, _ := loadVector(t)
	pub, _ := hex.DecodeString(v.PublicKeyHex)
	mutations := map[string]func(*Snapshot){
		"entry removed":     func(s *Snapshot) { s.Entries = s.Entries[1:] },
		"entry added":       func(s *Snapshot) { s.Entries = append(s.Entries, "ffffffffffffffffffffffffffffffff") },
		"entry changed":     func(s *Snapshot) { s.Entries[0] = "8b079656a7f799dc45e331128db881e3" },
		"unsorted":          func(s *Snapshot) { s.Entries[0], s.Entries[1] = s.Entries[1], s.Entries[0] },
		"duplicate":         func(s *Snapshot) { s.Entries[1] = s.Entries[0] },
		"uppercase hex":     func(s *Snapshot) { s.Entries[0] = strings.ToUpper(s.Entries[0]) },
		"network":           func(s *Snapshot) { s.Network = "testnet" },
		"unknown network":   func(s *Snapshot) { s.Network = "futurenet" },
		"version":           func(s *Snapshot) { s.Version = 2 },
		"older timestamp":   func(s *Snapshot) { s.GeneratedAt = "2026-10-26T00:00:00Z" },
		"non-UTC timestamp": func(s *Snapshot) { s.GeneratedAt = "2026-10-27T01:00:00+01:00" },
		"ruleset":           func(s *Snapshot) { s.RulesetVersion = "2026.10.2" },
		"key id":            func(s *Snapshot) { s.KeyID = "test-key-2" },
		"newline in key id": func(s *Snapshot) { s.KeyID = "a\nentries:0" },
		"format version":    func(s *Snapshot) { s.FormatVersion = 2 },
		"bad base64":        func(s *Snapshot) { s.Signature = "!!" },
		"short signature":   func(s *Snapshot) { s.Signature = s.Signature[:20] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := v.Snapshot
			s.Entries = slices.Clone(v.Snapshot.Entries)
			mutate(&s)
			if err := Verify(s, pub); err == nil {
				t.Fatal("tampered snapshot verified")
			}
		})
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if err := Verify(v.Snapshot, other); err == nil {
		t.Fatal("verified with the wrong key")
	}
	if err := Verify(v.Snapshot, pub[:10]); err == nil {
		t.Fatal("verified with a truncated key")
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	_, key := loadVector(t)
	signer, _ := NewEd25519Signer("test-key-1", key)
	good := Input{Network: entity.Public, Version: 1, GeneratedAt: time.Unix(1, 0), RulesetVersion: "2026.10.1"}
	cases := map[string]func(*Input){
		"zero version":     func(i *Input) { i.Version = 0 },
		"zero time":        func(i *Input) { i.GeneratedAt = time.Time{} },
		"bad ruleset":      func(i *Input) { i.RulesetVersion = "latest" },
		"unknown network":  func(i *Input) { i.Network = "futurenet" },
		"muxed account":    func(i *Input) { i.Entities = []Entity{{entity.Account, "M" + strings.Repeat("A", 68)}} },
		"non-ASCII domain": func(i *Input) { i.Entities = []Entity{{entity.Domain, "exаmple.com"}} },
		"unknown type":     func(i *Input) { i.Entities = []Entity{{"pool", "x"}} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := good
			mutate(&in)
			if _, err := Build(in, signer); err == nil {
				t.Fatal("bad input built a snapshot")
			}
		})
	}
	if _, err := NewEd25519Signer("Bad ID", key); err == nil {
		t.Fatal("accepted an invalid key id")
	}
	empty, err := Build(good, signer)
	if err != nil || len(empty.Entries) != 0 {
		t.Fatalf("empty snapshot: %+v, %v", empty, err)
	}
}
