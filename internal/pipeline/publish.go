package pipeline

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
)

// PublishStore is what the publisher needs from internal/store.
type PublishStore interface {
	ListFlagged(ctx context.Context, network entity.Network) ([]snapshot.Entity, error)
	NextSnapshotVersion(ctx context.Context, network entity.Network) (uint64, error)
	RecordSnapshot(ctx context.Context, r store.SnapshotRecord) error
}

// Publisher builds, signs and writes the network's snapshot. It must run
// under the network's writer lock so versions are assigned by one process.
type Publisher struct {
	Network        entity.Network
	Dir            string
	RulesetVersion string
	Signer         snapshot.Signer
	Store          PublishStore
}

// VersionedName is the file name of one snapshot version.
func VersionedName(n entity.Network, version uint64) string {
	return fmt.Sprintf("snapshot-%s-%d.json", n, version)
}

// LatestName is the file name that always holds the newest snapshot.
func LatestName(n entity.Network) string {
	return fmt.Sprintf("snapshot-%s-latest.json", n)
}

// Publish writes the next snapshot version. generatedAt is passed in (the
// worker's clock) and truncated to seconds, the precision of the signed field.
//
// Order: the versioned file is written first, then the snapshot row is
// recorded, then -latest is replaced. If recording fails, -latest still points
// at the previous version and the orphaned file is overwritten by the next
// attempt with the same version number.
func (p *Publisher) Publish(ctx context.Context, generatedAt time.Time) (snapshot.Snapshot, error) {
	if p.Dir == "" || p.Signer == nil || p.Store == nil {
		return snapshot.Snapshot{}, errors.New("pipeline: publisher needs a directory, signer and store")
	}
	generatedAt = generatedAt.UTC().Truncate(time.Second)
	flagged, err := p.Store.ListFlagged(ctx, p.Network)
	if err != nil {
		return snapshot.Snapshot{}, fmt.Errorf("pipeline: list flagged: %w", err)
	}
	version, err := p.Store.NextSnapshotVersion(ctx, p.Network)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	s, err := snapshot.Build(snapshot.Input{
		Network: p.Network, Version: version, GeneratedAt: generatedAt,
		RulesetVersion: p.RulesetVersion, Entities: flagged,
	}, p.Signer)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	body, err := json.Marshal(s)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	body = append(body, '\n')
	name := VersionedName(p.Network, version)
	if err := writeAtomic(p.Dir, name, body); err != nil {
		return snapshot.Snapshot{}, err
	}
	if err := p.Store.RecordSnapshot(ctx, store.SnapshotRecord{
		Network: p.Network, Version: version, GeneratedAt: generatedAt,
		RulesetVersion: p.RulesetVersion, EntryCount: len(s.Entries),
		ObjectKey: name, SigningKeyID: s.KeyID, Signature: sig,
	}); err != nil {
		return snapshot.Snapshot{}, fmt.Errorf("pipeline: record snapshot: %w", err)
	}
	if err := writeAtomic(p.Dir, LatestName(p.Network), body); err != nil {
		return snapshot.Snapshot{}, err
	}
	return s, nil
}

// writeAtomic writes dir/name via a synced temporary file and a rename, so a
// reader sees either the old file or the complete new one.
func writeAtomic(dir, name string, body []byte) (err error) {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(body); err != nil {
		return err
	}
	if err = tmp.Chmod(0o644); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
