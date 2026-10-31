package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/monitoring"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/pipeline"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
)

// Snapshots are served byte for byte as cmd/intel-worker wrote them, and only
// versions recorded in the snapshot table (the worker records a version after
// its file is complete). The file must agree with its row before it is served.
// Versions are immutable, so checked files are cached in memory.

const snapshotCacheSize = 4

type snapshotCache struct {
	mu    sync.Mutex
	order []string
	files map[string][]byte
}

func (c *snapshotCache) get(k string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.files[k]
	return b, ok
}

func (c *snapshotCache) put(k string, b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.files == nil {
		c.files = map[string][]byte{}
	}
	if _, ok := c.files[k]; ok {
		return
	}
	if len(c.order) == snapshotCacheSize {
		delete(c.files, c.order[0])
		c.order = c.order[1:]
	}
	c.order = append(c.order, k)
	c.files[k] = b
}

func (s *Server) getLatestSnapshot(w http.ResponseWriter, r *http.Request) {
	s.serveSnapshot(w, r, 0)
}

func (s *Server) getSnapshot(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("version")
	if len(raw) == 0 || len(raw) > 19 || raw[0] == '0' || !digitsOnly(raw) {
		writeError(w, http.StatusBadRequest, codeInvalidVersion)
		return
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 1 {
		writeError(w, http.StatusBadRequest, codeInvalidVersion)
		return
	}
	s.serveSnapshot(w, r, uint64(v))
}

func digitsOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (s *Server) serveSnapshot(w http.ResponseWriter, r *http.Request, version uint64) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["network"]) > 1 {
		writeError(w, http.StatusBadRequest, codeInvalidQuery)
		return
	}
	n := entity.Network(q.Get("network"))
	if n != entity.Public && n != entity.Testnet {
		writeError(w, http.StatusBadRequest, string(entity.ErrUnknownNetwork))
		return
	}
	rec, err := s.cfg.Store.Snapshot(r.Context(), n, version)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound)
		return
	}
	if err != nil {
		s.storeFailed(w, r, err)
		return
	}
	if rec.Network != n || (version != 0 && rec.Version != version) {
		s.storeFailed(w, r, errors.New("api: store returned a different snapshot"))
		return
	}
	body, err := s.snapshotFile(rec)
	if err != nil {
		// A recorded snapshot whose file is missing or disagrees is an operator
		// problem; the client gets no partial or unchecked file.
		s.cfg.Log.Error("snapshot file rejected", append(monitoring.AlertFields(monitoring.SnapshotRejected),
			"network", string(n), "version", rec.Version, "err", err)...)
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		return
	}
	if version == 0 {
		w.Header().Set("Cache-Control", "public, max-age=60")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write(body) //nolint:errcheck // the client may have gone
}

// snapshotFile reads and checks the file for rec: the name is derived from
// (network, version), never taken from the row, and every header field and
// the signature must equal the recorded ones.
func (s *Server) snapshotFile(rec store.SnapshotRecord) ([]byte, error) {
	name := pipeline.VersionedName(rec.Network, rec.Version)
	if rec.ObjectKey != name {
		return nil, errors.New("recorded object key is not the versioned file name")
	}
	if b, ok := s.snap.get(name); ok {
		return b, nil
	}
	f, err := os.Open(filepath.Join(s.cfg.SnapshotDir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, s.cfg.MaxSnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > s.cfg.MaxSnapshotBytes {
		return nil, errors.New("file larger than the configured maximum")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var snap snapshot.Snapshot
	if err := dec.Decode(&snap); err != nil {
		return nil, errors.New("file is not a snapshot document")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("trailing data after the snapshot document")
	}
	gen, err := time.Parse(time.RFC3339, snap.GeneratedAt)
	switch {
	case err != nil || !gen.Equal(rec.GeneratedAt):
		return nil, errors.New("generated_at differs from the record")
	case snap.FormatVersion != snapshot.FormatVersion, snap.Network != string(rec.Network), snap.Version != rec.Version:
		return nil, errors.New("header differs from the record")
	case snap.KeyID != rec.SigningKeyID, snap.RulesetVersion != rec.RulesetVersion:
		return nil, errors.New("key id or ruleset differs from the record")
	case len(snap.Entries) != rec.EntryCount:
		return nil, fmt.Errorf("entry count differs from the record")
	case snap.Signature != base64.StdEncoding.EncodeToString(rec.Signature):
		return nil, errors.New("signature differs from the record")
	}
	if _, err := snapshot.Payload(snap); err != nil {
		return nil, err
	}
	s.snap.put(name, body)
	return body, nil
}
