// Package ingest tails ledgers from a Source, extracts Phase 1 facts and hands
// them to a Sink, one ledger at a time and strictly in sequence. Progress is a
// per-network checkpoint written after each fully processed ledger, so a
// restart resumes at checkpoint+1 (idempotent by (network, ledger_seq)).
//
// Halting conditions (unknown XDR, unsupported protocol, gaps, inconsistent
// responses, wrong network) stop ingestion and need an operator; see IsHalt.
package ingest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
)

// Network passphrases (ARCHITECTURE §0, stable since 2015).
const (
	PublicPassphrase  = "Public Global Stellar Network ; September 2015"
	TestnetPassphrase = "Test SDF Network ; September 2015"
)

var (
	// ErrGap: the next ledger is missing (non-contiguous sequence, or no longer
	// retained by the source). Recovery needs a backfill; halt.
	ErrGap = errors.New("ingest: ledger gap")
	// ErrInconsistent: the source contradicts itself or the ledger chain. Halt.
	ErrInconsistent = errors.New("ingest: inconsistent ledger data")
	// ErrWrongNetwork: the source serves a different network. Halt.
	ErrWrongNetwork = errors.New("ingest: source network mismatch")
	// ErrWriterActive: another ingester already writes this network.
	ErrWriterActive = errors.New("ingest: a writer is already active for this network")
	// ErrNoStart: no checkpoint and no configured start ledger.
	ErrNoStart = errors.New("ingest: no checkpoint and no start ledger")
	// ErrRetriesExhausted: retryable errors in a row reached MaxRetries, so Run
	// gave up. Nothing is being recorded even though no single cause was a halt.
	ErrRetriesExhausted = errors.New("ingest: retryable errors exhausted")
)

// IsHalt reports whether err must stop ingestion rather than be retried. Running
// out of retries counts: from that point nothing is being recorded, whether or
// not any single error was a halt cause, so the caller treats it like one.
func IsHalt(err error) bool {
	for _, h := range []error{ErrGap, ErrInconsistent, ErrWrongNetwork, ErrWriterActive, ErrNoStart, ErrRetriesExhausted,
		xdrcompat.ErrUnknownXDR, xdrcompat.ErrUnsupportedProtocol, xdrcompat.ErrInvalidData} {
		if errors.Is(err, h) {
			return true
		}
	}
	return false
}

// Halt kinds are the stable names the operator-facing alerts group by. They are
// part of the monitoring contract (internal/monitoring) and are logged, never
// parsed back out of an error string, so a rule can narrow a halt to one cause
// without depending on wording.
const (
	HaltGap                 = "gap"
	HaltInconsistent        = "inconsistent"
	HaltWrongNetwork        = "wrong_network"
	HaltWriterActive        = "writer_active"
	HaltNoStart             = "no_start"
	HaltUnknownXDR          = "unknown_xdr"
	HaltUnsupportedProtocol = "unsupported_protocol"
	HaltInvalidData         = "invalid_data"
	HaltRetriesExhausted    = "retries_exhausted"
)

// HaltKind names why ingestion stopped, or "" when err is not a halt cause. A
// give-up after consecutive retryable errors is a halt of its own kind: the
// source kept answering, but never with something usable.
func HaltKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrGap):
		return HaltGap
	case errors.Is(err, ErrInconsistent):
		return HaltInconsistent
	case errors.Is(err, ErrWrongNetwork):
		return HaltWrongNetwork
	case errors.Is(err, ErrWriterActive):
		return HaltWriterActive
	case errors.Is(err, ErrNoStart):
		return HaltNoStart
	case errors.Is(err, xdrcompat.ErrUnknownXDR):
		return HaltUnknownXDR
	case errors.Is(err, xdrcompat.ErrUnsupportedProtocol):
		return HaltUnsupportedProtocol
	case errors.Is(err, xdrcompat.ErrInvalidData):
		return HaltInvalidData
	case errors.Is(err, ErrRetriesExhausted):
		return HaltRetriesExhausted
	}
	return ""
}

// RawLedger is one ledger as served by a Source.
type RawLedger struct {
	Sequence uint32
	Hash     string // hex ledger header hash as reported by the source
	Meta     []byte // XDR LedgerCloseMeta
}

// Range is the inclusive span of ledgers a Source currently retains.
type Range struct {
	Oldest, Latest uint32
}

// Source serves ledgers. The RPC implementation is in source/rpc.
type Source interface {
	NetworkPassphrase(ctx context.Context) (string, error)
	Range(ctx context.Context) (Range, error)
	// Ledgers returns up to limit ledgers starting at start, ascending.
	Ledgers(ctx context.Context, start, limit uint32) ([]RawLedger, error)
}

// Checkpoint stores the last fully processed ledger per network.
type Checkpoint interface {
	// Last returns ok=false when the network has no checkpoint yet.
	Last(ctx context.Context, network entity.Network) (seq uint32, ok bool, err error)
	Set(ctx context.Context, network entity.Network, seq uint32) error
}

// LedgerFacts is what a Sink receives for one ledger.
type LedgerFacts struct {
	Network   entity.Network
	Sequence  uint32
	CloseTime int64 // unix seconds from the ledger header, not the local clock
	Facts     xdrcompat.Facts
}

// Sink consumes facts. A crash between Sink and the checkpoint write replays
// that ledger, so Sink must be idempotent by (Network, Sequence).
type Sink interface {
	Ledger(ctx context.Context, f LedgerFacts) error
}

// Config controls one Ingester.
type Config struct {
	Network entity.Network
	// StartLedger is used only when the network has no checkpoint.
	StartLedger uint32
	// PageSize is ledgers per request; 1..200 (getLedgers limit), default 10.
	PageSize uint32
	// PollInterval is the wait when caught up; default 5s.
	PollInterval time.Duration
	// MaxRetries is how many consecutive retryable errors Run tolerates
	// before giving up; default 5.
	MaxRetries int
}

// Ingester is the single writer for one network in this process. Cross-process
// exclusion is the Postgres writer lease in internal/store (AcquireWriter),
// taken by cmd/intel-worker before this is constructed.
type Ingester struct {
	cfg       Config
	src       Source
	cp        Checkpoint
	sink      Sink
	netOK     bool
	prevHash  [32]byte
	prevSeq   uint32 // 0 until a ledger is processed in this run
	closeOnce sync.Once
}

var (
	writersMu sync.Mutex
	writers   = map[entity.Network]bool{}
)

// New claims the network for this process; Close releases it.
func New(cfg Config, src Source, cp Checkpoint, sink Sink) (*Ingester, error) {
	if _, err := passphrase(cfg.Network); err != nil {
		return nil, err
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 10
	}
	if cfg.PageSize > 200 {
		return nil, fmt.Errorf("ingest: page size %d above 200", cfg.PageSize)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}
	writersMu.Lock()
	defer writersMu.Unlock()
	if writers[cfg.Network] {
		return nil, fmt.Errorf("%w: %s", ErrWriterActive, cfg.Network)
	}
	writers[cfg.Network] = true
	return &Ingester{cfg: cfg, src: src, cp: cp, sink: sink}, nil
}

// Close releases the network claim.
func (in *Ingester) Close() {
	in.closeOnce.Do(func() {
		writersMu.Lock()
		delete(writers, in.cfg.Network)
		writersMu.Unlock()
	})
}

func passphrase(n entity.Network) (string, error) {
	switch n {
	case entity.Public:
		return PublicPassphrase, nil
	case entity.Testnet:
		return TestnetPassphrase, nil
	default:
		return "", fmt.Errorf("%w: unknown network %q", ErrWrongNetwork, n)
	}
}

// Run calls Step until ctx ends or an error halts it. Retryable errors are
// retried after PollInterval up to MaxRetries times in a row.
func (in *Ingester) Run(ctx context.Context) error {
	failures := 0
	for {
		n, err := in.Step(ctx)
		switch {
		case err == nil:
			failures = 0
		case ctx.Err() != nil:
			return ctx.Err()
		case IsHalt(err):
			return err
		default:
			failures++
			if failures >= in.cfg.MaxRetries {
				return fmt.Errorf("%w after %d consecutive errors: %w", ErrRetriesExhausted, failures, err)
			}
		}
		if err == nil && n > 0 {
			continue
		}
		t := time.NewTimer(in.cfg.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Step processes at most one page and returns how many ledgers it completed.
// Zero with a nil error means the source has nothing new yet.
func (in *Ingester) Step(ctx context.Context) (int, error) {
	if !in.netOK {
		want, _ := passphrase(in.cfg.Network)
		got, err := in.src.NetworkPassphrase(ctx)
		if err != nil {
			return 0, err
		}
		if got != want {
			return 0, fmt.Errorf("%w: configured %s", ErrWrongNetwork, in.cfg.Network)
		}
		in.netOK = true
	}
	next, err := in.next(ctx)
	if err != nil {
		return 0, err
	}
	r, err := in.src.Range(ctx)
	if err != nil {
		return 0, err
	}
	if r.Oldest > r.Latest {
		return 0, fmt.Errorf("%w: source range %d..%d", ErrInconsistent, r.Oldest, r.Latest)
	}
	if next > r.Latest {
		return 0, nil
	}
	if next < r.Oldest {
		return 0, fmt.Errorf("%w: next ledger %d is older than the source's oldest %d; backfill needed", ErrGap, next, r.Oldest)
	}
	page, err := in.src.Ledgers(ctx, next, in.cfg.PageSize)
	if err != nil {
		return 0, err
	}
	if len(page) > int(in.cfg.PageSize) {
		return 0, fmt.Errorf("%w: %d ledgers for limit %d", ErrInconsistent, len(page), in.cfg.PageSize)
	}
	done := 0
	for _, raw := range page {
		if err := in.process(ctx, next, raw); err != nil {
			return done, err
		}
		next++
		done++
	}
	return done, nil
}

func (in *Ingester) next(ctx context.Context) (uint32, error) {
	last, ok, err := in.cp.Last(ctx, in.cfg.Network)
	if err != nil {
		return 0, err
	}
	if ok {
		if last == ^uint32(0) {
			return 0, fmt.Errorf("%w: checkpoint at max sequence", ErrInconsistent)
		}
		return last + 1, nil
	}
	if in.cfg.StartLedger == 0 {
		return 0, ErrNoStart
	}
	return in.cfg.StartLedger, nil
}

func (in *Ingester) process(ctx context.Context, want uint32, raw RawLedger) error {
	if raw.Sequence != want {
		return fmt.Errorf("%w: expected ledger %d, source returned %d", ErrGap, want, raw.Sequence)
	}
	l, err := xdrcompat.Decode(raw.Meta)
	if err != nil {
		return fmt.Errorf("ledger %d: %w", want, err)
	}
	if l.Sequence != want {
		return fmt.Errorf("%w: ledger %d meta carries sequence %d", ErrInconsistent, want, l.Sequence)
	}
	if hex.EncodeToString(l.Hash[:]) != raw.Hash {
		return fmt.Errorf("%w: ledger %d hash differs from its meta", ErrInconsistent, want)
	}
	if in.prevSeq != 0 && in.prevSeq+1 == want && l.PreviousHash != in.prevHash {
		return fmt.Errorf("%w: ledger %d does not chain to ledger %d", ErrInconsistent, want, in.prevSeq)
	}
	if err := in.sink.Ledger(ctx, LedgerFacts{
		Network: in.cfg.Network, Sequence: want, CloseTime: l.CloseTime, Facts: l.Facts,
	}); err != nil {
		return fmt.Errorf("ingest: sink, ledger %d: %w", want, err)
	}
	if err := in.cp.Set(ctx, in.cfg.Network, want); err != nil {
		return fmt.Errorf("ingest: checkpoint, ledger %d: %w", want, err)
	}
	in.prevSeq, in.prevHash = want, l.Hash
	return nil
}

// MemoryCheckpoint is an in-process Checkpoint for tests and local runs. The
// Postgres-backed one replaces it in production.
type MemoryCheckpoint struct {
	mu   sync.Mutex
	last map[entity.Network]uint32
}

func NewMemoryCheckpoint() *MemoryCheckpoint {
	return &MemoryCheckpoint{last: map[entity.Network]uint32{}}
}

func (m *MemoryCheckpoint) Last(_ context.Context, n entity.Network) (uint32, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.last[n]
	return s, ok, nil
}

// Set refuses to move a checkpoint backwards or skip ahead: checkpoints only
// advance by one ledger at a time.
func (m *MemoryCheckpoint) Set(_ context.Context, n entity.Network, seq uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if last, ok := m.last[n]; ok && seq != last+1 {
		return fmt.Errorf("%w: checkpoint %d -> %d", ErrGap, last, seq)
	}
	m.last[n] = seq
	return nil
}
