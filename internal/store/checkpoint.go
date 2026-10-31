package store

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
)

// Checkpoint is the Postgres-backed ingest.Checkpoint (table ingest_checkpoint).
// Like ingest.MemoryCheckpoint it only ever advances by exactly one ledger.
type Checkpoint struct {
	pool *pgxpool.Pool
}

var _ ingest.Checkpoint = (*Checkpoint)(nil)

func NewCheckpoint(pool *pgxpool.Pool) *Checkpoint { return &Checkpoint{pool: pool} }

func checkNetwork(n entity.Network) error {
	if n != entity.Public && n != entity.Testnet {
		return &entity.Error{Code: entity.ErrUnknownNetwork}
	}
	return nil
}

func (c *Checkpoint) Last(ctx context.Context, n entity.Network) (uint32, bool, error) {
	if err := checkNetwork(n); err != nil {
		return 0, false, err
	}
	var last int64
	err := c.pool.QueryRow(ctx, `SELECT last_ledger FROM ingest_checkpoint WHERE network = $1`, string(n)).Scan(&last)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if last <= 0 || last > math.MaxUint32 {
		return 0, false, fmt.Errorf("%w: stored checkpoint %d", ingest.ErrInconsistent, last)
	}
	return uint32(last), true, nil
}

// Set writes seq if it is the first checkpoint for n or exactly last+1.
// Anything else is a gap: another writer moved it, or a caller skipped ahead.
func (c *Checkpoint) Set(ctx context.Context, n entity.Network, seq uint32) error {
	if err := checkNetwork(n); err != nil {
		return err
	}
	if seq == 0 {
		return fmt.Errorf("%w: checkpoint 0", ingest.ErrInconsistent)
	}
	tag, err := c.pool.Exec(ctx, `
		INSERT INTO ingest_checkpoint (network, last_ledger, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (network) DO UPDATE SET last_ledger = EXCLUDED.last_ledger, updated_at = now()
		WHERE ingest_checkpoint.last_ledger = EXCLUDED.last_ledger - 1`, string(n), int64(seq))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: checkpoint does not advance by one to %d", ingest.ErrGap, seq)
	}
	return nil
}

// ErrWriterLockLost means the connection holding this process's single-writer
// advisory lock failed, so Postgres may have handed the lock to another writer.
// It is a named condition rather than a message because the worker's alert
// taxonomy keys on it (internal/monitoring, intel #54).
var ErrWriterLockLost = errors.New("store: writer lock lost")

// WriterLock is a session-level advisory lock that makes one process the only
// writer for a network (ingest, pipeline and snapshot publishing). It holds a
// dedicated connection until Release; if that connection drops, Postgres
// releases the lock and Lost is closed.
type WriterLock struct {
	conn *pgxpool.Conn
	key  int64
	lost chan struct{}
	stop chan struct{}
	once sync.Once
	mu   sync.Mutex // the connection is not safe for concurrent use
	done bool       // released; guarded by mu
}

// writerLockKey namespaces the per-network lock away from migrateLockID.
func writerLockKey(n entity.Network) int64 {
	h := fnv.New32a()
	h.Write([]byte("sorosentinel-writer|" + string(n)))
	return int64(migrateLockID)<<32 | int64(h.Sum32())
}

// AcquireWriter takes the writer lock for n without waiting. If another
// process holds it the error wraps ingest.ErrWriterActive.
func AcquireWriter(ctx context.Context, pool *pgxpool.Pool, n entity.Network) (*WriterLock, error) {
	if err := checkNetwork(n); err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	key := writerLockKey(n)
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		conn.Release()
		return nil, err
	}
	if !ok {
		conn.Release()
		return nil, fmt.Errorf("%w: %s (held by another process)", ingest.ErrWriterActive, n)
	}
	return &WriterLock{conn: conn, key: key, lost: make(chan struct{}), stop: make(chan struct{})}, nil
}

// Watch pings the lock's connection every interval until Release. On a
// failure it closes Lost: the lock may already belong to another process.
func (l *WriterLock) Watch(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), interval)
				err := l.Ping(ctx)
				cancel()
				if err != nil {
					select {
					case <-l.stop:
					default:
						close(l.lost)
					}
					return
				}
			}
		}
	}()
}

// Ping checks the lock's connection is alive and still holds the lock.
func (l *WriterLock) Ping(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return fmt.Errorf("%w: already released", ErrWriterLockLost)
	}
	var held bool
	err := l.conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks
		WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
		AND objid = ($1::bigint & 4294967295)::oid AND classid = ($1::bigint >> 32)::oid)`, l.key).Scan(&held)
	if err != nil {
		return err
	}
	if !held {
		return ErrWriterLockLost
	}
	return nil
}

// Lost is closed when Watch sees the lock's connection fail.
func (l *WriterLock) Lost() <-chan struct{} { return l.lost }

// Release unlocks and returns the connection.
func (l *WriterLock) Release(ctx context.Context) {
	l.once.Do(func() {
		close(l.stop)
		l.mu.Lock()
		defer l.mu.Unlock()
		l.done = true
		l.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, l.key) //nolint:errcheck
		l.conn.Release()
	})
}
