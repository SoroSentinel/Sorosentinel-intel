package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
)

// terminateSession ends the given backend from another connection. It is what a
// SIGKILLed or rebooted worker looks like to Postgres: the session goes, and a
// session-level advisory lock goes with it. No lock-table surgery, which is
// what the reclaim assertions below are about.
func terminateSession(ctx context.Context, pool *pgxpool.Pool, pid int) error {
	_, err := pool.Exec(ctx, "SELECT pg_terminate_backend($1)", pid)
	return err
}

func holderPID(ctx context.Context, l *WriterLock) (int, error) {
	var pid int
	err := l.conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
	return pid, err
}

// TestWriterLeaseReclaimedAfterHolderDies proves a crashed holder's lease is
// reclaimable by the next worker with no operator SQL, and that the dead holder
// can no longer claim to hold it.
func TestWriterLeaseReclaimedAfterHolderDies(t *testing.T) {
	_, pool := migrated(t)
	ctx := context.Background()

	holder, err := AcquireWriter(ctx, pool, entity.Testnet)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := holderPID(ctx, holder)
	if err != nil {
		t.Fatalf("holder pid: %v", err)
	}
	if err := terminateSession(ctx, pool, pid); err != nil {
		t.Fatalf("terminate holder session: %v", err)
	}

	// The holder is still a running process but holds nothing.
	if err := holder.Ping(ctx); err == nil {
		t.Error("ping on a dead holder session succeeded")
	}
	next, err := AcquireWriter(ctx, pool, entity.Testnet)
	if err != nil {
		t.Fatalf("stale lease was not reclaimable: %v", err)
	}
	if err := next.Ping(ctx); err != nil {
		t.Errorf("new holder cannot confirm its lease: %v", err)
	}
	next.Release(ctx)
	holder.Release(ctx) // discards the dead connection
}

// TestWriterLeaseLossIsReportedToWatch is the path cmd/intel-worker selects on
// to stop publishing: Watch must notice the dropped session by itself.
func TestWriterLeaseLossIsReportedToWatch(t *testing.T) {
	_, pool := migrated(t)
	ctx := context.Background()

	holder, err := AcquireWriter(ctx, pool, entity.Testnet)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release(ctx)
	pid, err := holderPID(ctx, holder)
	if err != nil {
		t.Fatalf("holder pid: %v", err)
	}
	holder.Watch(200 * time.Millisecond)
	if err := terminateSession(ctx, pool, pid); err != nil {
		t.Fatalf("terminate holder session: %v", err)
	}
	select {
	case <-holder.Lost():
	case <-time.After(10 * time.Second):
		t.Fatal("Watch never reported the lost lease")
	}
	// A process that lost its lease must not keep writing.
	if err := holder.Ping(ctx); err == nil {
		t.Error("ping succeeded after Lost fired")
	}
}
