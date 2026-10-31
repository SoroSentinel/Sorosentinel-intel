// Command intel-ingest tails one network from Stellar RPC and extracts the
// Phase 1 detector inputs (ADR 0004). Run exactly one per network.
//
// This is a facts-only debugging tool: the checkpoint is in memory (pass
// -start-ledger on every start) and facts are only counted in the log. The
// production path, with the Postgres checkpoint, detectors and snapshot
// publishing, is cmd/intel-worker. It exits non-zero on any halting condition.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/source/rpc"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/monitoring"
)

func main() {
	network := flag.String("network", "testnet", "testnet or public")
	rpcURL := flag.String("rpc-url", "", "Stellar RPC endpoint (https); testnet defaults to "+rpc.DefaultTestnetURL)
	start := flag.Uint("start-ledger", 0, "first ledger when there is no checkpoint")
	page := flag.Uint("page-size", 10, "ledgers per getLedgers call (1-200)")
	poll := flag.Duration("poll", 5*time.Second, "wait between polls when caught up")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	n := entity.Network(*network)
	url := *rpcURL
	if url == "" && n == entity.Testnet {
		url = rpc.DefaultTestnetURL
	}
	if url == "" {
		log.Error("ingest: -rpc-url is required for this network", "network", *network)
		os.Exit(2)
	}
	src, err := rpc.New(rpc.Config{URL: url})
	if err != nil {
		log.Error("ingest: bad config", "err", err)
		os.Exit(2)
	}
	in, err := ingest.New(ingest.Config{
		Network: n, StartLedger: uint32(*start), PageSize: uint32(*page), PollInterval: *poll,
	}, src, ingest.NewMemoryCheckpoint(), logSink{log})
	if err != nil {
		log.Error("ingest: bad config", "err", err)
		os.Exit(2)
	}
	defer in.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = in.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	// "alert" is the field the log-based alerting matches on; alert_id and
	// halt_kind say which rule it is (internal/monitoring, intel #54). The
	// production worker logs the same id, so one rule covers both commands.
	log.Error("ingest halted", append(monitoring.AlertFields(monitoring.IngestHalt),
		"network", *network, "halt", ingest.IsHalt(err), "halt_kind", haltKind(err), "err", err)...)
	os.Exit(1)
}

// haltKind names the stop condition, falling back to a label that still alerts.
func haltKind(err error) string {
	if k := ingest.HaltKind(err); k != "" {
		return k
	}
	return "unclassified"
}

// logSink logs counts only: no addresses or untrusted strings in logs.
type logSink struct{ log *slog.Logger }

func (s logSink) Ledger(_ context.Context, f ingest.LedgerFacts) error {
	s.log.Info("ledger", "network", f.Network, "seq", f.Sequence,
		"assets", len(f.Facts.Assets), "home_domains", len(f.Facts.HomeDomains))
	return nil
}
