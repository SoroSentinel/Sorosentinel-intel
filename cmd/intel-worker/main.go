// Command intel-worker runs the Phase 1 Intel pipeline for one network:
// RPC ingestion (Postgres checkpoint), the look-alike and home-domain
// detectors, evidence storage, verdict recompute, and periodic publishing of
// the signed snapshot (ADR 0002).
//
// It is the single writer for its network: it takes a Postgres advisory lock
// at start and exits if another process holds it or if the lock's connection
// drops. It exits non-zero on any ingestion halt.
//
// Configuration: flags, plus INTEL_DATABASE_URL (never logged). The signing
// key is a PEM PKCS#8 Ed25519 file readable by its owner only; this is the
// interim path until the KMS signer lands. Logs are JSON with a correlation
// id and carry counts only: no XDR, addresses, domains or key material.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/fetcher"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/source/rpc"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/pipeline"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
)

const dbEnv = "INTEL_DATABASE_URL"

type config struct {
	network          entity.Network
	rpcURL           string
	startLedger      uint32
	pageSize         uint32
	poll             time.Duration
	reference        string
	snapshotDir      string
	snapshotInterval time.Duration
	keyFile          string
	keyID            string
	fetchInterval    time.Duration
}

func main() {
	network := flag.String("network", "testnet", "testnet or public")
	rpcURL := flag.String("rpc-url", "", "Stellar RPC endpoint (https); testnet defaults to "+rpc.DefaultTestnetURL)
	start := flag.Uint("start-ledger", 0, "first ledger when the network has no checkpoint yet")
	page := flag.Uint("page-size", 10, "ledgers per getLedgers call (1-200)")
	poll := flag.Duration("poll", 5*time.Second, "wait between polls when caught up")
	reference := flag.String("reference", "", "reviewed reference-asset file (default config/reference-assets.<network>.json)")
	snapDir := flag.String("snapshot-dir", "", "directory the signed snapshot files are written to (required)")
	snapEvery := flag.Duration("snapshot-interval", 5*time.Minute, "how often to publish the snapshot")
	keyFile := flag.String("signing-key-file", "", "PEM PKCS#8 Ed25519 private key, mode 0600 (required)")
	keyID := flag.String("signing-key-id", "", "key id written into the snapshot; must match the id Guard pins (required)")
	fetchEvery := flag.Duration("fetch-interval", pipeline.DefaultFetchInterval, "minimum gap between stellar.toml fetches")
	flag.Parse()

	runID := newRunID()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("run_id", runID, "network", *network)

	cfg := config{
		network: entity.Network(*network), rpcURL: *rpcURL, startLedger: uint32(*start), pageSize: uint32(*page),
		poll: *poll, reference: *reference, snapshotDir: *snapDir, snapshotInterval: *snapEvery,
		keyFile: *keyFile, keyID: *keyID, fetchInterval: *fetchEvery,
	}
	if cfg.rpcURL == "" && cfg.network == entity.Testnet {
		cfg.rpcURL = rpc.DefaultTestnetURL
	}
	if cfg.reference == "" {
		cfg.reference = filepath.Join("config", "reference-assets."+*network+".json")
	}
	if err := cfg.check(); err != nil {
		log.Error("worker: bad config", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		// "alert" is the field the log-based alerting matches on.
		log.Error("worker stopped", "halt", ingest.IsHalt(err), "alert", true, "err", err)
		os.Exit(1)
	}
	log.Info("worker stopped")
}

func (c config) check() error {
	switch {
	case c.network != entity.Testnet && c.network != entity.Public:
		return fmt.Errorf("unknown network %q", c.network)
	case c.rpcURL == "":
		return errors.New("-rpc-url is required for this network")
	case c.snapshotDir == "" || c.keyFile == "" || c.keyID == "":
		return errors.New("-snapshot-dir, -signing-key-file and -signing-key-id are required")
	case c.snapshotInterval < 10*time.Second:
		return errors.New("-snapshot-interval must be at least 10s")
	case os.Getenv(dbEnv) == "":
		return errors.New(dbEnv + " is not set")
	}
	if fi, err := os.Stat(c.snapshotDir); err != nil || !fi.IsDir() {
		return errors.New("-snapshot-dir must be an existing directory")
	}
	return nil
}

func newRunID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read does not fail on supported platforms
	return hex.EncodeToString(b)
}

func run(ctx context.Context, cfg config, log *slog.Logger) error {
	signer, err := snapshot.LoadEd25519KeyFile(cfg.keyFile, cfg.keyID)
	if err != nil {
		return err
	}
	ref, err := pipeline.LoadReference(cfg.reference)
	if err != nil {
		return err
	}
	src, err := rpc.New(rpc.Config{URL: cfg.rpcURL})
	if err != nil {
		return err
	}

	pool, err := pgxpool.New(ctx, os.Getenv(dbEnv))
	if err != nil {
		return errors.New("worker: database config invalid") // the error may echo the URL
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("worker: database unreachable: %w", err)
	}

	lock, err := store.AcquireWriter(ctx, pool, cfg.network)
	if err != nil {
		return err
	}
	defer lock.Release(context.WithoutCancel(ctx))
	lock.Watch(15 * time.Second)

	st := store.New(pool)
	pl, err := pipeline.New(ctx, pipeline.Config{
		Network: cfg.network, Reference: ref, Ruleset: verdict.V1, Now: time.Now,
		FetchInterval: cfg.fetchInterval, Log: log.With("component", "pipeline"),
	}, st, src, fetcher.New())
	if err != nil {
		return err
	}
	in, err := ingest.New(ingest.Config{
		Network: cfg.network, StartLedger: cfg.startLedger, PageSize: cfg.pageSize, PollInterval: cfg.poll,
	}, src, store.NewCheckpoint(pool), pl)
	if err != nil {
		return err
	}
	defer in.Close()
	pub := &pipeline.Publisher{
		Network: cfg.network, Dir: cfg.snapshotDir, RulesetVersion: verdict.V1.Version,
		Signer: signer, Store: st,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 3)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs <- in.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		errs <- publishLoop(ctx, pub, cfg.snapshotInterval, log.With("component", "snapshot"))
	}()
	log.Info("worker started", "snapshot_interval", cfg.snapshotInterval.String(), "ruleset_version", verdict.V1.Version)

	var first error
	select {
	case <-ctx.Done():
	case <-lock.Lost():
		first = errors.New("worker: writer lock lost")
	case first = <-errs:
	}
	cancel()
	wg.Wait()
	close(errs)
	if first == nil || errors.Is(first, context.Canceled) {
		// Shutdown by signal: a clean exit unless a component failed first.
		for err := range errs {
			if err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
		}
		return nil
	}
	return first
}

// publishLoop publishes once at start and then every interval. A failed
// publish is logged and retried at the next tick; Guard's max-age check turns
// a long outage into a visible "protection data stale" state.
func publishLoop(ctx context.Context, pub *pipeline.Publisher, every time.Duration, log *slog.Logger) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s, err := pub.Publish(ctx, time.Now())
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err != nil:
			log.Error("snapshot publish failed", "alert", true, "err", err)
		default:
			log.Info("snapshot published", "correlation_id", fmt.Sprintf("%s-snapshot-%d", s.Network, s.Version),
				"version", s.Version, "entries", len(s.Entries), "key_id", s.KeyID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
