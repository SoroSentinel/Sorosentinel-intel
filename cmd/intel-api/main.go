// Command intel-api serves Intel's public read API (PRD I-5,
// schemas/openapi/intel.v1.yaml): entity signals from Postgres and the signed
// snapshots cmd/intel-worker publishes.
//
// It only reads. Configuration: flags, plus INTEL_DATABASE_URL (never
// logged). TLS, API keys and rate limits are the gateway's job in v1. Logs
// are JSON and carry route patterns, status codes and timings only: no
// paths, bodies or addresses.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/api"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/monitoring"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
)

const dbEnv = "INTEL_DATABASE_URL"

type config struct {
	addr             string
	snapshotDir      string
	methodologyURL   string
	reviewURL        string
	requestTimeout   time.Duration
	maxSnapshotBytes int64
}

func main() {
	var cfg config
	flag.StringVar(&cfg.addr, "addr", "127.0.0.1:8080", "listen address (TLS terminates at the gateway)")
	flag.StringVar(&cfg.snapshotDir, "snapshot-dir", "", "directory cmd/intel-worker writes the signed snapshots to (required)")
	flag.StringVar(&cfg.methodologyURL, "methodology-url", "", "https URL of the published methodology, used in statements (required)")
	flag.StringVar(&cfg.reviewURL, "review-url", "", "https URL where a signal can be reviewed, used in statements (required)")
	flag.DurationVar(&cfg.requestTimeout, "request-timeout", api.DefaultRequestTimeout, "store time budget per request")
	flag.Int64Var(&cfg.maxSnapshotBytes, "max-snapshot-bytes", api.DefaultMaxSnapshotBytes, "largest snapshot file served")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := cfg.check(); err != nil {
		log.Error("api: bad config", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		// "alert" is the field the log-based alerting matches on; the id names the
		// rule (internal/monitoring, intel #54).
		log.Error("api stopped", append(monitoring.AlertFields(monitoring.ApiStopped), "err", err)...)
		os.Exit(1)
	}
	log.Info("api stopped")
}

func (c config) check() error {
	switch {
	case c.snapshotDir == "" || c.methodologyURL == "" || c.reviewURL == "":
		return errors.New("-snapshot-dir, -methodology-url and -review-url are required")
	case c.requestTimeout <= 0 || c.requestTimeout > time.Minute:
		return errors.New("-request-timeout must be between 0 and 1m")
	case c.maxSnapshotBytes <= 0:
		return errors.New("-max-snapshot-bytes must be positive")
	case os.Getenv(dbEnv) == "":
		return errors.New(dbEnv + " is not set")
	}
	if fi, err := os.Stat(c.snapshotDir); err != nil || !fi.IsDir() {
		return errors.New("-snapshot-dir must be an existing directory")
	}
	return nil
}

func run(ctx context.Context, cfg config, log *slog.Logger) error {
	reg, err := wording.LoadEmbedded()
	if err != nil {
		return err
	}
	rnd, err := wording.NewRenderer(reg, wording.Config{MethodologyURL: cfg.methodologyURL, ReviewURL: cfg.reviewURL})
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, os.Getenv(dbEnv))
	if err != nil {
		return errors.New("api: database config invalid") // the error may echo the URL
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("api: database unreachable: %w", err)
	}

	srv, err := api.New(api.Config{
		Store: store.New(pool), Renderer: rnd, SnapshotDir: cfg.snapshotDir,
		Log: log, RequestTimeout: cfg.requestTimeout, MaxSnapshotBytes: cfg.maxSnapshotBytes,
	})
	if err != nil {
		return err
	}
	hs := api.HTTPServer(cfg.addr, srv.Handler(), log)
	errs := make(chan error, 1)
	go func() { errs <- hs.ListenAndServe() }()
	log.Info("api started", "addr", cfg.addr)

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdown); err != nil {
		return err
	}
	if err := <-errs; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
