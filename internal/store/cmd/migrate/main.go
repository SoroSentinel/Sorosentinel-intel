// Command migrate applies Intel's forward-only migrations to the database in
// INTEL_DATABASE_URL. It never prints the URL.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
)

func main() {
	url := os.Getenv("INTEL_DATABASE_URL")
	if url == "" {
		fmt.Fprintln(os.Stderr, "migrate: INTEL_DATABASE_URL is not set")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate: cannot open database")
		os.Exit(1)
	}
	defer pool.Close()
	ran, err := store.Migrate(ctx, pool)
	for _, name := range ran {
		fmt.Println("applied", name)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
	if len(ran) == 0 {
		fmt.Println("up to date")
	}
}
