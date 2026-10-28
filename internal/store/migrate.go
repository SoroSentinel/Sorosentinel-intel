package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SoroSentinel/Sorosentinel-intel/migrations"
)

// migrateLockID is the advisory lock that serializes concurrent migrators.
const migrateLockID = 0x534f524f // "SORO"

// Migrate applies the embedded forward-only migrations in name order, each in
// its own transaction. It refuses to run when an applied migration was edited
// or is missing from this build (a newer schema than the code).
func Migrate(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	return migrate(ctx, pool, migrations.FS)
}

func migrate(ctx context.Context, pool *pgxpool.Pool, files fs.FS) ([]string, error) {
	names, err := fs.Glob(files, "*.sql")
	if err != nil {
		return nil, err
	}
	slices.Sort(names)

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLockID); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateLockID) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		sha256     TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	applied := map[string]string{}
	rows, err := conn.Query(ctx, `SELECT version, sha256 FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v, h string
		if err := rows.Scan(&v, &h); err != nil {
			rows.Close()
			return nil, err
		}
		applied[v] = h
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for v := range applied {
		if !slices.Contains(names, v) {
			return nil, fmt.Errorf("store: database has migration %s that this build does not", v)
		}
	}

	var ran []string
	for _, name := range names {
		body, err := fs.ReadFile(files, name)
		if err != nil {
			return ran, err
		}
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		if h, ok := applied[name]; ok {
			if h != hash {
				return ran, fmt.Errorf("store: applied migration %s was edited; migrations are forward-only", name)
			}
			continue
		}
		if strings.TrimSpace(string(body)) == "" {
			return ran, errors.New("store: empty migration " + name)
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, sha256) VALUES ($1, $2)`, name, hash)
			return err
		})
		if err != nil {
			return ran, fmt.Errorf("store: migration %s: %w", name, err)
		}
		ran = append(ran, name)
	}
	return ran, nil
}
