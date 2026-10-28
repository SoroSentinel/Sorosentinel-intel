### `sorosentinel-intel` (Go)

- **Owns:** `schemas/` (OpenAPI + JSON Schema, canonical key-encoding spec + test vectors), `wording/` (templates), `migrations/`, ingestion, detectors, verdict engine, API, snapshot publisher.
- **Commands:** check everything `make verify` (gofmt check, `go vet`, wordlint, tests, shared vectors) · test `make test` · lint `make lint` · build `go build ./...` · generate schemas `make gen` (no generator chosen yet; a no-op) · migrate `make migrate` (applies `migrations/` to `INTEL_DATABASE_URL`; forward-only, refuses edited migrations) · store, pipeline and API integration tests `make test-integration` (needs `INTEL_TEST_DATABASE_URL` pointing at a disposable Postgres 16; `make test` skips them without it) · run the read API `go run ./cmd/intel-api -snapshot-dir … -methodology-url … -review-url …` (reads `INTEL_DATABASE_URL`) · sync docs to Scan/Guard `scripts/sync-docs.sh`.
- **Rules:**
  - Schema changes are **additive within a major version**; breaking changes need a new `/v2` and a dual-run period. Regenerate packages; don't hand-edit generated code.
  - Ingestion is idempotent by `(network, ledger_seq)`, writes a checkpoint, and **halts with an alert on unknown XDR** (never skips or guesses). Detect and alert on non-contiguous ledger sequences.
  - Pin the XDR library version; upgrade it deliberately per protocol release (see §8).
  - Create `entity` rows lazily (on evidence, first lookup, or curated watchlist). Normalize muxed `M…` → `G…` on input.
  - Contract verdicts record the WASM hash and `as_of`; re-scan/recompute on contract upgrade.
  - Verdicts: rule table (not numeric score), `active | revoked` + `disputed` flag, every change appends to `verdict_events`. Replay tests must reproduce stored verdicts.
  - Migrations are forward-only and tested against a copy of representative data.
  - Detectors ship **with** their templates and a golden-corpus test; no detector merges without both.
  - Evidence store holds public data only; reporter PII goes in a separate erasable store.
