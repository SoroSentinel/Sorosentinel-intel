# sorosentinel-intel

Threat-intelligence backbone for SoroSentinel (Go). Owns the shared schemas
(`schemas/`), the approved public wording (`wording/`), and the canonical docs.

Status: Phase 0 scaffold. See `docs/project_structure.md` §3 and §8.

## Commands

```
make deps          # download and verify pinned modules
make fmt           # gofmt
make lint          # gofmt check, go vet, wordlint
make test          # unit tests
make test-contract # shared vectors (canonical keys, render) and schema checks
make gen           # schema codegen (no generator chosen yet)
make verify        # lint + test + test-contract; run before calling a task done
```

## Layout so far

| Path | What |
|---|---|
| `schemas/` | JSON Schema + OpenAPI contracts and shared test vectors |
| `wording/` | Template registry, attribution, blocklist, render vectors |
| `internal/entity/` | Canonical entity-key encoding |
| `internal/signal/` | Internal level → public signal mapping |
| `internal/wording/` | Template loader, linter, fail-closed renderer |
| `cmd/wordlint/` | Template + blocklist lint (run in CI) |
