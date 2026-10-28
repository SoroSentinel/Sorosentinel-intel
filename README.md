<!-- TODO: add a banner/logo image here once one exists. -->

# SoroSentinel Intel

[![CI](https://github.com/SoroSentinel/Sorosentinel-intel/actions/workflows/ci.yml/badge.svg)](https://github.com/SoroSentinel/Sorosentinel-intel/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SoroSentinel/Sorosentinel-intel/badge)](https://scorecard.dev/viewer/?uri=github.com/SoroSentinel/Sorosentinel-intel)
![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)
![Stellar](https://img.shields.io/badge/Stellar-Soroban-black)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Intel is the evidence and reputation backbone of SoroSentinel. It reads Stellar ledger data, runs rule-based detectors (look-alike asset codes, home-domain mismatches, account-takeover patterns), stores the raw evidence behind every signal, and publishes the results as a REST API and an Ed25519-signed snapshot that wallets can check offline. It also owns the shared schemas and the approved wording that every public statement must come from.

Part of **SoroSentinel**, security tooling for the Stellar ecosystem. It advises; it never controls the network and never touches private keys.

## Maintainers | [Telegram](TODO-telegram-group-link)

| Maintainer | GitHub | Contact |
|---|---|---|
| TODO name | [@TODO](https://github.com/TODO) | [Telegram](https://t.me/TODO) |

## Community

Questions and coordination: [Telegram group](TODO-telegram-group-link).

## How the pieces fit

| Repo | Language | Role |
|---|---|---|
| [Sorosentinel-intel](https://github.com/SoroSentinel/Sorosentinel-intel) | Go | Evidence, detectors, signals, API, signed snapshot, shared schemas |
| [Sorosentinel-guard](https://github.com/SoroSentinel/Sorosentinel-guard) | TypeScript | Pre-signing transaction analysis SDK for wallets |
| [Sorosentinel-scan](https://github.com/SoroSentinel/Sorosentinel-scan) | Rust | Static triage of deployed Soroban WASM |

Data flows Scan → Intel → signed snapshot/API → Guard. The repos only talk through versioned schemas owned by Intel.

## Status

Phase 1 complete in code; the Phase 1 exit test passed on testnet on 2026-10-28. In place: RPC-only ingestion with checkpoints and gap detection, the asset look-alike and home-domain detectors, Postgres evidence and verdict storage with a rule table, the SSRF-safe fetcher, `cmd/intel-worker` publishing an Ed25519-signed snapshot, the read API (`cmd/intel-api`), shared schemas and vectors (pre-release tag `v0.1.0-next.0`), and the fail-closed wording renderer. Not yet: counsel-approved wording (all templates are drafts), a KMS signer, deployment, and the Protocol 30 XDR upgrade.

## Quick start

Prerequisites: Go 1.27+ and GNU Make.

```bash
git clone https://github.com/SoroSentinel/Sorosentinel-intel.git
cd Sorosentinel-intel
make deps
make verify
```

| Command | What it does |
|---|---|
| `make verify` | gofmt check, `go vet`, wordlint, tests, shared vectors, docs drift check |
| `make test` | Unit tests |
| `make lint` | gofmt, `go vet`, wordlint |
| `scripts/sync-docs.sh` | Regenerate `AGENTS.md` and push doc copies into the sibling repos |

## Repository layout

| Path | What |
|---|---|
| `schemas/` | Cross-repo contracts (JSON Schema, OpenAPI) and shared test vectors |
| `wording/` | Approved public text templates, attribution block, blocklist |
| `internal/` | Entity keys, signal mapping, wording renderer (more to come) |
| `cmd/wordlint/` | Template and blocklist lint, run in CI |
| `docs/` | Canonical PRD, architecture, ADRs and agent instructions |

## Contributing

Pick an open issue (Wave issues carry the `Stellar Wave` label), comment to be assigned, then follow [CONTRIBUTING.md](CONTRIBUTING.md). Every PR must pass `make verify`. AI coding agents must follow [AGENTS.md](AGENTS.md).

## Security

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md). This code is **not audited**.

## Contributors

[![Contributors](https://contrib.rocks/image?repo=SoroSentinel/Sorosentinel-intel)](https://github.com/SoroSentinel/Sorosentinel-intel/graphs/contributors)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
