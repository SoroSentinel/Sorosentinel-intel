![SoroSentinel Intel Banner](media/sorosentinel-intel.jpg)

# SoroSentinel Intel

[![CI](https://github.com/SoroSentinel/Sorosentinel-intel/actions/workflows/ci.yml/badge.svg)](https://github.com/SoroSentinel/Sorosentinel-intel/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SoroSentinel/Sorosentinel-intel/badge)](https://scorecard.dev/viewer/?uri=github.com/SoroSentinel/Sorosentinel-intel)
[![Docs](https://img.shields.io/badge/docs-GitHub_Pages-blue.svg)](https://sorosentinel.github.io/Sorosentinel-intel/)
![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)
![Stellar](https://img.shields.io/badge/Stellar-Soroban-black)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Intel is the evidence and reputation backbone of SoroSentinel. It reads Stellar ledger data, runs rule-based detectors (look-alike asset codes, home-domain mismatches, account-takeover patterns), stores the raw evidence behind every signal, and publishes the results as a REST API and an Ed25519-signed snapshot that wallets can check offline. It also owns the shared schemas and the approved wording that every public statement must come from.

Part of **SoroSentinel**, security tooling for the Stellar ecosystem. It advises; it never controls the network and never touches private keys.

## Watch it work

[![A 23-second film: the word "verdict" struck through, then one testnet ledger's evidence chain assembling row by row, then the four internal levels Intel never publishes](media/sorosentinel-intel.jpg)](media/sorosentinel-intel.mp4)

No real account, asset or transaction hash appears in it: the issuer is shown truncated and the ledger number is a public testnet sequence. The panel is the Phase 1 exit test as recorded in `docs/runbooks/phase1-exit-test-results-2026-10.md` — one look-alike asset, two stored evidence rows, an automated-cap rule, a snapshot signed with Ed25519, and the public signal a wallet can verify for itself. `snapshot: bad signature` is what a copy with one entry changed fails with; Guard then reports `partial`, never a clean result. The four words struck through near the end are the internal levels that never leave Intel — what it publishes is `consistent`, `no_signals`, `caution` or `high_caution`.

Music: ["Business Moves Vol. 12"](https://www.ende.app) by Sascha Ende, used under CC BY 4.0.

### The whole flow, end to end

[![An 88-second film: one asset key printed on a run record — issued on testnet, stored as evidence, given a `caution` signal, packed into a signed snapshot, then stopped by Guard as `findings_present`](media/demo-flow.jpg)](media/demo-flow.mp4)

That is Intel plus Guard in one command: seven steps, 4 minutes 8 seconds, measured. Every line of product text in the film is verbatim stdout from the 13:14Z run of `make demo` on 2026-11-01, whose numbers are in [docs/runbooks/demo-rerun-2026-11.md](docs/runbooks/demo-rerun-2026-11.md) §6 — nothing is mocked up and no screen was redrawn. Accounts are abbreviated to their first and last characters; they are throwaway testnet accounts.

Two things the film shows instead of claiming. `"statements": []` is printed with its reason next to it: all twelve wording templates are still draft, so the renderer fails closed and the API answers with a level and facts, no sentence. And `not_checked: NC-EXECUTION-TIME` appears on both Guard results, including the control — a clean result still carries what was not checked. The film does not show contract WASM scanning, because `make demo` does not run it.

**Re-running it has an expiry date, and that is the product working.** Testnet reaches Protocol 30 at **2026-11-03 17:00 UTC**; this build pins XDR for protocol 29 (`xdrcompat.MaxProtocol`), so from that ledger onward `make demo` stops at step 4 with `intel-worker stopped` and an `unsupported protocol version` error. Ingestion refuses to guess a ledger shape it has not been taught, so it halts rather than returning something that looks clean. The film above is a recording of a passing run; [docs/runbooks/protocol-30-preflight-2026-10.md](docs/runbooks/protocol-30-preflight-2026-10.md) is the procedure that makes it pass again, and it waits on the `go-stellar-sdk` v0.8.0 pin (issue #37) — not on raising the ceiling, which would be the wrong fix.

Music: ["Business Moves Vol. 9"](https://www.ende.app) by Sascha Ende, used under CC BY 4.0. Sound effects are CC0 from [Kenney.nl](https://kenney.nl) (keyboard set by unicae_games).

## Maintainers

| Maintainer | GitHub | Contact |
|---|---|---|
| Allison | [@Teescom](https://github.com/Teescom) | [GitHub](https://github.com/Teescom) |

## Community

Questions and coordination: [GitHub Discussions](https://github.com/SoroSentinel/Sorosentinel-intel/discussions) and [Issues](https://github.com/SoroSentinel/Sorosentinel-intel/issues). Live documentation: [Documentation site](https://sorosentinel.github.io/Sorosentinel-intel/).

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
| `cmd/intel-fuzz-seeds/` | Exports deployed contract WASM for Scan's fuzzer (see below) |
| `docs/` | Canonical PRD, architecture, ADRs and agent instructions |

## Contract WASM for Scan's fuzzer

Scan cannot fetch (it depends on neither an HTTP client nor the Stellar XDR
definitions); Intel already reads both. `cmd/intel-fuzz-seeds` pages ledger
metadata over Stellar RPC, extracts each `ContractCode` entry's WASM, and writes
`<sha256>.wasm` files for `make fuzz` in
[Sorosentinel-scan](https://github.com/SoroSentinel/Sorosentinel-scan):

```bash
go run ./cmd/intel-fuzz-seeds -out ../Sorosentinel-scan/fuzz/seeds/scan -span 5000
```

It refuses any network whose passphrase it does not know, halts on a ledger gap
or on XDR this build cannot decode exactly, caps output size and module count,
and writes only public ledger data into a gitignored directory. Measured on SDF
testnet on 2026-10-28: 73 distinct modules (1.1 MB) in 3000 ledgers, so use a
wide `-span`. Nothing here is evidence or a verdict: the files are parser inputs
and are re-checked against the hash in the ledger entry they came from.

## Contributing

Pick an open issue (Wave issues carry the `Stellar Wave` label), comment to be assigned, then follow [CONTRIBUTING.md](CONTRIBUTING.md). Every PR must pass `make verify`. AI coding agents must follow [AGENTS.md](AGENTS.md).

## Security

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md). This code is **not audited**.

## Contributors

[![Contributors](https://contrib.rocks/image?repo=SoroSentinel/Sorosentinel-intel)](https://github.com/SoroSentinel/Sorosentinel-intel/graphs/contributors)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
