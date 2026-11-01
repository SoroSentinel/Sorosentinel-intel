---
title: Project status
---

# Project status

Measured against `origin/main` in all three repos on **2026-11-01**. Re-measure
before quoting any number here — this page is a snapshot of a moving tree, and
nothing on it is a claim about what is running for anyone else.

## The short version

**The engineering is done to the point where the core loop can be proven on a
local machine. Nothing is hosted, nothing is published, and no public text has
been approved.** If you are evaluating whether to integrate, the answer to "is
this live?" is no. The answer to "does the mechanism work end to end?" is yes,
with a recorded testnet run.

| | Intel (Go) | Scan (Rust) | Guard (TypeScript) |
|---|---|---|---|
| Role | ledger ingestion, evidence, verdicts, signed snapshot, read API | deployed-contract WASM triage in a sandbox | pre-signing transaction analysis SDK |
| Version in the tree | tag `v0.1.0-next.0` (pre-release) | `0.0.0` | `0.0.0` |
| Published | no GitHub Release | `publish = false` in `Cargo.toml`, nothing on crates.io | `private: true`, nothing on npm |
| Hosted | **nowhere** — runs only via `make demo` | one-shot container image, run by Intel or by hand | in-process SDK; runs inside the integrator's app |
| Audited | **not audited** | not audited | not audited |

## What is implemented

Counts read out of the trees on the date above.

**Intel** — 1 SQL migration (`0001_init.sql`, forward-only), 8 JSON Schemas under
`schemas/jsonschema/`, 4 read endpoints (`/v1/entities/{type}/{id}`,
`/v1/entities:batchGet`, `/v1/snapshots/latest`, `/v1/snapshots/{version}`),
6 commands (`intel-ingest`, `intel-worker`, `intel-api`, `gen-alerts`,
`wordlint`, `intel-fuzz-seeds`), the snapshot builder and verifier, the verdict
rule table, ledger-gap and lease handling, and halt-on-unknown-XDR ingestion.
**Two detectors produce signals: `D-ASSET-LOOKALIKE` and
`D-HOMEDOMAIN-MISMATCH`.** A `D-CONTRACT-SCAN` identifier appears in the schemas
and docs, but no code path writes that evidence: the `ScanReport → evidence`
wire is not built (Intel #50, #51). There is no analyst confirmation tool, so the
top verdict level — the one only a human can set — cannot be reached through the
product at all.

**Scan** — `scan-core` plus a one-shot CLI, 7 indicators, 6 `not_checked` codes,
SARIF 2.1.0 output, a `scratch`-based sandbox image, fuzz targets, and the
deterministic `ScanReport` validated against Intel's pinned schema. Nothing is
executed and nothing is fetched. See [reference/scan-indicators.html](reference/scan-indicators.html).

**Guard** — 8 finding codes, the four public statuses, canonical-key encoding and
snapshot verification in TypeScript, worst-case effect derivation for the v1
operation set, `analyzeAsync` Soroban simulation against an integrator-chosen
RPC, an opt-in Intel API fallback, a SEP-43 wallet adapter and auth-entry
analysis, a reference UI component, a replay harness (`make replay`) and a
latency baseline. 7 of its own `not_checked` codes. See
[reference/guard-findings.html](reference/guard-findings.html).

## What is proven, and how

`docs/runbooks/phase1-exit-test.md` and
`docs/runbooks/phase1-exit-test-results-2026-10.md` record a testnet run on
2026-10-28: a look-alike asset → two evidence rows → an automated verdict that
publishes as `caution` → a signed snapshot that verified, where changing one
entry produced `snapshot: bad signature` → Guard raising `G-TRUST-FLAGGED` at
high severity. The reference USDC issuer in the same run produced
`no_issues_found`. That is the whole pipeline, start to finish, on one case.

`make demo` reproduces it locally with Docker Compose. **The compose file is not
a production deployment:** it uses a throwaway test key, and only the read API is
published, on `127.0.0.1`.

## What is not there yet, and who owns it

| Gap | State | Owner |
|---|---|---|
| Public text | All 12 `wording/templates/en/` templates are `status: draft`; 0 approved. The renderer fails closed, so **the API and Guard return structured facts with no prose.** | Named counsel (Intel #32); merging the flip is not something an agent may do |
| Signing key | The interim keyfile path signs snapshots. No KMS signer exists. ADR 0006 chose GCP Cloud KMS `ec-sign-ed25519` at SOFTWARE protection level — FIPS 140-3 Level 1, not an HSM | Project owner: GCP account and spend (Intel #33) |
| Deployment | Nothing runs anywhere. No public API URL, no public snapshot URL, no production key to pin | Project owner (Intel #33, #46) |
| Precision | **Unmeasured.** There is no labelled corpus, so nobody can state what the detectors catch or how often they are wrong. The PRD's ≥98% precision target has no evidence for or against it | Corpora labelling (corpus #1, Scan #29, Intel #45) |
| Wallet | Zero integrations. End-user value flows through wallets, so with none there are no users | Project owner (Guard #38) |
| Repo identity | No logo or banner; no maintainer table, Telegram or security-contact email; 0 required PR approvals and one maintainer | Project owner (Intel #70) |
| Scan → Intel | The `ScanReport → evidence` ingest path is not written | Code (Intel #50, #51) |
| Product-flow demo | No video of the real flow; the two brand films in the READMEs are not substitutes | Blocked on a running stack |

Nine runbooks exist in `sorosentinel-intel/docs/runbooks/`. There is no
`mainnet-launch.md`, because there has been no launch attempt.

## Protocol 30

Ingestion and decoding read raw ledger XDR, so both depend on the XDR library
version. Protocol 30 is scheduled for **testnet on 2026-11-03** and **mainnet
vote on 2026-11-23**. The delta is 12 new union arms across 3 unions; only
`ScAddressTypeMuxedContract` touches Guard, and CAP-0088 is the Intel blocker.
`docs/runbooks/protocol-30-preflight-2026-10.md` and
`docs/runbooks/protocol-upgrade.md` are the procedure. A mainnet run needs
`-page-size 10`: at 50, mainnet metadata (~2.9 MB/ledger against testnet's
~314 KiB) exceeds the client's 64 MiB body cap and ingestion halts by design.

## Security posture

- **Not audited.** No third-party review of any of the three repos. The scope
  document for SDF's Audit Bank is filed (Intel #71) and awaiting a response.
- AGENTS.md §3 invariants are enforced in code and CI: no `safe` status exists,
  error paths return `partial` or `unanalyzable`, the top verdict level needs a
  human confirmation record, Guard never touches keys, public text comes only
  from the renderer.
- CI runs a blocklist lint on user-facing wording, `gofmt`/`vet`, `clippy -D
  warnings`, strict TypeScript with no `any`, and the shared canonical-key and
  snapshot-signing vectors in Intel's and Guard's suites. CodeQL and OSSF
  Scorecard workflows are configured in every repo, and Scan adds a fuzz
  workflow.
- Detector precision is measured against a labeled set kept in a separate
  `Sorosentinel-corpus` repo (labeling rules, an entry schema and a validator
  exist; `labels/` held zero entries as of 2026-11-01). Nothing is labeled yet,
  so no precision number exists for any detector.

## What this project is not

It does not block anything. It does not hold keys, sign, or submit transactions.
It is not an antivirus, an RPC provider, or a compliance oracle. Its output is
reproducible, attributable and reversible advice about effects and signals — and
it is, as of the date above, unfinished in the ways listed in this page.
