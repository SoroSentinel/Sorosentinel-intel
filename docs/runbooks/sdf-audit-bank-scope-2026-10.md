# SDF Audit Bank scope: 2026-10-29

SDF's Soroban Security Audit Bank funds an external audit after an award, so the
scope has to be ready before the money is (Intel #71). This page is that scope:
which components an auditor should open, at which commit, how to reproduce the
tests that back each claim, and what is already known to be weak.

This is **not** a security review, and it does not claim any component is
without vulnerabilities (AGENTS.md §3.1). It routes limited audit hours to the
places where a mistake would actually cost something.

## 1. In scope

Four components, in the order the threat model makes them worth reviewing.

### 1.1 Guard: decode and effect derivation

| | |
|---|---|
| Repo / paths | `sorosentinel-guard`: `packages/core/src/decode/` (`envelope.ts`, `account.ts`, `operations.ts`, `network.ts`, `types.ts`), `packages/core/src/effects/` (`derive.ts`, `asset.ts`, `contract.ts`, `types.ts`), `packages/core/src/analyze.ts`, `packages/core/src/rules/`, `packages/core/src/assert-never.ts` |
| The property | **Only the bytes that are signed are analyzed** (AGENTS.md §3.8), and every XDR union arm is either handled or makes the result `unanalyzable`. Nothing decodes into a guess. |
| What to attack | A hostile envelope: unknown operation arm, `hash(x)` and preauth signers, muxed sources, per-operation source accounts, fee-bump inner/outer, padding, an envelope from an unknown network, an oversized input. |
| Claims to test | Effects are per affected account from the signer's perspective, with `delta_min`/`delta_max` and an `assurance` tag, and event-derived values are never presented as ledger truth (§3, ARCHITECTURE §5). Money is integer stroops end to end (§3.11). |
| Existing evidence | `packages/core/test/decode.test.ts`, `effects.test.ts`, `analyze.test.ts`, `rules.test.ts`, `property.test.ts` (randomized), `replay.test.ts` plus `scripts/replay.ts` and `scripts/export-rpc-txs.ts` (real RPC envelopes); one fixture per operation/credential variant under `fixtures/tx/benign/`, hostile cases under `fixtures/tx/hostile/`; `fixtures-check` regenerates them and fails on any diff. |
| Compile-time control | `assert-never.ts` is the exhaustive-switch guard, so a new protocol arm fails the build rather than falling through silently. |

### 1.2 Snapshot signing (Intel) and verification (Guard)

| | |
|---|---|
| Repo / paths | `sorosentinel-intel`: `internal/snapshot/snapshot.go`, `internal/snapshot/keyfile.go`, `cmd/intel-worker/main.go`. `sorosentinel-guard`: `packages/core/src/intel/snapshot.ts`, `packages/core/src/canonical/key.ts`. Shared: `schemas/vectors/snapshot_signing.json`, `schemas/canonical-key.md`, both repos' `test/contract/` suites |
| The property | A snapshot that fails to verify, names an unknown key id, or is older than the max age is **refused**, and Guard then reports `stale`/`partial` instead of treating absent intelligence as absence of risk (§3.9). |
| What to attack | Signature confusion (is the signed payload exactly the canonical bytes, with no re-encoding on either side?), key-id substitution, a valid signature over a wrong network, a future timestamp, a truncated or oversized snapshot, a replayed older version. |
| Existing evidence | Intel `internal/snapshot/snapshot_test.go`, `keyfile_test.go`; Guard `packages/core/test/contract/snapshot.test.ts` runs the pinned `snapshot_signing.json` vectors and `canonical-keys.test.ts` runs the shared key-encoding vectors; Guard's `make schemas-check` (part of `verify`) re-hashes the copied vectors against `intel-schemas/SHA256SUMS`, so they cannot drift silently. |
| Known deviation | The production signer is not a KMS yet — see §5 row 1. Today's signer is `Ed25519Signer` (in-memory key) plus `keyfile.go`, which ADR 0006 records as an accepted, stated deviation rather than an oversight. |

### 1.3 The isolated fetcher

| | |
|---|---|
| Repo / paths | `sorosentinel-intel`: `internal/fetcher/fetcher.go` (+ `fetcher_test.go`), call sites in `internal/pipeline/pipeline.go` (`homeDomain`, `rateLimit`) |
| The property | Every outbound fetch of an attacker-controlled URL (`stellar.toml` above all) goes through one client that cannot be talked into reaching an internal address (AGENTS.md §6). |
| What to attack | DNS rebinding and re-resolution between check and connect, link-local and metadata ranges (`169.254.169.254`), IPv6 mapped forms, a redirect that lands somewhere the first request was refused, a non-443 port, a body larger than the cap, a slow-body timeout, userinfo in the URL. |
| Claims to test | The IP policy is evaluated **at dial time**, so it holds after DNS and on every redirect (`internal/fetcher/fetcher.go:3-4`); `IsPublic` (`fetcher.go:177-190`) blocks loopback, private, link-local including the `169.254.169.254` metadata address, CGNAT, unique-local, multicast, unspecified, benchmarking and documentation prefixes, and is wired into the dialer (`allowIP: IsPublic` at `fetcher.go:77`, checked per connection at `:82-84`, `DialContext` at `:91-95`); the port must be 443 (`fetcher.go:83`) and that rule is lifted only by the test-only `WithTestServer` option (`fetcher.go:50-52,70`); `MaxBodyBytes` 100 KiB, `Timeout` 10 s, `maxRedirects` 3 (`fetcher.go:25-30`); the pipeline rate-limits repeat fetches (`internal/pipeline/pipeline.go:329`). |
| Existing evidence | `internal/fetcher/fetcher_test.go`, `internal/pipeline/pipeline_test.go` (`TestFetchesAreRateLimited`). On the text side: `internal/wording/wording_test.go:161-166` refuses a renderer configured with an unsafe URL (including `javascript:`, userinfo and a bidi override), and `internal/api/api_test.go:342` pushes `<script>alert(1)</script>` through an entity-key path expecting `invalid_key`. |

### 1.4 The Scan sandbox

| | |
|---|---|
| Repo / paths | `sorosentinel-scan`: `crates/scan-core/src/` (`parse.rs`, `meta.rs`, `spec.rs`, `detectors.rs`, `limits.rs`, `report.rs`, `sarif.rs`), `crates/scan-cli/src/main.rs`, `sandbox/Dockerfile`, `fuzz/fuzz_targets/`, `.github/workflows/fuzz.yml` |
| The property | Hostile WASM is **parsed, never executed**, under resource caps; output is deterministic for the same input and `ruleset_version`; the spec/meta custom sections are treated as untrusted claims, not facts. |
| What to attack | Section-count and module-size exhaustion, an `env_meta` or `contractspecv0` blob designed to make the reader retain unbounded data or recurse, deep `SCSpecTypeDef` nesting, an endless sequence of empty arrays, a module whose declared imports/exports exceed the caps. |
| Claims to test | `#![forbid(unsafe_code)]` in both crates (`crates/scan-core/src/lib.rs:3`, `crates/scan-cli/src/main.rs:7`); the caps in `crates/scan-core/src/limits.rs` (1 MiB module, 256 payloads, 32 custom sections, 4096 imports and exports, 128 bytes of retained `env_meta`, 64 KiB spec body, 512 spec entries, nesting depth 8, 20 000 strings) — and that an over-cap input is **dropped, not partially followed**: an `env_meta` blob larger than the cap "is not retained at all", and a spec deeper than `MAX_SPEC_DEPTH` is not followed rather than guessed at (`limits.rs` comments). Two sections that claim different values cancel out instead of one being picked (`MAX_ENV_META_SECTIONS`, `MAX_SPEC_SECTIONS`). The seven indicator ids (`S-UPGRADEABLE`, `S-CROSS-CALL`, `S-CREATES-CONTRACTS`, `S-OLD-SDK`, `S-NO-SPEC`, `S-SEP41-DEVIATION`, `S-KNOWN-BAD-HASH`) reach Intel as **one** informational detector, `D-CONTRACT-SCAN`, whose `MaxAlone` is `unknown` (`internal/verdict/rules.go:58`), and the rules table refuses to load if an informational detector is given any higher ceiling (`rules.go:89`) — so no scan indicator can raise a level by itself. The per-indicator trust line (a known-bad hash raising more than `unknown`) is still a TODO waiting on ADR 0002 (`rules.go:56-57`). |
| Existing evidence | `crates/scan-core/tests/` (`scan.rs`, `sep41.rs`, `sarif.rs`, `schema_contract.rs`, `fuzz_seeds.rs`, `common/mod.rs`), five fuzz targets run in CI (`fuzz.yml`, `make fuzz`), `make schemas-check` proves the report against the pinned `ScanReport` schema. |
| The image | `sandbox/Dockerfile`: static musl binary, `FROM scratch`, `USER 65534:65534`, base pinned by digest — no shell, no package manager, no network tools. **Note before trusting it:** the build image is `rust:1.99.0-alpine@sha256:0cce0a5e…` while the comment above it names `rust:1.98.1-alpine` and `rust-toolchain.toml` pins channel `1.98.1`; which toolchain actually compiles the binary depends on rustup behavior inside the container and is `TODO(verify)` by building the image and reading `rustc -V` out of it. Its runtime limits are set by whoever runs the container, which is §5 row 8. |

## 2. Adjacent surface, worth the remaining hours

Two things the issue does not name but that sit on the same trust boundary:

- **Untrusted strings to a user's screen.** `packages/core/src/wording/sanitize.ts`
  and the plain-DOM `packages/core/src/ui/findings.ts` in Guard, plus
  `internal/wording/` and `cmd/wordlint` in Intel. Asset codes, memos, domains and
  a wallet's own `error.message` are attacker-controlled text; the rule is escape,
  strip control and bidi characters, never linkify, and never render prose that
  did not come from an approved template (§3.6, §5). Tests: Guard
  `test/sanitize.test.ts`, `test/ui-findings.test.ts`, `test/wording.test.ts`;
  Intel `internal/wording/wording_test.go`.
- **Canonical entity keys.** `schemas/canonical-key.md` and
  `schemas/vectors/canonical_keys.json`, `internal/entity/canonical.go`,
  `packages/core/src/canonical/key.ts`. If the two implementations disagree, a
  lookup silently misses and Guard reports nothing about an entity Intel has
  flagged. Both repos run the same 19 cases from that vector file, plus their own
  extras.

## 3. Explicitly out of scope

| Item | Why it is out |
|---|---|
| The 12 Protocol 30 XDR union arms | Not in the pinned SDK yet. Testnet vote 2026-11-03, mainnet 2026-11-23 (AGENTS.md §8). Reviewing decoder coverage before the pin moves is reviewing a tree that will change; see `docs/runbooks/protocol-30-preflight-2026-10.md`. |
| The SEP-43 wallet adapter | **Now in scope: it merged.** Guard PR #61 landed, so `packages/adapter-reference/` and `analyzeAuthEntry` are on `main`, and its byte-comparison step (`sameTransactionPayload`, `sameAuthEntry`) belongs in §1.1 — that is where a "we analyzed something else" bug would live. Guard #65 is the first such bug found here, and it was in the *reporting*, not the comparison: a compliant preimage-reading wallet's bare signature was labelled `signed_other_bytes`, an accusation the evidence did not support. |
| Deployment, gateway and secrets management | In v1 the gateway owns TLS, API keys and rate limits (`internal/api/api.go:10`, `cmd/intel-api/main.go:6`); no cloud deployment exists (Intel #33). Those controls are not auditable from these repos. |
| Dynamic analysis of contracts | Not built, and on the v1 do-NOT-build list (AGENTS.md §4; Scan #33). |
| Database and API as an attack surface | Only `intel-api` takes inbound traffic, and it is a thin read-only surface over Postgres (the four routes are listed in §5 row 10). Include it only if hours remain; its authN/authZ is the gateway's, per the row above. |
| Detector precision | No labeled corpus exists (Intel #45, Corpus #1), so no audit of "did this detector fire correctly" is possible yet. That is a measurement gap, not a code gap — see §5 row 6. |

## 4. Pins and reproduction

Audited tree, as of 2026-10-29:

| Repo | `main` | Notable pins |
|---|---|---|
| `sorosentinel-intel` | `ad13565dfc54f2bb9ea0acaab10390e962256b5a` | `github.com/stellar/go-stellar-sdk v0.7.3` (+ `go-xdr` indirect) in `go.mod`; CI's PostgreSQL `16.14-alpine` pinned by digest at `.github/workflows/ci.yml:30` |
| `sorosentinel-scan` | `63250ccd05d7f834fbc38334a106313eb236166b` | toolchain in `rust-toolchain.toml`, `wasmparser` per `Cargo.lock`, sandbox base `rust:1.99.0-alpine@sha256:0cce0a5e…` |
| `sorosentinel-guard` | `a05fb88054bad004948a58f75d5b7aa6469fe47d` | `@stellar/stellar-sdk` 17.2.1, TypeScript strict, `intel-schemas/` copies pinned by `SHA256SUMS` |
| `sorosentinel-corpus` | `c38e73935de13cfe8360a101f35909d988492db6` | E3 harness only: `scripts/precision.py`, `scripts/validate.py`, `schema/entry.schema.json`, their tests. `labels/` holds a single `.gitkeep` — no labeled entry exists yet (§5 row 6) |

Reproduce everything the claims above rest on. Each repo exposes the same
targets (AGENTS.md §7, `docs/project_structure.md` §2.2):

```sh
# in each repo
make deps && make verify        # lint + typecheck + unit + contract vectors (+ fixtures-check in Guard)

make test-integration           # Intel only: CI runs it against PostgreSQL 16
make fuzz                       # Scan only: the five fuzz targets, short run
make replay                     # Guard only: real RPC envelopes through the decoder
make sandbox                    # Scan only: build the image, then run it with your own --memory/--cpus/--network none
docker build -f sandbox/Dockerfile -t sorosentinel-scan .   # same image, from the Scan repo root
```

`make verify` is the gate that CI runs; a claim in this page that CI does not
check is marked as such in §5.

## 5. Known limitations, stated before the auditor finds them

| # | Limitation | Where | Audit consequence |
|---|---|---|---|
| 1 | Snapshots are signed with a software-held key, not the KMS. Intel #34 is open and ADR 0006 (row 6 of its decision table) records the deviation as accepted for this key's compromise impact (forged **public** intelligence text, mitigated by two key ids, a keyset pinned in Guard and a release revocation list). | `internal/snapshot/snapshot.go:62-83`, `keyfile.go`, `docs/adr/0006-gcp-provider-and-kms-signing.md` | Review the key-id handling, the pinned keyset and the revocation path rather than HSM behavior — and confirm the deviation's reasoning holds. |
| 2 | `DEFAULT_MAX_AGE_SECONDS` is 3600 and the product value is unconfirmed. | `packages/core/src/intel/snapshot.ts:11`, `docs/adr/0005-guard-integrator-contract.md:70` | A stale-snapshot window that is too wide is a real failure mode; test it, don't assume the number. |
| 3 | `MaxBodyBytes` = 100 KiB is `TODO(verify)` against SEP-1 guidance. | `internal/fetcher/fetcher.go:25` | If real `stellar.toml` files exceed it, home-domain evidence silently stops being collected. |
| 4 | `MAX_MODULE_BYTES` = 1 MiB is `TODO(verify)` against the network's maximum contract size — a cap below the network limit means valid contracts are refused. | `crates/scan-core/src/limits.rs:1-4` | Check the cap against the protocol limit, in both directions. |
| 5 | Strkey checksum validation happens at **one** boundary. `entity.NormalizeKey` checks shape by regex and says so in its own comment (`internal/entity/canonical.go:49-51`); the API then adds a real checksum check for account, contract and asset-issuer keys (`internal/api/entities.go:153,159-170`). The other callers of `NormalizeKey` get shape only: `internal/ingest/xdrcompat/xdrcompat.go:433,450`, both built detectors, `internal/fetcher/fetcher.go:122`, and the signer-key wording slot is shape-only as well (`internal/wording/slots.go:72-78`). Guard never sees a bad checksum because its addresses are output, encoded from the raw 256-bit key (`packages/core/src/decode/account.ts:10-13`). | `internal/entity/canonical.go:49-51`, `internal/api/entities.go:159-170`, `internal/wording/slots.go:72-78`, `schemas/canonical-key.md:32` | The write path and the read path disagree about what a valid address is. Worth a test in both directions, not a review of the regex. |
| 6 | No labeled corpus, so detector precision is unmeasured; the verdict rules for `D-CONTRACT-SCAN` are informational and the `known-bad-hash`/combined-class raises wait on ADR 0002. | `internal/verdict/rules.go:36,56-58`; `sorosentinel-corpus` `labels/` (empty), Intel's planned `corpus/` directory does not exist on `main` | Audit the rules' *shape* (reproducibility, `as_of`, revocation) — not their accuracy. |
| 7 | Detectors that the architecture lists are not built: only `assetlookalike` and `homedomain` exist; no `flags`, `trustlinespam`, `takeover`, `scanevidence`; there is no `internal/scanjob` or Galexie backfill. | `internal/detectors/`, `docs/project_structure.md` §3 | "Not built" must not be read as "built and clean". Several are `needs-approval`. |
| 8 | Scan's resource limits come from whoever runs the container; the repo pins the image, not the cgroups, and the fetcher's egress allowlist in production is a deployment property. | `sandbox/Dockerfile`, §3 row 3 | Ask for the actual `docker run` flags / job spec Intel will use (Intel #51) before accepting the sandbox as enforced. |
| 9 | The Guard latency baseline is one machine and its RPC figure is explicitly weak. | `docs/runbooks/guard-latency-baseline-2026-10.md` §4 | Not a security item, but do not treat its numbers as a bound. |
| 10 | Revocation and dispute exist as a library **and** as store methods (`internal/verdict/state.go:96-101`; `internal/store/store.go:39-40,266-274`, both recording `actor` and `reason`, and refusing the engine as an actor), but **nothing in `cmd/` calls them** — the only callers are tests. The API is read-only: `GET /v1/entities/{type}/{id}`, `POST /v1/entities:batchGet`, `GET /v1/snapshots/latest` and `GET /v1/snapshots/{version}` (`internal/api/api.go:83-86`). The `intelctl` admin CLI appears only in `docs/project_structure.md`, not in `cmd/`. So §3.3's human confirmation has no path through the software, and the two-person rule is an unenforced process. | `internal/verdict/state.go`, `internal/store/store.go`, `internal/api/api.go`, `cmd/`, Intel #53 | Review `verdict_events` (`migrations/0001_init.sql`) as the audit log, and treat the missing operator path as a finding in itself. |
| 11 | SEP-43 is a Draft, its result type `T & error?: Error` is pseudo-TypeScript, and `signAuthEntry`'s input is described as a "preimage" while typed as base64. | Guard `packages/adapter-reference/src/sep43.ts` header, `stellar/stellar-protocol@62a67297ea14 ecosystem/sep-0043.md` v1.2.1, `stellar/freighter@b237323ccf55` | **Checked and resolved 2026-10-30** (PR #61 merged; Guard #65). Both readings exist in the ecosystem and Freighter is the preimage one, so the adapter now classifies the reply (`signed` / `signed_other_bytes` / `signed_unverifiable`) instead of assuming it. Extended 2026-10-31 (Guard #66, PR #68): a bare signature is now *checked*, not filed as unknowable — `verifyAuthEntrySignature` rebuilds the preimage the analyzed entry implies and verifies it against the address the entry's credentials name, not the wallet's `signerAddress`, so `signed_unverifiable` is only the four inputs no claim can be made on. The upstream contradiction is still open; audit that derivation against CAP-0046-11 and CAP-0071-01/-02, not the spec. |

## 6. Open `security`-labeled issues, triaged (2026-10-29)

AC "triage open security issues first". Nothing here is closed — closure is the
issue owner's call, and two of these are delivered work still open as issues.

| Issue | State of the work | Gates the audit? |
|---|---|---|
| Intel #36 single-writer lease | **Delivered and merged** (`internal/store/checkpoint.go`, lease + `alert` log fields); issue left open for its owner | No |
| Guard #45 opt-in Intel API fallback | **Delivered and merged** (`packages/core/src/intel/api.ts`, `test/intel-fallback.test.ts`) | No |
| Intel #34 KMS-held signing key | Not built; ADR 0006 chose the provider and recorded the software-key deviation | **Yes** — §1.2 and §5 row 1 |
| Intel #51 sandboxed Scan triage | Not built (no `internal/scanjob`); note the job-table shape AGENTS.md §4 forbids, so it needs a decision before code | **Yes** — §5 row 8 |
| Intel #53 analyst confirmation tool | Not built. `verdict_events`, the state transitions and the store methods exist; no CLI or endpoint reaches them | Partially — §5 row 10 |
| Intel #54 monitoring, alerting, on-call runbook | Not built; the `alert: true` log convention exists in `cmd/intel-{ingest,worker,api}` and `internal/api/api.go:235`, but no alert rules or runbook consumes them | Indirectly — a halt nobody is told about is §3's fail-loud made silent |
| Intel #56 v0.1.0 with signed release artifacts | Not cut; depends on #34 for signing | Yes for supply-chain review |
| Intel #64 Repo Guard tracking (PRD §15) | Tracking issue | No |
| Intel #67 Tranche 2 threat model + monitoring plan | Not written; §1 of this page is the closest existing threat model | No, but it should not contradict this page |
| Intel #71 this scope | This page | — |
| Scan #30 released binaries + signed sandbox image | Not published; the image builds but no release or attestation exists | Yes for §1.4's provenance claim ("pinned by digest" is about the base image, not a released artifact) |
| Scan #33 dynamic analysis | Out of v1 scope by AGENTS.md §4 | No — and any audit hour spent here is wasted until the scope changes |

## 7. Two runbooks the tree promises and the repo does not have

`docs/project_structure.md` §3 lists `docs/runbooks/` as
`protocol-upgrade.md, snapshot-key-rotation.md, ingest-gap-recovery.md`. Only the
first exists (`protocol-upgrade.md`, plus dated pages for counsel review, the
Guard latency baseline, the Phase 1 exit test and Protocol 30 pre-flight).

An auditor will ask for both missing ones in the first hour: §1.2 cannot be
accepted without a documented rotation path for the pinned keyset, and the
`ErrGap` halt path (`internal/ingest/ingest.go:29,272-280`) has no recovery
procedure. Writing them is a documentation task, not a code change.

## 8. Re-pin at award time

The pins above are a snapshot of a moving tree. Before the scope is sent:

1. Re-read this page against each repo's `main` at that date and replace the four
   SHAs in §4; re-run every command in §4 and confirm green.
2. Re-check the Protocol 30 dates and the SDK pin — if the XDR pin moved, §1.1
   changes and `docs/runbooks/protocol-30-preflight-2026-10.md` is the checklist.
3. Re-run §6: the `security`-label query changes as issues land, and PR #61's
   outcome decides whether §1.1 grows an adapter row.
4. Write the two runbooks in §7.
5. Any change to *what is in scope* — a new component, a new detector, a KMS —
   needs an ADR line, not an edit to this page alone (AGENTS.md §8).
