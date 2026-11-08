---
title: Threat model and monitoring plan
---

# Threat model and monitoring plan

Written 2026-11-01 for the SCF Build application's Tranche 2 requirement (Intel #67). It extends [ARCHITECTURE.md §9](../ARCHITECTURE.md), which lists threats and intended controls; this document adds what is **actually in the code today**, what is only planned, and the monitoring that would notice each one.

Read it with that split in mind. A control listed in §9 that is not in the table below is a design intention, and this document says so. Nothing here is a security claim about a deployed service — **nothing is deployed** (see [Project status](../site/status.md)), and the project has not been audited.

Line references are to `main` on 2026-11-01 in `sorosentinel-intel` unless a path says `guard/` or `scan/`. Re-verify them before treating any row as current; the honest way to use this file is to re-run the greps, not to trust the table.

## 1. What is being protected, and from whom

| Asset | Why an attacker wants it | Who holds it |
|---|---|---|
| The Ed25519 snapshot signing key | Whoever holds it can make Guard believe any set of entities is flagged, or that nothing is | Intel operator (currently a keyfile, §3.2) |
| The evidence store | Deleting or rewriting history would let a flagged entity look clean | Intel Postgres |
| The verdict a wallet acts on | Smearing a competitor, or laundering an asset past a wallet | Intel's public statuses |
| The wallet user's decision | Guard's output *is* the user's only view of the transaction | Everyone: Intel, the RPC, the dApp that supplied the XDR |
| The signing host running Scan | Contract bytecode is attacker-chosen input executed… never, but parsed always | Scan's sandbox |
| The `stellar.toml` fetch path | Intel makes outbound requests to URLs an issuer controls | Intel's isolated fetcher |

Trust boundaries, in the order anything crosses them:

```
attacker-controlled ledger bytes ─▶ ingest ─▶ evidence store ─▶ verdict ─▶ signed snapshot ─▶ Guard ─▶ human decision
attacker-controlled URLs ─▶ isolated fetcher ─▶ detector
attacker-controlled WASM ─▶ one-shot sandbox ─▶ ScanReport ─▶ (ingestion not yet built)
```

Every arrow above is a hostile-input boundary (AGENTS.md §3.5). There are no trusted inputs in this design, including the dApp-provided XDR Guard is asked about.

## 2. Guard — in the wallet

| Threat | Control in the code today | Gap, and where it goes |
|---|---|---|
| The SDK sends the transaction or the counterparty list to a third party | `analyze()` is synchronous and cannot reach the network: the snapshot lookup is local, and the Intel API fallback only runs from `analyzeAsync()` when the integrator passes `ctx.intel` explicitly (`guard/packages/core/src/analyze.ts:355`). Total network surface is two configured endpoints — the integrator's RPC and Intel — and there is no telemetry path to opt into | Nothing to close; keep the review rule that a new outbound call is an "ask first" item |
| A stale or forged snapshot is read as "nothing flagged" | `checkSnapshot` runs strict parse → pinned key by `key_id` → base64 + Ed25519 verify → network match → age window, in that order, and **any** rejection downgrades to `partial` with `NC-COUNTERPARTY-SIGNALS`. `guard/packages/core/src/intel/snapshot.ts:104-122` | The pinned key is a build-time constant with no revocation list or keyset manifest (deliberately cut from v1). Until releases exist, a wallet cannot rotate a compromised key without shipping a new SDK — §3.2 |
| An unknown operation type produces a clean answer | Exhaustive `switch` with a `never` check, so a new protocol variant is a compile error; anything undecodable is `unanalyzable`, never `no_issues_found` | Protocol 30 adds 12 union arms; only `ScAddressTypeMuxedContract` touches Guard. Tracked as Intel #37 / the P30 preflight runbook |
| The XDR Guard is handed was not the XDR that gets signed | Analysis is of exactly the bytes presented, fee-bump inner/outer and per-operation sources handled | The integrator contract (Guard ADR 0005) makes "what you analyze is what you sign" the wallet's obligation; a wallet that re-signs after analysis voids this control |
| Slow analysis pushes a wallet to skip it | Measured 2026-10-29: local p95 **1.4 ms**, with RPC simulation p95 **454 ms** against an 800 ms target | The end-to-end figure rests on one fixture and ran without a verified snapshot; re-measure against the integrator's real endpoint (Guard #47 follow-up) |
| A finding sentence overstates what the evidence supports | Guard returns structured facts and `statement: null`; public sentences come only from Intel's registry, whose renderer **fails closed** | 12 of 12 templates are `status: draft`, so today the product answers with facts and no prose. Counsel review (Intel #32) — not code |

## 3. Intel

### 3.1 Poisoning the record

The realistic attack is not hacking Intel — it is using it as designed: issue an asset whose code collides with a known one, or make a `stellar.toml` unreadable, and let the detector produce a signal.

| Threat | Control in the code today | Gap |
|---|---|---|
| An automated detector's output is treated as a determination | The rule table caps automated evidence at the highest level any detector can reach alone (`R-AUTOMATED`); the top public status needs a human confirmation record. `internal/verdict/rules.go:189` | The analyst tool that would create that record does not exist, so the top status is reachable only by writing rows by hand. Intel #53 |
| Evidence is edited or deleted after the fact | `evidence`, `verdict_events` and `public_statement` have `BEFORE UPDATE OR DELETE` and `TRUNCATE` triggers that raise; store tests assert the rejection. `migrations/0001_init.sql:141-170` | Triggers do not stop a superuser running the same DDL. Database-role separation at deploy time is not written down anywhere yet |
| An insider changes a verdict silently | Every change appends to `verdict_events` with actor, from/to level and status; replay tests recompute stored verdicts from evidence | No two-person rule and no export job. Recommended before mainnet, not built |
| A look-alike detector flags a legitimately shared code | Codes with several real issuers are listed and not flagged; the exception list is data, reviewed with the detector | The list is a maintainer judgment; precision is **unmeasured** (the corpus store has 0 label entries) |
| An issuer's unfetchable `stellar.toml` becomes a public signal | `fetch_failed` is a recorded reason with a sub-cause (`too_large`/`blocked`/`timeout`/`unreachable`), and an issuer with no `home_domain` is "not checked", not a mismatch | The detector cannot distinguish "does not list the asset" from "could not read the file". **Availability of a third-party domain is an input to a public status** — so a brief outage on a well-known issuer's domain can raise `caution` for its assets. Needs a re-check-over-time rule before mainnet; this is the most likely source of a false public signal in the current build |
| Report/submission abuse | Not applicable in v1: there is no report endpoint, no dispute queue, no community submission path | By design — Phase 2 (Intel #59, #60) and it is why the §9 "reporter trust weights" control has nothing to apply to yet |

### 3.2 Snapshot signing and the key

| Threat | Control today | Gap and the plan |
|---|---|---|
| Signing key theft | `LoadEd25519KeyFile` refuses a key readable by group or others (chmod 600), the file is capped at 4 KiB, and key bytes never appear in an error string | **This is the weakest control in the project.** An interim keyfile is the only signer; there is no KMS signer in `internal/`. ADR 0006 selects GCP Cloud KMS `ec-sign-ed25519` at SOFTWARE protection level, which a human must accept because raw-message Ed25519 signing is not offered at HSM level. Intel #34 |
| Key compromise persists because clients cannot stop trusting it | Guard pins by `key_id`, refuses unknown ids, and consults `revokedKeyIds` | Guard enforces `revokedKeyIds` on every snapshot check; a compromised key can be revoked immediately via configuration or release update, rejecting untrusted signatures with `revoked_key`. Intel #34 KMS signer is tracked for production custody |
| A snapshot tampered with in transit or by a CDN | Signature is verified client-side over the canonical byte layout; transport is never trusted | The verification path has vectors and tests; there is no second publisher to compare against |
| Two writers publish different snapshots for the same network | A Postgres advisory lock makes one process the writer per network, and losing it is a paging alert (`WRITER_LOCK_LOST`) | Single-writer per network only; nothing yet coordinates across regions because there is no region |
| Publishing something the publisher cannot re-verify | A recorded snapshot whose file is missing or disagrees with its row returns **503**, not the bytes (`internal/api/snapshots.go:117-119`) and pages as `SNAPSHOT_FILE_REJECTED` | — |

### 3.3 Supply chain and dependencies

Lockfiles committed, exact pins, Dependabot with a 14-day cooldown in all three repos, SHA-pinned actions, CodeQL and Scorecard workflows (scores measured 2026-11-01: Intel 7.6, Scan 7.6, Guard 7.5). The XDR library is version-pinned and upgrades follow the runbook rather than a merge. `Publish = false` on the Scan crates and no npm package exist yet, so today the supply-chain surface is the *integrator's* build of a source checkout. The Scorecard `Signed-Releases` and `Packaging` rows stay unanswerable until Intel #56 / Guard #48 / Scan #30 land.

## 4. Scan — hostile bytecode

Contract WASM is attacker-chosen input, so the sandbox is the control, and the report format is the honesty control.

- **Isolation** (`scan/sandbox/run.sh`): `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, a seccomp syscall allowlist, non-root, `--memory 256m --memory-swap 256m`, `--pids-limit 16`, a 30 s timeout. Contract code is never executed — only parsed — in v1.
- **Input limits**: every parser path has a size cap, and over cap a section is **not retained at all** rather than truncated; four of the caps are measured from real testnet modules and the rest are chosen, which the README states.
- **Output honesty**: 7 indicators, 6 `not_checked` items always present, every SARIF result at `level: none`, deterministic for the same `(input, ruleset_version)`.
- **Fuzzing**: 5 cargo-fuzz targets plus a seed corpus derived from sampled testnet modules.
- **Residual**: a container escape is the threat that only the sandbox itself defends. The crate forbids `unsafe` code, the one-shot lifecycle (no long-lived server, no job table, no callbacks) and a fresh container per job keep the blast radius to one process. This is the component most worth paying an auditor for (Intel #71).

## 5. The isolated fetcher

Fetching `stellar.toml` means Intel asks attacker-controlled URLs to make it connect somewhere. Controls, all in `internal/fetcher/fetcher.go`:

- HTTPS only, port 443 only, no proxies, no cookies, fixed `User-Agent` (`fetcher.go:77-83`).
- The address policy runs in `Dialer.Control`, on **the exact address being connected to after resolution** — so DNS rebinding to a private range is caught at dial time, and every redirect is re-checked, not just the first URL.
- Private, loopback, link-local and metadata ranges are denied (`IsPublic`, `fetcher.go:177-180`).
- 100 KiB body cap (also re-checked in the detector, so the parser never sees more), 10 s whole-request timeout, 3 redirects max.
- `ErrBlocked` / `ErrTooLarge` are surfaced as detector reasons, never swallowed.

Not built: per-domain rate limits and a network-segment egress allowlist at the infrastructure layer — both are deployment-time items that belong in the Tranche 2 runbook, and today there is no deployment to put them in. **TODO(verify)**: the 100 KiB cap is SEP-1's own limit and is marked unverified against current guidance in the source.

## 6. Monitoring plan

Three things a reviewer asked to see: ingestion, snapshot freshness, and key use. The first two have rules on `main`; the third is the weakest, and §6.3 says exactly how weak.

`internal/monitoring/alerts.go` is the single table of alert definitions. `make gen-alerts` writes `deploy/monitoring/log-metrics.json` (14 metrics) and `deploy/monitoring/alert-policies.json` (13 policies) from it, and tests fail if the committed artifacts and the table disagree, if a rule keys on a log line nothing emits, or if code emits an id the table doesn't list. Rules read Cloud Logging on structured slog lines rather than a scrape endpoint — adding an endpoint would need an approval, a port and an auth story, and every failure mode here is already a log statement. Operator actions are one section per alert in `docs/runbooks/oncall-alerts.md`, and the generated policies link to those anchors.

### 6.1 Ingestion

| Condition | Rule | Threshold | Severity |
|---|---|---|---|
| The worker exited on a bad ledger | `INGEST_HALT` | 1 line / 300 s | page |
| …because a ledger is missing from the source | `LEDGER_GAP` (halt_kind `gap`) | 1 / 300 s | page |
| …because XDR is unknown or the protocol is newer than the pin | `XDR_UNSUPPORTED` (`unknown_xdr`, `unsupported_protocol`, `invalid_data`) | 1 / 300 s | page |
| The single-writer lock went away | `WRITER_LOCK_LOST` | 1 / 300 s | page |
| Progress stopped without a halt | `INGEST_LAG` | `ledger processed` absent for 900 s | page |

The design point worth stating to a reviewer: ingestion **halts with an alert** on anything it cannot decode. It never skips a ledger and never guesses a shape. The same invariant is what makes `XDR_UNSUPPORTED` the expected first signal on Protocol 30 day, and the P30 preflight runbook is the prepared response.

### 6.2 Snapshot freshness

Publish interval default is 5 minutes (`-snapshot-interval`, floor 10 s), and the chain is deliberately wider at each end:

| Stage | Signal | What it means |
|---|---|---|
| A publish attempt failed | `SNAPSHOT_PUBLISH_FAILED` | 2 in 600 s, ticket — one is noise, the loop retries |
| Signing failed, so no snapshot exists at all | `SNAPSHOT_SIGN_FAILED` | 1 / 300 s, page |
| Nothing published for two intervals | `SNAPSHOT_STALE` | absence of `snapshot published` for 600 s, page |
| The API refuses to serve a snapshot it cannot re-verify | `SNAPSHOT_FILE_REJECTED` | 1 / 300 s, page, and the client gets 503 |
| The wallet's own limit | Guard rejects a snapshot older than 3600 s (or newer than +300 s) → `stale` / `from_future` → `partial` + "protection data stale" | The end of the chain is a *user-visible* degradation, not a silent one |

Both product values (`DEFAULT_MAX_AGE_SECONDS`, `MAX_FUTURE_SKEW_SECONDS`) carry a `TODO: confirm the product value` — they are engineering defaults, not an agreed SLA, and they should be set with the integrator before mainnet.

### 6.3 Key use — the honest answer

Today the only key-related signals are `SNAPSHOT_SIGN_FAILED` and the absence-based `SNAPSHOT_STALE`. There is **no** log of how often the key signs, nothing notices an unexpected `key_id` appearing in a published snapshot, and a keyfile on a disk leaves no audit trail. Two facts to state plainly:

- With the interim keyfile signer, "monitoring key use" means monitoring the *output* (snapshots appear and are valid). Detecting misuse of the key itself is not possible.
- Moving to Cloud KMS (Intel #34) changes this materially, and ADR 0006 chose the provider partly for that reason: Cloud Audit Logs record every crypto operation, and rotation becomes a visible event with a `key_id` change.

Planned rules for Tranche 2, none of which exist yet:

| Proposed rule | Watches | Fires when |
|---|---|---|
| `SNAPSHOT_KEY_ID_UNEXPECTED` | the `key_id` field of each published snapshot | a `key_id` outside the operator's allowlist appears — the only practical detection of a signer swap |
| `SNAPSHOT_SIGN_RATE` | KMS `crypto_keys.sign` counts | signings exceed the publish rate, i.e. something is using the key that is not the publisher |
| `FETCHER_BLOCKED_SPIKE` | the fetcher's `ErrBlocked` path | blocked-address attempts jump, which is what an SSRF probe against Intel looks like — **nothing alerts on fetcher failures today** |
| `DETECTOR_SILENCE` | per-detector evidence counts | a detector that used to emit stops emitting: a detector can be broken and look exactly like a quiet network |

The last two matter because a monitor that only fires on explicit errors cannot see a silent failure. `UNCLASSIFIED_ALERT` is the existing net under the taxonomy — a line that sets the `alert` flag with an id the table doesn't know — and it is the pattern these four would follow.

### 6.4 API and availability

`API_PANIC` (page), `API_STOPPED` (page), `API_ERROR_RATE` (>1% 5xx over 300 s across 2 windows, minimum 100 requests as the denominator so a low-traffic spike is not treated as an incident). Not covered and not built: TLS, API keys, rate limits and tiering are recorded as the gateway's job in v1 (`cmd/intel-api/main.go:6`), which means **the read API has no abuse control until it is deployed behind one.** That is a deploy-time task, not a code task, and it belongs in the Tranche 2 runbook.

## 7. Explicitly not protected against

Saying this is the useful part of a threat model.

- **The content of a `stellar.toml` is a claim, not identity.** A `consistent` status means an issuer's own domain agrees with the issuer — anyone who controls a domain can make that true. Nothing here defends against a legitimately-configured lie.
- **Precision is unmeasured.** No detector's false-positive rate is published, because the labeled corpus has no labels yet.
- **Guard's coverage is its own.** It derives per-account effects for seven classic operations and analyzes Soroban invocations through simulation; every other operation type is decoded and reported with a generic summary, not analyzed. `NC-OPERATION-EFFECTS` is in the result whenever that happens, so the gap is visible to the wallet rather than claimed away.
- **A wallet that signs without calling Guard, or re-signs after analysis**, is outside the product.
- **Physical compromise of the Intel host, or a subpoena**, are addressed by nothing in this design except that the evidence store holds public data only and there is no key material in it.
- **Dynamic analysis, fuzzy WASM similarity, source-level auditing** are out of scope by decision, and other tools do them better.

## 8. What changes this model at each tranche

| Milestone | New attack surface created | Control that must land with it |
|---|---|---|
| KMS signer (Intel #34) | Cloud IAM becomes the key-protection boundary | Audit-log-based `SNAPSHOT_SIGN_RATE` + `SNAPSHOT_KEY_ID_UNEXPECTED`, and a rotation runbook |
| Public testnet API (Intel #33) | Anonymous read traffic, scraping, and the first real rate-limit exposure | Gateway authn + rate limits before the URL is announced anywhere |
| Scan ingestion (Intel #50/#51) | Intel starts storing conclusions about other people's contracts, and starts launching containers on new deployments | A triage budget per ledger, caps on scans-per-hour, and the evidence class reviewed as part of the schema change (it is an "ask first" item) |
| Reports and disputes (Phase 2) | The whole §3.1 "poisoned verdict" threat becomes live: a public submission path is an attack surface by definition | Reporter trust weights, rate limits, a review queue, and the dispute SLA — none designed in enough detail to model today |
| Mainnet launch (Intel #58) | Real users act on the output | Counsel-approved wording, measured precision, and an agreed freshness SLA with the integrator |

## 9. Audit status

Not audited. Every README says so, and the four areas worth paying for are §2 (Guard decode and effect derivation), §3.2 (snapshot signing and verification), §5 (the fetcher) and §4 (Scan's sandbox) — that is the draft scope in `docs/runbooks/sdf-audit-bank-scope-2026-10.md` (Intel #71), intended to be spent through the SDF Audit Bank rather than from an SCF budget.

---

Sources for every claim above: `internal/monitoring/alerts.go`, `deploy/monitoring/*.json`, `docs/runbooks/oncall-alerts.md`, `internal/fetcher/fetcher.go`, `internal/snapshot/{snapshot,keyfile}.go`, `internal/api/{api,snapshots}.go`, `internal/verdict/rules.go`, `migrations/0001_init.sql`, `schemas/{canonical-key,snapshot-signing}.md`, plus the Guard and Scan files named inline. [ARCHITECTURE.md §9](../ARCHITECTURE.md) is the threat list this file was checked against; where the two disagree, the code is right and §9 needs the correction.
