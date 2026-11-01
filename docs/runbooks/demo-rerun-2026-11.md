# Runbook record: `make demo` re-run, 2026-11-01 (testnet)

A dated re-run of the end-to-end demo described in [local-demo.md](local-demo.md), recorded so that the demo claim in the READMEs, the docs site and the grant application has a current date next to it rather than only the 2026-10-28 exit test.

**Result: PASS, 4 minutes 8 seconds** (`real 248.34`), steps 1–7 with no manual intervention.

## 1. Setup

| Item | Value |
|---|---|
| Date | 2026-11-01 |
| Network | testnet, RPC `https://soroban-testnet.stellar.org`, **protocol 29** (the Protocol 30 testnet vote is 2026-11-03; see §5) |
| Intel commit | `a9ffdc9` — a docs-only commit on top of `main` at `3985bdc`, so the built images are `main`'s code. Ruleset `2026.10.1` |
| Guard commit | `19c1595` (`main`) |
| Host | Apple M1 Pro, macOS, Node v26.9.0, Docker 29.5.2 under Colima (2 CPU / 4 GiB) |
| Images | Intel worker/API images cached from a previous run; the demo-tools image rebuilt during this run |
| Signing key | throwaway Ed25519 key generated inside the stack, `key_id demo-test-key`, removed with the volumes |

The signing key never left the container. No secret seed was printed, logged or committed. The holder and signer accounts are omitted here; the issuer appears only inside the asset key, because the asset key is the thing the pipeline hashes.

## 2. Observations

| Step | Output |
|---|---|
| 1 prerequisites | `RPC https://soroban-testnet.stellar.org is testnet` |
| 2 stack | worker from ledger **5502234**; `postgres`, `intel-worker`, `intel-api` running; `TEST-ONLY snapshot signing key generated`; API on `127.0.0.1:18080` |
| 3 issuance | issuer `GCBQ…XMNF` with `home_domain example.com`; a holder opened a `USDC` trustline in ledger **5502282** (48 ledgers of ingestion behind the worker start) |
| 4 snapshot | after one poll cycle: **version 2, 1 entry**, `key_id demo-test-key`, `generated_at 2026-11-01T12:10:54Z`; the entry the demo waited for was `93c43f1a03a8ae988ce4d6ebd0051440` |
| 5 read API | `"signal_level": "caution"`, `"as_of": "2026-11-01T12:10:51Z"`, `"ruleset_version": "2026.10.1"`, `"disputed": false`, `"statements": []` |
| 6 Guard, look-alike | `status: findings_present`, `snapshot: verified`, `operations: 1`, `effects: 1` (`native delta_min=-100 delta_max=0 assurance=ledger`), **`high G-TRUST-FLAGGED`** with `entity_type=asset roles=trustline`, `not_checked: NC-EXECUTION-TIME` |
| 7 Guard, control | `status: no_issues_found`, `snapshot: verified`, `findings: 0`, same effect line, same `not_checked` |

Three of those rows are worth reading twice, because they are the invariants rather than the happy path:

- **`"statements": []`** is the renderer failing closed on live data. All 12 templates are still `status: draft` (Intel #32), so the API answers with facts and no prose. A demo that printed a sentence today would be the bug.
- **`caution`** is the public signal name for "one or more observed signals are worth checking". The internal level that produced it never appears in the response.
- **`snapshot: verified` on both cases**, including the control, is the point of the exercise: the control is not flagged because it is not a look-alike, not because Intel was unreachable. Guard checked the signature against the pinned key both times.

## 3. What this run does and does not prove

Proves: the decode → ingest → evidence → verdict → sign → publish → verify → advise chain still works end to end on a live Stellar network, on protocol 29, from a clean clone of `main`, in one command, in under five minutes.

Does not prove:

- **precision.** Nothing here measures false positives; the labeled corpus still has no labels (Intel #45).
- **any deployment property.** Local containers, `127.0.0.1`, no TLS, no rate limit, a throwaway key. Nothing is hosted (Intel #33).
- **the two cases being hard.** The control issuer is the reference `USDC` issuer; this is the same scenario as the 2026-10-28 exit test, not a new one.
- **cold-build time.** The worker/API images were cached. A first run on a clean machine adds the image builds, so report a cold number to an organizer, not this one.

## 4. Reproducing

```sh
git clone https://github.com/SoroSentinel/Sorosentinel-guard.git && (cd Sorosentinel-guard && pnpm install)
git clone https://github.com/SoroSentinel/Sorosentinel-intel.git && cd Sorosentinel-intel
GUARD_REPO=../Sorosentinel-guard make demo
```

Keep the stack up to curl it yourself: `DEMO_KEEP_STACK=1 make demo`, then `curl -s http://127.0.0.1:18080/v1/snapshots/latest`.

## 5. Re-run after 2026-11-03 before quoting this page

The testnet Protocol 30 vote is scheduled for 2026-11-03. From that ledger onward `intel-worker` **halts by design** — `xdrcompat` refuses an unknown protocol — and this demo fails at step 4 with `intel-worker stopped`. That is the intended behavior, not a regression: ingestion never guesses a ledger shape (AGENTS.md §7a).

The demo works again once the XDR pin is bumped to `go-stellar-sdk` v0.8.0 per [protocol-30-preflight-2026-10.md](protocol-30-preflight-2026-10.md) and ARCHITECTURE §12 (Intel #37). Do not raise `xdrcompat.MaxProtocol` to make the run pass. After that bump, re-run this record and replace the numbers; a dated runbook is only worth as much as its date.

## 6. The 13:14Z run — the numbers in the README film

`make demo` was run a second time the same afternoon, on the same commits, and its output is what the 88-second film in the README shows. The numbers differ from §2 only because the stack started from a later ledger and Friendbot handed out different throwaway accounts. Everything in §3 and §5 applies to this run as well.

| Item | Value |
|---|---|
| Worker start | ledger **5503035** |
| Trustline ledger | **5503042**, issuer `GAVZ…MA6UH` with `home_domain example.com` |
| Asset key | `USDC:GAVZ…MA6UH` — the carrier the film follows |
| Snapshot | **version 3, 1 entry**, `key_id demo-test-key`, `generated_at 2026-11-01T13:14:41Z`, entry hash `c3557f9811b8c64d2153c3b5c2bd1dc1` |
| Read API | `"signal_level": "caution"`, `"as_of": "2026-11-01T13:14:13Z"`, `"ruleset_version": "2026.10.1"`, `"disputed": false`, `"statements": []` |
| Guard, look-alike | `status: findings_present`, `operations: 1`, `snapshot: verified`, `effects: 1`, `native delta_min=-100 delta_max=0 assurance=ledger`, `high G-TRUST-FLAGGED entity_type=asset roles=trustline`, `not_checked: NC-EXECUTION-TIME` |
| Guard, control | `status: no_issues_found`, `findings: 0`, same `not_checked` |

The film adds no claim this table does not carry. Accounts are abbreviated to their first and last characters for the same reason as in §2: they are throwaway testnet accounts, and a truncated identifier is harder to mistake for a real one.
