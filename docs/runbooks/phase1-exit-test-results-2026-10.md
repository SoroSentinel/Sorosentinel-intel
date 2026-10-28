# Phase 1 exit test results: 2026-10-28 (testnet)

Run of [phase1-exit-test.md](phase1-exit-test.md) against ADR 0002 / PRD §9:
a look-alike asset on testnet is flagged by Intel, appears in the signed
snapshot, and Guard warns on a transaction adding a trustline to it.

**Result: PASS.**

## Setup

| Item | Value |
|---|---|
| Date | 2026-10-28 (before the Protocol 30 testnet vote on 2026-11-03) |
| Network | testnet, RPC `https://soroban-testnet.stellar.org`, protocol 29 |
| Intel commit | `b3b0e60` (main), go-stellar-sdk v0.7.3, ruleset `2026.10.1` |
| Guard commit | `bb12ec8` (main), `@stellar/stellar-sdk` 17.2.1, vitest 5.0.4 |
| Database | Postgres 16 in Docker (Colima), `make migrate` applied `0001_init.sql` |
| Signing key | throwaway Ed25519 PEM, key id `exit-test-key`, deleted after the run |

Keypairs, the signing key and all scripts lived in a scratch directory outside
both repos. No secret seed was printed, logged or committed. The holder
address is omitted here; the issuer appears only as part of the asset key.

## Steps and observations

1. **Worker start.** `-start-ledger 5429250`, `-snapshot-interval 30s`.
   Snapshot v1 published with 0 entries.
2. **Issuance.** Fresh issuer and holder funded by Friendbot. The issuer set
   `home_domain` to `example.com` (ledger 5429262), then the holder opened a
   trustline to `USDC` from that issuer (ledger **5429263**, tx
   `02b2643366465685e8a96080a29ba7ae0730562520cad1af850daabc2036093a`). The
   runbook §6 script worked as written; the run added a `getNetwork`
   passphrase check and `pollTransaction` attempts.
3. **Intel.** Worker logged `ledger processed` for seq 5429263 with
   `evidence_appended: 2`, `verdicts_changed: 1`. Evidence rows:
   `D-ASSET-LOOKALIKE` (`asset_code_lookalike`) and `D-HOMEDOMAIN-MISMATCH`
   (`home_domain_mismatch`), both at ledger 5429263. Verdict: `suspicious`,
   rule `R-AUTOMATED` (automated cap, as intended).
   - Asset key: `USDC:GAMKBI32WTNC7BNLFYPOIRGTW6YNKI3TW3OYIN6OPQXULSKAM3QB7ZLD`
4. **Snapshot.** First non-empty snapshot: **v4** (`entries: 1`), ~23 s after
   the ledger was processed. v4 to v7 all carry the same single entry.
   - Entry hash: `e2b218e853733f4eac33aafa44af7852`, equal to the first 16
     bytes of `SHA-256("testnet|asset|USDC:<issuer>")`.
   - `snapshot.Verify` against the pinned public key: OK. A copy with one
     entry changed fails with `snapshot: bad signature`.
5. **Guard.** Unsigned changeTrust envelope from the holder, analyzed with
   the latest snapshot (v5 at run time), pinned `exit-test-key`, `asOf` now,
   and `Networks.TESTNET`, through both `analyze` and `analyzeAsync`:

   | Case | status | snapshotStatus | findings | operations |
   |---|---|---|---|---|
   | Look-alike `USDC:GAMK…7ZLD` | `findings_present` | `verified` | `G-TRUST-FLAGGED` (high), facts `entity_type=asset`, `roles=trustline` | 1 |
   | Reference `USDC:GBBD…FLA5` | `no_issues_found` | `verified` | none | 1 |

   Both cases list `NC-EXECUTION-TIME` in `notChecked`. Sync and async
   results matched. The finding's `statement` is `null`: Guard findings carry
   structured facts and are rendered separately (by design, not a failure).

Worker ran to ledger 5429287 with no `"alert":true` lines, then was stopped.

## Follow-ups

- Runbook §6 script can drop its `TODO(verify)`: it was run on 2026-10-28.
- After 2026-11-03 the worker halts on testnet until the XDR bump to v0.8.0
  (ARCHITECTURE §12); re-run this test after that bump.
