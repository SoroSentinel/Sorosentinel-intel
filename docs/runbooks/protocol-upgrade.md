# Runbook: protocol and XDR upgrade

How to execute the ARCHITECTURE §12 runbook in Intel, with Protocol 30 as the
worked example. Guard has its own counterpart for the JS SDK (guard #14); this
page is about the Go XDR pin.

Related: intel #37 (the Protocol 30 bump), `phase1-exit-test.md` §0,
`local-demo.md` §0.

## 0. The dates, and why testnet is expected to halt

| Fact | Value | Source |
|---|---|---|
| Intel's current pin | `go-stellar-sdk` v0.7.3, published 2026-08-20 | `go.mod` |
| `xdrcompat.MaxProtocol` | 29 | `internal/ingest/xdrcompat/xdrcompat.go` |
| v0.8.0 published | 2026-10-20T21:30:21Z | `proxy.golang.org/.../@v/v0.8.0.info` |
| v0.8.0 eligible under the 14-day rule | **2026-11-03T21:30Z** | AGENTS.md §6 |
| Protocol 30 testnet upgrade | 2026-11-03 | ARCHITECTURE §12 |
| Protocol 30 mainnet upgrade | 2026-11-23 | ARCHITECTURE §12 |

The eligibility date and the testnet upgrade fall on the **same day**. So on
testnet the worker halts first and the permitted dependency arrives hours later.
That is the intended sequence, not an incident:

- A testnet halt is acceptable. Testnet is a development network, and nothing
  user-facing depends on it. `intel-worker` and `intel-ingest` exit non-zero and
  log `"alert":true`; leave them halted rather than improvising.
- The deadline that matters is **mainnet on 2026-11-23**. Bumping on or after
  2026-11-03 and validating against real post-upgrade testnet ledgers leaves
  about nineteen days of margin.
- Do not demo on mainnet during the vote week (PRD §14 HQ1 T1).

**Never** work around a halt by raising `MaxProtocol` alone. The constant is a
statement about which XDR definitions this build was checked against; raising it
without the bump makes the worker accept ledgers it cannot prove it decoded,
which is the one failure mode the whole ingestion design exists to avoid.

## 1. Ask first (blocking)

AGENTS.md §10 requires a human decision before changing the XDR library version.
Post on intel #37 and wait for approval. This gate is also the moment to confirm
that the 14-day rule is being satisfied rather than waived; if someone wants the
bump earlier than its eligibility date, that is an explicit exception to record
here, not a silent `go get`.

## 2. Verify the new version actually carries Protocol 30

Do not assume it from the version number or from the comment in `xdrcompat.go`.

```sh
go list -m -versions github.com/stellar/go-stellar-sdk
curl -s https://proxy.golang.org/github.com/stellar/go-stellar-sdk/@v/v0.8.0.info
```

Then read that release's notes and confirm it ships Protocol 30 XDR. If the
release notes do not say so, check the `xdr` package for the new ledger and
transaction-meta variants. Record what you found in the PR; if you cannot
confirm it, leave a `TODO(verify)` and stop.

Done in advance on 2026-10-28: `protocol-30-preflight-2026-10.md` §2 confirms
v0.8.0 carries Protocol 30 XDR (CAP-0084/0087/0088, regenerated from
stellar-xdr@4f524bba, ungated) and records which of its breaking changes actually
reach Intel, including the one that decides §0's halt: the new `StellarValue`
millisecond arms no earlier SDK can decode. Re-check it if the pin target changes.

## 3. Branch and bump the pin

```sh
git checkout -b chore/intel-xdr-v0.8.0 origin/main
go get github.com/stellar/go-stellar-sdk@v0.8.0
go mod tidy
git diff --stat go.mod go.sum
```

`git diff go.mod go.sum` must show **only** that module and its transitive
requirements. Any other package appearing here is an unapproved new dependency
(AGENTS.md §6) — investigate before continuing.

```sh
go build ./... && make verify
```

Expect failures at this point if the new XDR adds variants; that is the signal
doing its job, not a problem to suppress.

## 4. Review every exhaustive switch

`xdrcompat` is the only place Intel touches XDR. Walk each of these and decide
what a new variant means; the answer is either "handle it" or "fall through to
the existing `default`, which halts", and never "ignore it".

| Site | Switches over | What a new case means |
|---|---|---|
| `xdrcompat.header` | `meta.V` (0, 1, 2) | A new `LedgerCloseMeta` version carries fields the fact extractor never reads. |
| `xdrcompat.txChanges` | `tm.V` (0..4) | A new `TransactionMeta` version changes where ledger-entry changes are recorded. |
| `xdrcompat.changes` | `LedgerEntryChangeType` | A new change type is a new way state moved; skipping it loses facts silently. |
| `xdrcompat.trustlineAsset` | `AssetType` | A new asset type has no code/issuer pair the detectors can key on. |
| `xdrcompat.Decode` | protocol check, re-encode equality | Both must keep failing closed. |

Measured import surface, so this list is not guessed: Intel imports only `xdr`
(11 files), `strkey` (3), `network` (2) and `keypair` (1) from the module, none of
`ingest`, `historyarchive`, `horizonclient`, `rpcclient` or `protocols`. So the bump
also moves `strkey`, which v0.8.0 extends for CAP-0084 `W…` addresses — key
encoding, which is the cross-repo contract in §7, not an ingestion detail. See
`protocol-30-preflight-2026-10.md` §3.

Two properties must survive the upgrade:

1. **Byte-for-byte re-encoding.** `Decode` re-marshals the meta and rejects any
   difference, which is what proves nothing was dropped or normalised away.
2. **Halt, never skip.** `ingest.IsHalt` covers `ErrUnknownXDR`,
   `ErrUnsupportedProtocol` and `ErrInvalidData`, plus ledger gaps, inconsistent
   source responses and the wrong network. A new variant must reach one of
   those, not a `continue`.

If a new switch case is genuinely irrelevant to the two Phase 1 detectors, still
return `ErrUnknownXDR` for it until a detector needs it. Being loud about
unhandled input is cheaper than being wrong.

## 5. Replay ledgers, in the right order

`cmd/intel-ingest` is the replay tool: facts-only, in-memory checkpoint, exits
non-zero on any halt, and it logs counts only, so no addresses or untrusted
strings end up in the output. Run exactly one per network.

```sh
go run ./cmd/intel-ingest -network testnet -start-ledger <tip minus 500> -page-size 100
```

**Before the testnet upgrade** the newest ledgers are still protocol 29, so this
step proves only that the bump did not regress anything. That is exactly what
ARCHITECTURE §12 step 3 means by staging before the vote. Reproduce the v0.7.3
baseline: 50 live testnet ledgers decoded and re-encoded byte for byte.

**You cannot prove Protocol 30 decoding before Protocol 30 ledgers exist.** Do
not invent them. What you can do:

- Add a synthetic ledger at `LedgerVersion = 30` in `xdrtest` and assert
  `ErrUnsupportedProtocol` fires while `MaxProtocol` is still 29. This proves the
  halt path, not the decode path.
- Wait for the testnet upgrade, then replay **real** post-upgrade ledgers with
  the same command. This is the primary validation and it happens before the
  mainnet date.
- Re-run `make test-integration` and the Phase 1 exit test on those ledgers.

## 6. Raise `MaxProtocol` last

Only after step 5 shows real protocol 30 ledgers decoding and re-encoding
byte for byte:

- `xdrcompat.MaxProtocol` 29 → 30,
- update the package doc comment above it, which records what the pin was
  checked against and on what date,
- land it in the same PR as the pin bump, so the diff reads as one decision.

## 7. Cross-repo check

The canonical key encoding and its test vectors are shared with Scan and Guard
(HQ2 EC20). An XDR bump that changes how an asset or account key canonicalises
would silently desync snapshot lookups.

```sh
# Intel
make test-contract
# Scan and Guard, each in its own checkout
make test-contract && make verify
```

All three must pass at the same pinned schema version.

## 8. After the merge

1. Re-run the Phase 1 exit test (`phase1-exit-test.md`) and write a new results
   file under `docs/runbooks/` with the date, protocol version and pins used.
2. Re-check the `xdrcompat.go` comment in §2 of this runbook if it still claims
   v0.7.3.
3. Update ARCHITECTURE §12's "verify" markers and any `TODO(verify)` the upgrade
   settled.
4. `docs/runbooks/` is Intel-only — `scripts/sync-docs.sh` copies only PRD,
   ARCHITECTURE, ARCHITECTURE_ESSENTIALS and project_structure to Scan and
   Guard, so no doc sync is needed for this file.

## 9. Rollback

Revert the pin and `MaxProtocol` together. A halted worker is a safe state; a
worker publishing snapshots from partially decoded ledgers is not. Never publish
a snapshot built from a ledger that failed the re-encoding check.

## 10. Halt conditions you should expect to see

| Log line | Meaning | Action |
|---|---|---|
| `worker stopped` / `ingest halted`, `"alert":true`, `err` contains `xdrcompat: unsupported protocol version` | Ledger is newer than `MaxProtocol` | Expected on testnet from 2026-11-03 until the bump lands |
| `xdrcompat: unknown or malformed XDR` | Decoding is incomplete or re-encoding differs | Stop and investigate; do not restart past the gap |
| `xdrcompat: invalid ledger data` | A ledger rule the extractor relies on is broken | Same |
| non-contiguous ledger sequence | Ingestion gap | Needs a backfill decision; RPC keeps about 7 days |
