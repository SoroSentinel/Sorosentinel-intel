# Protocol 30 pre-flight results (2026-10-28)

Status: measurements and citations only. **No dependency changed, no pin bumped, no code touched.**
This is runbook §2 answered in advance, so the bump PR starts from checked facts instead of assumption.
Both bumps stay gated: `xdrcompat` and the SDK pins are AGENTS.md §10 items, and neither release has
reached its 14-day eligibility date yet (§5 below).

## 1. Dates, from primary sources

| Item | Value | Source, checked 2026-10-28 |
|---|---|---|
| Intel's pin | `go-stellar-sdk` v0.7.3 | `go.mod` at `8f5088e` |
| Guard's pin | `@stellar/stellar-sdk` 17.2.1, published 2026-10-01T00:50:56Z | `packages/core/package.json:13`; `npm view @stellar/stellar-sdk time` |
| Go v0.8.0 published | 2026-10-20T21:30:21Z (module proxy), release object 21:30:48Z | `https://proxy.golang.org/github.com/stellar/go-stellar-sdk/@v/v0.8.0.info`; `api.github.com/repos/stellar/go-stellar-sdk/releases/tags/v0.8.0` |
| JS 17.3.0 published | 2026-10-21T19:14:25Z | `npm view @stellar/stellar-sdk time` |
| JS 17.4.0 (current latest) published | 2026-10-25T11:30:46Z | same |
| Eligible under the 14-day rule | Go v0.8.0 → 2026-11-03T21:30Z; JS 17.3.0 → 2026-11-04T19:14Z; JS 17.4.0 → 2026-11-08T11:30Z | AGENTS.md §6 |
| Protocol 30 testnet upgrade | 2026-11-03 17:00 UTC | SDF upgrade guide, `stellar.org/blog/developers/bell-protocol-30-upgrade-guide` |
| Protocol 30 mainnet activation | 2026-11-23 17:00 UTC | same |

The two dates AGENTS.md asserted are confirmed, and the testnet hour (17:00 UTC) is new information: the
Go pin becomes eligible at 21:30Z the same day, i.e. **about four and a half hours after testnet halts**,
not before it. Runbook §0's "the eligibility date and the testnet upgrade fall on the same day" still
holds and is now quantified.

`developers.stellar.org/docs/networks/software-versions` does **not** list Protocol 30 at all yet — its
highest entry is Protocol 29 (mainnet 2026-10-01). So the SDF blog is currently the only primary source
for the CAP list and the dates. Re-check that page before the mainnet bump.

## 2. Does v0.8.0 carry Protocol 30? Yes, and it is a breaking release

Verbatim from the v0.8.0 CHANGELOG (`raw.githubusercontent.com/stellar/go-stellar-sdk/v0.8.0/CHANGELOG.md`):

> **Breaking Changes**
> - xdr: Protocol 30 support (CAP-0084, CAP-0087, CAP-0088). Regenerated from stellar-xdr@4f524bba,
>   where all three CAPs are ungated, so `XDR_FEATURES` is now empty.

"Ungated" matters for runbook §5: with the CAPs ungated, the same XDR definitions decode pre- and
post-upgrade ledgers, so replaying pre-upgrade testnet ledgers is a real regression check rather than a
partial one.

## 3. What Intel actually imports from that module

Measured at `8f5088e` (`git grep -h "stellar/go-stellar-sdk" HEAD -- '*.go' | grep -v _test`, counted by
subpackage): `xdr` 11 files, `strkey` 3, `network` 2, `keypair` 1. Nothing imports `ingest`,
`historyarchive`, `horizonclient`, `rpcclient` or `protocols/horizon` — consistent with invariant
§3.10 (no Horizon) and with the RPC-only ingestion of ADR 0004.

Two corrections this forces on runbook §4:

- "`xdrcompat` is the only place Intel touches XDR" is true for `xdr`, but the bump also moves **`strkey`**,
  which v0.8.0 extends with `VersionByteMuxedContract` (`W…`), `MuxedContract`, `DecodeMuxedContract` and
  `IsValidMuxedContractAddress`. That is a key-encoding surface, and key encoding is the cross-repo
  contract (HQ2 EC20, runbook §7), not an ingestion detail.
- The Horizon effects change (`ContractMuxed` / `ContractMuxedID` on `ContractCredited`) is irrelevant
  here, and `support/storage` / `historyarchive` removals cannot affect Intel because nothing imports them.

## 4. The three CAPs, and what each one means for this repo

**CAP-0088 (millisecond close time) is the one that breaks ingestion, and it is not optional.** From the
changelog: new `StellarValue` arms `StellarValueTypeStellarValueSignedMs` and
`StellarValueTypeStellarValueEmptyTxSetMs`, plus a `TimePointMs` type, and — the sentence that decides
runbook §0 — *"Every ledger after the Protocol 30 upgrade ledger uses one of these arms, so earlier SDK
versions cannot decode them."* So `xdrcompat.MaxProtocol = 29` is not merely a policy gate after
2026-11-03: the pinned v0.7.3 has no arm to read. Runbook §4's switch table has no `StellarValue` row;
wherever Intel reads close time, that arm choice becomes load-bearing and must be walked at bump time.

The same release notes that `GetLcValueSignature()` "only reads the `SIGNED` arm, so it finds no
signature on any ledger after the Protocol 30 upgrade", and adds `StellarValueExt.LedgerCloseValueSignature()`
as the correct accessor. Intel reads no LCV signature today: the only `signature` hits at HEAD are snapshot publishing and
verification (`internal/api/snapshots.go:173`, `internal/pipeline/publish.go:72`) and the demo's
`xdr.DecoratedSignature` (`internal/demo/cmd/issue-lookalike/main.go:201`). So this is a trap avoided by
not being in that business — but re-check it if ledger-crypto verification is ever added.

**CAP-0084 (muxed contract addresses) lands on the key-encoding contract.** `ScAddress` gains a
`ScAddressTypeScAddressTypeMuxedContract` arm which renders as a `W…` strkey, and `strkey` gains the
matching version byte. Both repos currently refuse `W…` — see §5.

**CAP-0087 (ML-DSA) is names only in XDR terms**: new `ContractCostType` values 86–94, and the changelog
says explicitly "These are names only; cost params are positional, so they decoded before." No new signer
arm in `xdr` is described in this release's notes, so a post-30 Soroban `ScSigner` for ML-DSA is **not
established by these sources** — `TODO(verify)` before assuming Guard's signer rules need a new variant.

**Worth a separate look for Scan:** the same regeneration widens contract-spec UDT and event names to
`SC_SPEC_TYPE_NAME_LIMIT` (1024 bytes) and changes `ScSpecEventV0.Name` from `ScSymbol` to `string`. Scan
today only records `spec_present`, so nothing breaks, but Scan #7 (SEP-41 conformance read from the spec)
would be built on exactly these widened fields, and Scan's `MAX_NAME_BYTES` reasoning was calibrated
against import/export names, not spec names.

## 5. Measured current behaviour on a Protocol 30 address form

No Protocol 30 ledger exists yet, so this is a shape-level check of what happens *today* when a key that
is not `G…`/`M…`/`C…` reaches the entity canonicalizers:

- Intel `internal/entity/canonical.go:104-112`: `normalizeAccount` returns `ErrMuxedNotNormalized` for an
  `M` prefix and `ErrInvalidKey` for anything failing `accountRe`; a `W…` therefore lands in the second
  bucket, not the muxed one.
- Guard `packages/core/src/canonical/key.ts:67-71` mirrors it (`muxed_not_normalized` for `M`, then
  `^G[A-Z2-7]{55}$`).
- The path that decides whether a signer is reassured is the one that matters:
  `packages/core/src/intel/lookup.ts:117-118` catches a canonicalization failure and counts it as
  `unresolved`; `packages/core/src/analyze.ts:212` and `:214` turn any `unresolved` into
  `counterpartiesChecked = false`, which adds `NC-COUNTERPARTY-SIGNALS` (`analyze.ts:222`) and degrades
  the status through `statusOf`.
  **An address form Guard cannot canonicalize cannot read as "counterparties checked"** — invariant §3.9
  holds against a `W…` today, without any Protocol 30 code.

What this does not prove: that a real post-upgrade ledger decodes, or that `muxedId`-style fields
alongside a `W…` address are captured. That is runbook §5's job, after 2026-11-03.

## 6. Two silent-wrongness items to read before the bump

- `support/contractevents` bug fix: "A SAC transfer to a muxed destination (CAP-0067 `M…`, CAP-0084 `W…`)
  previously parsed as a transfer with `Amount` zero **and no error**." Intel and Guard both surface
  amounts, and AGENTS.md §3.11 makes money integers a hard rule. Neither repo uses that helper today
  (`git grep` at HEAD finds no `contractevents` import), so this is a "do not adopt it blindly" note rather
  than a bug here.
- The `txnbuild` fix (`BuildXDR` reusing cleared `SetOptions` fields, `FromXDR` merging into the receiver)
  is a lesson for Guard's own decode path: `setOptions` is one of the seven operations Guard derives
  effects for, and a decoder that merges into a reused object instead of replacing it produces exactly the
  kind of wrong-effect value that passes tests. **Checked 2026-10-30, and negative:** every Guard decoder
  returns fresh object literals, every accumulator is call-local, `aggregate()` copies before mutating
  (`effects/derive.ts`), no module-scope mutable state exists outside the wording registry's
  `ReadonlySet`s, and a simulation is only attributed when the transaction holds exactly one invocation.
  `SC_ADDRESS_TYPE_MUXED_ACCOUNT` carries its own `MuxedEd25519Account` struct, so `.muxedAccount.ed25519`
  is the right field, not a missed union arm; CAP-0084's `muxedContract` sits behind
  `#ifdef CAP_0084_MUXED_CONTRACT`, so when the pin moves, Guard's `assertNever` switches fail at compile.
  The review is closed by `packages/core/test/purity.test.ts` in Guard rather than by this note, because
  the existing suite would not have caught it: replacing `byKey.set(key, { ...d })` with
  `byKey.set(key, d)` — an in-place write into caller-owned data — leaves 675 of 676 core tests green.

## 7. Gate status

| Repo | Issue | Blocked on | Earliest the code change is *allowed* |
|---|---|---|---|
| Intel | #37 | AGENTS.md §10 approval for the XDR pin change; 14-day rule | 2026-11-03T21:30Z (then runbook §4-§6) |
| Guard | #14 | §10 approval; 14-day rule; `@stellar/stellar-sdk` 17.2.1 is compliant today | 17.3.0 on 2026-11-04T19:14Z, 17.4.0 on 2026-11-08T11:30Z |

Guard's `decode/account.ts:8-18` and `intel/lookup.ts:88` switches over `MuxedAccount` / `ScAddress` arms
are `assertNever`-terminated, so a new arm is a **compile-time** failure in TypeScript and a
`default → ErrUnknownXDR` halt in Go. That is AGENTS.md §7c working as designed: the upgrade should be
loud, and this document is where the loudness was predicted before it happened.
