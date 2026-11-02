---
title: How SoroSentinel compares
---

# How SoroSentinel compares

Stellar already has risk data and security tools. This page says what they do, what SoroSentinel does differently, and where the two meet.

Each claim about another project was checked on 2026-11-02 against that project's own API or README, and is linked so you can check it again. Projects change; if a line here is out of date, open an issue.

## In one table

| Project | What it looks at | When | Where it runs | SoroSentinel component it sits next to |
|---|---|---|---|---|
| StellarExpert directory and ratings | accounts, domains, assets | continuously, curated | hosted API | Intel |
| Assay | an asset issuer's authorization flags | on request | Soroban contract on testnet | Intel (issuer-flag detector, planned) |
| Stellar Agent Guard | an AI agent's own transactions against its spending policy | before broadcast | custom account contract plus SDK | Guard |
| soroban-security-scanner | contract **Rust source** | before deployment | CLI | Scan |
| soroban-upgrade-safeguard | two **WASM builds** of the same contract | before an upgrade | CLI | Scan |
| Stellar-Explain, stellar-xdr-lens | a transaction that already happened, or a raw XDR blob | after the fact, or while debugging | hosted API (Horizon), Go CLI | Guard |
| **SoroSentinel** | the exact bytes a wallet user is about to sign; deployed bytecode; ledger evidence | **before signing**; continuously | SDK in the wallet; Go service; sandboxed CLI | — |

## StellarExpert

StellarExpert is the most widely used source of Stellar reputation data today. Verified against its public API:
- **An address directory** that follows [SEP-0037](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0037.md) (status: Draft).
  - Entries carry tags such as `exchange`, `issuer`, `memo-required` and `unsafe`.
  - Tag list: `https://api.stellar.expert/explorer/directory/tags`.
- **A domain blocklist,** served at `https://api.stellar.expert/explorer/directory/blocked-domains`.
- **Asset ratings** scored on age, activity, trustlines, liquidity, 7-day volume and interoperability, returned with each asset record.

It covers far more entities than SoroSentinel does today. SoroSentinel does not try to replace it.

**What SoroSentinel adds:**
- **Evidence for every signal.**
  - Each Intel signal points to stored, public ledger evidence: the ledger, the observation and its `as_of` time.
  - The result comes from a published rule table, so the same evidence gives the same answer.
  - A directory tag records a conclusion. Intel records the observations behind one.
- **A signed snapshot that works offline.**
  - Guard checks counterparties against an Ed25519-signed snapshot inside the wallet, without sending the user's transaction or addresses anywhere.
  - See [Verifying a snapshot yourself](verifying-snapshots.html).
- **Effects, not only reputation.**
  - Guard reports what the transaction will do: balances that change, signers added, missing memos, open-ended time bounds.
  - These findings work on an account nobody has ever tagged.
- **Disputes and an audit trail** are built into the verdict model. Every change is appended to a log, and an automated source can never reach the highest level without a human.

**Where they meet:** importing third-party lists as attributed input is planned for Phase 3 (partner imports, [Intel #63](https://github.com/SoroSentinel/Sorosentinel-intel/issues/63)). Nothing is imported today.

## Assay

[Assay](https://github.com/use-assay/Assay) classifies what an asset's issuer **can** do from the issuer's authorization flags on the ledger: whether it can freeze or claw back holdings. Its README states that a registry contract on testnet answers `get_safety(asset)` for other contracts to call.

SoroSentinel plans a detector over the same flags ([Intel #47](https://github.com/SoroSentinel/Sorosentinel-intel/issues/47)) and is keeping its own. The two use the data differently:
- **Assay** is an on-chain gate that a contract consults at call time.
- **Intel** stores the flag change as evidence, feeds it into a reproducible verdict, and ships it in the snapshot Guard checks before a user signs.

The underlying ledger fact is the same, so the two should agree. If they don't, one of them has a bug worth reporting.

## Stellar Agent Guard

[Stellar Agent Guard](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-sdk) protects **AI agents** that hold their own funds.
- A custom account contract enforces spend caps, allowlists and a dead-man switch on-chain.
- Its SDK simulates each call before broadcast and returns `admissible`, `blocked` or `undetermined`.
- It is published on npm.

SoroSentinel Guard has a different user and a different role:
- **The user:** a person signing in a wallet.
- **It advises, it doesn't enforce:** it has no contract, holds no keys, and never blocks anything. The wallet decides what to show.
- **What it explains:** the effects of the exact bytes about to be signed, worst case first, for every operation type it knows. Anything it doesn't know is reported as `unanalyzable` rather than passed through.

Both projects share one rule: when the analysis cannot decide, it says so (`undetermined` there, `partial` or `unanalyzable` here).

## Contract scanners

| Project | Input | SoroSentinel Scan |
|---|---|---|
| [soroban-security-scanner](https://github.com/StellarFoundry/soroban-security-scanner) | Rust source, before deployment; JSON and SARIF | compiled WASM **already deployed**, so no source code is needed |
| [soroban-upgrade-safeguard](https://github.com/ShippedLabs/soroban-upgrade-safeguard) | two WASM builds, to catch breaking upgrades | one module at a time, for capability indicators |

Source scanners and pre-deployment audits help contract authors before release. Scan helps everyone else afterwards, by triaging contracts that are already on the network and feeding what it finds into Intel as evidence.

Scan reports indicators of what a module **can** do (replace its own code, create contracts, call other contracts). It never says a contract is fine, and every report lists what it did not check. See [What Scan reports](reference/scan-indicators.html).

## Transaction explainers

[Stellar-Explain](https://github.com/StellarCommons/Stellar-Explain) explains a transaction from its hash using Horizon. [stellar-xdr-lens](https://github.com/stellar-optics/stellar-xdr-lens) explains and diffs raw XDR, including failures.

Both are useful after the fact or while debugging. Guard works **before** a signature exists:
- It analyzes the envelope the wallet is about to sign, not one already on the ledger.
- It reads no history from Horizon. SoroSentinel uses Stellar RPC only.

## What we do not claim

- **We are not the only source of risk data.** For breadth of coverage, StellarExpert is ahead today.
- **We are not complete.** Guard derives effects for a fixed set of operation types and reports the rest as `unanalyzable`. Scan checks seven indicators.
- **We are not audited.** None of the three components has had an external security audit.
- **No signal is a judgement about a person or project.** Each one is an observation with a time, a method and the evidence behind it.
