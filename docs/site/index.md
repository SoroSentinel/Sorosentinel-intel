---
title: Home
---

# SoroSentinel

Security tooling for the Stellar ecosystem. It **advises**: it never controls the network, never touches a private key, and never signs anything for you.

Stellar's classic layer has no arbitrary code, so the interesting risks are narrower than "malware": a contract that can replace its own code, a transaction that quietly adds a signer, an asset with a familiar code issued by somebody else, a domain that no longer says what the issuer says it says. SoroSentinel looks at those and describes what it observed.

## The three repos, and the one flow

| Repo | Language | Role |
|---|---|---|
| [sorosentinel-guard](https://github.com/SoroSentinel/Sorosentinel-guard) | TypeScript | Checks a transaction **before you sign it**. SDK or middleware, called by a wallet. |
| [sorosentinel-intel](https://github.com/SoroSentinel/Sorosentinel-intel) | Go | Evidence and verdicts. Reads ledgers over Soroban RPC, stores write-once evidence, publishes a signed snapshot and a read API. Owns the shared schemas. |
| [sorosentinel-scan](https://github.com/SoroSentinel/Sorosentinel-scan) | Rust | Reads deployed contract bytecode in a sandbox with no network access. Library and CLI. |

Data flows one way: **Scan → evidence → Intel → signed snapshot → Guard.** The repos never import each other's internals; they talk through versioned schemas that Intel owns.

- [What Guard reports](reference/guard-findings.html) — the eight finding codes it can raise today.
- [What Scan reports](reference/scan-indicators.html) — seven indicators, six things it does not examine, and the caps it enforces.
- [What Intel publishes](reference/intel-signals.html) — the four public signal names and what each one does *not* mean.
- [Verifying a snapshot yourself](verifying-snapshots.html) — you do not have to trust the publisher.
- [Project status](status.html) — what runs, what is gated, and what is not finished.

## Three rules that shape the whole design

**Absence of a result is never reassurance.** If analysis fails, times out, or meets an operation type it does not know, the answer is `partial` or `unanalyzable`. A tool that returns "clean" when it crashed is worse than no tool, because the wallet user cannot tell the difference.

**No verdict without stored evidence.** Every signal points at the rows that produced it, with the time it was checked and the ruleset version. Verdicts are a reproducible rule table over `(evidence, as_of, ruleset_version)` — not a numeric score, and never a guess.

**Public text is fixed and reviewed.** Statements come only from a small registry of templates, filled with observed values. If a statement cannot be rendered exactly, the system returns structured data with no prose. That is why the wording registry is gated on legal review rather than shipped when convenient: a sentence that overstates what the evidence supports is a defect of the same class as a parser bug.

## What this project is not

It is not an endpoint antivirus, not a smart-contract source auditor, and not a scoring service. It does not assert that anything is safe, and it does not draw conclusions about the character, intent or identity of an account, asset or contract — only what a transaction would do, and what was observed on the ledger as of a stated time.

The full design documents are in the repository: [`PRD.md`](https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/PRD.md), [`ARCHITECTURE.md`](https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/ARCHITECTURE.md), and the [architecture decision records](https://github.com/SoroSentinel/Sorosentinel-intel/tree/main/docs/adr). The invariants above are enforced by [`AGENTS.md`](https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/AGENTS.md) and by CI.
