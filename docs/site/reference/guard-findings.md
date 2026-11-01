---
title: What Guard reports
---

# Guard finding codes

Guard is called by a wallet **before** you sign. It decodes exactly the bytes that will be hashed for signature, derives the effect on each affected account from your point of view, and lists findings most severe first. It never truncates the list, and it always shows the operation count and the transaction hash.

## The eight codes that exist today

| Code | What it means |
|---|---|
| `G-ACCOUNT-CONTROL` | A `SetOptions` operation changes who can authorize the account: master weight, thresholds, or removing a signer. Signers being *added* are reported as `G-SIGNER-ADDED`, so one change is not counted twice. |
| `G-SIGNER-ADDED` | A signer is added or its weight changes. A `hash(x)` or pre-authorized-transaction signer ranks highest, because it has no visible owner key: anyone holding the preimage, or that exact transaction, can use it. |
| `G-NO-EXPIRY` | The transaction has no upper time bound (`ledger` `max` of 0, or none), so a signed copy stays valid until your sequence number is used. A bound more than seven days past the check time counts as no expiry. |
| `G-MEMO-REQUIRED` | The transaction carries no memo and an operation sends to an account whose SEP-29 data entry requires one. One finding per operation. |
| `G-TRUST-FLAGGED` | An asset in the transaction appears in Intel's verified snapshot. |
| `G-DEST-FLAGGED` | A destination account — or a contract that only holds a balance — appears in the verified snapshot. |
| `G-CONTRACT-FLAGGED` | A contract being invoked, or a non-native token being moved, appears in the verified snapshot. |
| `G-NETWORK-UNKNOWN` | The network passphrase has no Intel coverage. Absence of data is not safety, so a result containing this can be at best `partial`. |

The three `*-FLAGGED` codes read the snapshot, which does not say which level an entity reached. Severity is therefore high, and the facts name the entity and every role it plays in the transaction.

## Result statuses

| Status | Meaning |
|---|---|
| `findings_present` | At least one item needs attention. All of them are listed. |
| `no_issues_found` | Nothing was found. A list of what was **not** checked always accompanies this. |
| `partial` | Some parts could not be analyzed — simulation unavailable, network not covered, snapshot stale. |
| `unanalyzable` | The transaction could not be analyzed. This is never a clean result. |

There is no `safe` status and there never will be one.

## What is not checked

Guard reports these codes whenever the corresponding data was unavailable, so that "nothing found" always carries its own limits:

`NC-DECODE` · `NC-OPERATION-EFFECTS` · `NC-SIMULATION` · `NC-COUNTERPARTY-SIGNALS` · `NC-MEMO-REQUIRED` · `NC-NETWORK-COVERAGE` · `NC-EXECUTION-TIME`

The last one is the honest caveat on everything Soroban-related: Guard analyzes what is signed, and behavior at execution time can differ if a contract's code or state changes after the check.

## What a finding contains

`code`, `severity`, `operationIndex`, and `facts` — the observed values as strings. User-facing sentences come only from Intel's reviewed template registry, so a finding without an approved template ships with its facts and no prose. That is deliberate: the wording is gated on legal review, not on convenience.

Source: [`packages/core/src/rules/`](https://github.com/SoroSentinel/Sorosentinel-guard/tree/main/packages/core/src/rules) in `sorosentinel-guard`.
