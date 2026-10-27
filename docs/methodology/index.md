<!--
DRAFT for counsel review. Not published. Do not merge without counsel approval
(AGENTS.md §5, project_structure §2.5). Every public statement will link here.
Placeholders: TODO-review-contact, TODO-review-url.
-->

# How SoroSentinel signals work

SoroSentinel reports **observations** about Stellar accounts, assets, contracts
and domains, and about what a transaction would do if signed. Every
observation states when it was made, how, and from which data. A signal is an
indicator, not a determination of intent or wrongdoing.

SoroSentinel never reports anything as "safe". When nothing is found, it says
that no signals were observed and lists what was not checked.

## Signal levels

| Signal | What it means | What it does not mean |
|---|---|---|
| `consistent` | The entity matches information it publishes about itself, for example an issuer's `stellar.toml` lists the asset. | It does not verify identity or trustworthiness. Anyone who controls a domain can publish matching data. |
| `no_signals` | No risk signals were observed as of the stated time. | It is not an assurance. It can also mean we have little or no data. |
| `caution` | One or more observed signals are worth checking. Each is listed with its facts. | It is not a finding that anyone acted wrongly. |
| `high_caution` | Several independent signals were observed, and an analyst reviewed them on the stated date. | It is still an indicator, not a determination of intent or wrongdoing. |

Automated checks alone can produce at most `caution`. `high_caution` always
involves a human review.

## What every statement includes

- **Observed at** (`as_of`): the time the underlying data was checked.
- **Method**: the check that produced it, and the ruleset version.
- **Facts**: the specific values observed, for example an asset code, an issuer
  account and a ledger number.
- **Links**: this page, and a link to request a review.

Statements come only from fixed, reviewed templates filled with these facts.
If a statement cannot be produced exactly, only the facts are shown.

## What we check

These are the v1 checks. Each is marked live here when it ships; until then it produces no signals.

| Check | Based on | Status |
|---|---|---|
| Asset code look-alikes | An asset uses the same or a confusable code (for example `0`/`O`, `I`/`l`/`1`) as a known asset, from a different issuer. Codes legitimately used by several issuers are listed and not flagged. | Planned |
| Home-domain consistency | Whether the issuer's `home_domain` publishes a `stellar.toml` that lists the asset, re-checked over time. | Planned |
| Issuer and trustline flags | Clawback, revocable and authorization-required flags. Reported as information, not as a risk on their own. | Planned |
| Account-control patterns | Observed sequences that remove an account's signer and add another, followed by funds leaving. | Planned |
| Contract bytecode indicators | Capabilities present in deployed contract code, such as the ability to replace its own code. Reported as information; they do not raise a level on their own. | Planned |

## What a transaction check (Guard) reports

Before you sign, Guard describes what the transaction would do to each affected
account: balances that can change (the largest possible amount first), signers
or thresholds that change, trustlines added, and contract authorizations
granted. It reports one of:

| Status | Meaning |
|---|---|
| `findings_present` | At least one item needs your attention. All items are listed, most severe first. |
| `no_issues_found` | No items were found. A list of what was not checked is always shown. |
| `partial` | Some parts could not be analyzed, for example simulation was unavailable or the network is not covered. |
| `unanalyzable` | The transaction could not be analyzed. Do not treat this as a clean result. |

Guard analyzes exactly the bytes you are asked to sign and shows that
transaction's hash. Behavior at execution time can differ if a contract's code
or state changes after the check.

## Data sources

- Stellar ledger data via Stellar RPC (recent) and archived ledger history.
- Each issuer's published `stellar.toml`, fetched and stored with its hash and
  fetch time, so every published fact can be shown as it was on that date.
- Deployed contract bytecode, identified by its SHA-256 hash.

## Requesting a review

If you control an account, asset, contract or domain and believe a signal is
wrong, request a review at TODO-review-url or TODO-review-contact.

- We aim to acknowledge requests within 72 hours.
- To show control of a domain or issuer, we ask you to publish a challenge value
  in your `stellar.toml`. We do not ask for identity documents.
- Signals are re-evaluated against the evidence. If a signal is withdrawn, the
  change appears in the next published snapshot and the history is kept.

## Limits

- Checks are rule-based and use public data. New patterns may not be detected
  until a rule exists for them.
- Snapshots are published every few minutes, so a very recent change may not
  appear yet.
- Absence of data is not evidence of anything. Networks and entities we do not
  cover are reported as not checked.
