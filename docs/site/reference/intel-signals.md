---
title: What Intel publishes
---

# Intel signals and verdicts

Intel observes the ledger and publishes what it saw. It publishes **four** signal names, and it publishes nothing about intent.

## The four public signal names

| Signal | What it means | What it does **not** mean |
|---|---|---|
| `consistent` | The entity matches information it publishes about itself — for example an issuer's `stellar.toml` lists the asset. | Not identity, not trustworthiness. Anyone who controls a domain can publish data that matches. It can also decay: a `consistent` result was true at its `as_of`. |
| `no_signals` | No risk signals were observed as of the stated time. | Not an assurance. It can equally mean little or no data exists. |
| `caution` | One or more observed signals are worth checking, each listed with its facts. | Not a finding that anyone acted wrongly. |
| `high_caution` | Several independent signals were observed **and a human analyst reviewed them** on the stated date. | Still an indicator, not a determination of intent or wrongdoing. |

Automated checks alone can produce at most `caution`. Reaching `high_caution` requires a human review, and the tool that would record one does not exist yet, so today `high_caution` is unreachable through the product. The internal-to-public mapping is a single function (`internal/signal`), and an unrecognized internal level is an error rather than a default to a reassuring name. Internal working labels never appear in an API response, a snapshot or a lookup page.

## What every published statement carries

- **`as_of`** — the time the underlying data was checked. Verdict logic never reads the wall clock; `as_of` is an input and is stored.
- **Method** — which check produced it, and the ruleset version.
- **Facts** — the observed values: an asset code, an issuer account, a ledger number.
- **Attribution** — that this is an indicator, not a determination — plus links to the methodology page and to a review request.

Text comes only from a small registry of reviewed templates filled with those facts. The renderer **fails closed**: if a template or a slot is missing, the response contains structured data and no sentences. A blocklist lint runs in CI over the registry, because a sentence that overstates the evidence is a defect of the same class as a parser bug.

## What is live, and what is planned

Two ledger detectors exist today:

| Detector | What it observes |
|---|---|
| `D-ASSET-LOOKALIKE` | An asset using the same or a confusable code (`0`/`O`, `I`/`l`/`1`) as a known asset, from a different issuer. Codes that legitimately have several issuers are listed and not flagged. |
| `D-HOMEDOMAIN-MISMATCH` | Whether an issuer's `home_domain` publishes a `stellar.toml` that lists the asset, re-checked over time. |

Other detector identifiers are declared in the evidence vocabulary and reasoned about by the verdict rule table before their producers exist. An identifier with no producer produces no signals — which is the correct failure mode, since inventing a signal would be worse than not having one. Issuer and trustline flags, account-control patterns and community reports are on the roadmap and are listed as such in the tracker.

## Reproducibility

A verdict is a rule table over `(evidence, as_of, ruleset_version)` — not a numeric score. The same inputs must produce the same output, and every status change appends to an event log. Replay tests reproduce the stored verdicts; a verdict that cannot be recomputed from stored evidence is a bug.

Source: [`internal/detectors/`](https://github.com/SoroSentinel/Sorosentinel-intel/tree/main/internal/detectors), [`internal/verdict/`](https://github.com/SoroSentinel/Sorosentinel-intel/tree/main/internal/verdict), [`internal/signal/`](https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/internal/signal/signal.go) and [`wording/`](https://github.com/SoroSentinel/Sorosentinel-intel/tree/main/wording) in `sorosentinel-intel`.
