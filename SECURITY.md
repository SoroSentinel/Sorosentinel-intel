# Security Policy

## Status

SoroSentinel Intel is pre-release and **has not been audited**. Do not rely on it to protect funds.

## Reporting a vulnerability

Please do not open a public issue, PR or discussion for a vulnerability.

Report privately through GitHub private vulnerability reporting:
<https://github.com/SoroSentinel/Sorosentinel-intel/security/advisories/new>
(or the repository's **Security** tab → **Report a vulnerability**). If you cannot use GitHub, email TODO-security-contact.

Include:

- A description of the issue and its impact
- Steps or an input that reproduces it (a minimal XDR, WASM or request)
- The commit or version you tested

## Disclosure process

We follow coordinated disclosure:

1. **Acknowledge** your report within 5 business days.
2. **Triage** within 10 business days: confirm the issue, assess severity, and tell you whether we accept it.
3. **Fix** in a private fork or advisory branch. We aim to release a fix within 90 days of the report; we will keep you updated at least every 14 days and tell you if we need longer.
4. **Disclose** by publishing a GitHub Security Advisory (with a CVE where applicable) once the fix is available, on a date agreed with you. We credit reporters who want to be credited.

Please give us reasonable time to fix the issue before disclosing it. If 90 days pass without a fix or an agreed extension, you may disclose.

Only the latest commit on `main` is supported; there are no maintained releases yet.

## Scope

In scope:

- Anything that makes SoroSentinel report a clean result for input it did not fully analyze
- Crashes, hangs or resource exhaustion from hostile input (XDR, WASM, `stellar.toml`, API requests)
- Ingestion of untrusted ledger data, the `stellar.toml` fetcher (SSRF), snapshot signing, the wording renderer.
- Leaks of private data or keys, or bypasses of the public-wording controls

Out of scope:

- Findings in third-party dependencies with no demonstrated impact on this project (report those upstream)
- Social engineering, physical attacks, and denial of service by volume against hosted infrastructure
- Disagreements with a signal about a specific asset or account: use the review process instead

## Safe harbor

Good-faith research that follows this policy, avoids privacy violations and service disruption, and does not touch other users' funds will not be pursued.
