# Changelog

All notable changes to this repository. Versions follow [Semantic Versioning](https://semver.org/); until 1.0, minor versions may change schemas additively and patch versions fix bugs.

## [Unreleased]

- Docs site: comparison with existing Stellar tools (StellarExpert, Assay, Stellar Agent Guard, contract scanners, transaction explainers).
- Protocol 30 upgrade script, staged until `go-stellar-sdk` v0.8.0 clears the 14-day dependency rule on 2026-11-03 (#37).
- Code of conduct and changelog.
- README and CONTRIBUTING: removed dead community links.

## [0.1.0] - 2026-11-01

First release. The Phase 1 exit test passed on testnet on 2026-10-28.

- Stellar RPC ingestion with checkpoints, gap detection and a per-network single-writer lock. Halts on unknown XDR and on protocols above 29.
- Detectors: asset look-alike codes and home-domain mismatch (SEP-1, via the isolated fetcher).
- Postgres evidence store; rule-table verdicts that are reproducible for the same evidence, `as_of` and ruleset.
- `ScanReport` ingestion as evidence (#50).
- `intel-worker` publishes an Ed25519-signed snapshot; `intel-api` serves read-only lookups.
- Shared schemas and canonical-key vectors used by Guard and Scan.
- Fail-closed wording renderer with a blocklist lint. All templates are drafts awaiting counsel review.
- Alert classification and on-call runbooks.
- `make demo`: the full testnet flow in Docker.

[Unreleased]: https://github.com/SoroSentinel/Sorosentinel-intel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SoroSentinel/Sorosentinel-intel/releases/tag/v0.1.0
