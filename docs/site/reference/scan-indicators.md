# Scan indicators

Every indicator `scan-core` can emit, with what triggers it. Source of truth:
`crates/scan-core/src/detectors.rs`. The ruleset version in force is
`RULESET_VERSION` in `crates/scan-core/src/lib.rs` (currently `2026.10.3`) and is
carried in every report.

**Indicators describe bytecode, not intent.** Six of the seven are
informational, and an informational indicator never raises a signal level on its
own. A report is a set of facts about one WASM module at one point in time.

## The indicators

| Code | Informational | Fires when | Facts carried |
|---|---|---|---|
| `S-KNOWN-BAD-HASH` | **no** | the module's SHA-256 appears in the `--known-bad-hashes` list supplied to the CLI | none |
| `S-UPGRADEABLE` | yes | the module imports `update_current_contract_wasm` | none |
| `S-CREATES-CONTRACTS` | yes | it imports `create_contract` or `create_contract_with_constructor` | none |
| `S-CROSS-CALL` | yes | it imports `call` or `try_call` | none |
| `S-NO-SPEC` | yes | the module has no contract-spec custom section | none |
| `S-OLD-SDK` | yes | its own `contractenvmetav0` claim is a protocol version below `OLD_PROTOCOL_FLOOR` (21) | `claimed_protocol_version`, `claimed_pre_release` |
| `S-SEP41-DEVIATION` | yes | the module's own spec declares **at least 3 of the 10** SEP-41 function names — enough to read as a token claim — and the signatures it declares then differ from the interface, or names are missing | declared and required counts, the required name list, missing and deviating names (deviation list capped at 3, count always complete) |

`S-KNOWN-BAD-HASH` is the only level-raising indicator, and it is only as good as
the hash list handed to it: nothing is fetched, and no list ships with the crate.

The absence of `S-SEP41-DEVIATION` is not conformance. A module that declares
nothing token-like is never compared at all, so `NC-SEP41-CONFORMANCE` stays in
`not_checked` whether or not the indicator fired.

## Claims are treated as claims

The WASM spec and `contractenvmetav0` sections are written by the contract's own
author and are not checked by the network. Scan reads them as untrusted claims:

- An unreadable, truncated, oversized or unknown-arm env-meta entry is reported
  as *no claim*, never guessed into a value.
- Two `contractenvmetav0` sections that assert different protocols cancel each
  other out; Scan does not pick one.
- `S-OLD-SDK` therefore only fires when the module makes exactly one readable
  claim.

## Never checked

`not_checked` is a fixed list of six codes emitted on every report. Absence of a
finding is not evidence of anything; these are the things a report says it did
not look at:

| Code | What was not examined |
|---|---|
| `NC-AUTH-CHECKS` | whether authorization is required, or sufficient, for any call |
| `NC-RUNTIME-BEHAVIOR` | what the contract does at runtime; nothing is executed |
| `NC-SDK-VERSION` | the SDK version actually used to build it (only the module's own claim is read) |
| `NC-SEP41-CONFORMANCE` | whether a SEP-41 contract conforms; `S-SEP41-DEVIATION` names a gap between its own spec and the baseline, which is not the same check |
| `NC-SOURCE-CODE` | any source code; analysis is on deployed bytes only |
| `NC-UPGRADE-AUTHORITY` | who can call an upgrade path, or whether one has been used |

## Parsing limits

`crates/scan-core/src/limits.rs` bounds every parse path. A module that exceeds a
limit is a `limit_exceeded` error, not a partial report — over-large input is
never quietly trimmed into a result.

| Limit | Value |
|---|---|
| `MAX_MODULE_BYTES` | 1 MiB |
| `MAX_PAYLOADS` | 256 |
| `MAX_CUSTOM_SECTIONS` | 32 |
| `MAX_ENV_META_SECTIONS` / `MAX_SPEC_SECTIONS` | 2 each |
| `MAX_IMPORTS`, `MAX_EXPORTS` | 4096 each |
| `MAX_NAME_BYTES` | 256 |
| `MAX_KNOWN_BAD_HASHES` | 1,000,000 |
| `MAX_ENV_META_BYTES` | 128 |
| `MAX_SPEC_BYTES` | 64 KiB |
| `MAX_SPEC_ENTRIES` | 512 |
| `MAX_SPEC_DEPTH` | 8 |
| `MAX_SPEC_STRINGS` | 20,000 |

**Which of these are measured and which are chosen.** The four `MAX_SPEC_*` caps
are the only ones derived from a sample: **61 distinct contract modules across
6,000 testnet ledgers** (measured 2026-10-29 — largest spec body 28,056 bytes,
peak 117 entries, depth 3). The env-meta entry shape and the `OLD_PROTOCOL_FLOOR`
choice come from a separate sample of **73 distinct modules across 3,000 testnet
ledgers** (2026-10-28), where every entry was exactly 12 bytes with kind 0 and
`protocol` ranged 21 to 29. Every other cap above is a chosen safety limit, not a
measurement, and `MAX_MODULE_BYTES` carries a `TODO(verify)` against the network's
own maximum contract size, which the module header says must be checked before
that cap is trusted.

## Running it

The crate is a library and a one-shot CLI. It is not a server, has no job table,
and makes no callbacks.

```
sorosentinel-scan <file.wasm | -> [--known-bad-hashes <file>] [--format json|sarif]
```

- Output is deterministic: the same bytes, the same hash list, the same
  `RULESET_VERSION` produce the same report. Indicators are sorted by code.
- On failure the CLI prints `{"error":"<code>"}` on stderr and exits 1. The
  stable codes are `too_large`, `invalid_wasm`, `not_core_module`,
  `limit_exceeded`, `bad_hash_list`. Intel maps any of them to `unanalyzable`;
  a failed scan never becomes a clean result.
- `--format sarif` emits SARIF 2.1.0 for CI. No Scan result is a determination,
  so the log claims no severity: every result is `level: none`, and informational
  indicators additionally carry `kind: informational`.
- `make sandbox` builds the image Intel runs: a static musl binary on a `scratch`
  base, no shell, no package manager, no network tools, uid 65534.
- `sandbox/run.sh` is the isolation Intel is meant to launch it with, and it is
  readable rather than assumed: `--network none`, `--read-only`, `--cap-drop ALL`,
  `no-new-privileges`, a syscall allowlist (`sandbox/seccomp.json`), `--memory
  256m` with swap equal, `--pids-limit 16`, and the container killed after
  `SCAN_TIMEOUT` (default 30 s). Contract code is never executed, in this or
  anywhere else.

## Status

`scan-core` and `scan-cli` are `publish = false` at version `0.0.0` in
`Cargo.toml`. Nothing is published to crates.io, and no crate name in this repo
has been reserved. The `ScanReport` schema that output is validated against is
owned by Intel (`schemas/jsonschema/`), and this repo pins it rather than
defining its own.
