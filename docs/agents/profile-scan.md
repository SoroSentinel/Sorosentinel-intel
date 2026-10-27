### `sorosentinel-scan` (Rust)

- **Is:** a library + CLI. Intel runs it as a one-shot sandboxed container job. **No server, no job table, no callbacks.**
- **Commands:** check everything `make verify` (rustfmt check, clippy `-D warnings`, tests) · test `make test` · lint/clippy `make lint` · build `cargo build --locked` · sandbox image `make sandbox` · fuzz `make fuzz` (each target for `FUZZ_SECONDS`, default 60; needs `nightly-2026-10-01` and cargo-fuzz 0.13.2, see README).
- **Rules:**
  - Output is JSON conforming to the pinned `ScanReport` schema from `sorosentinel-intel`; include `wasm_sha256`, `ruleset_version`, `indicators[]`, `not_checked[]`.
  - Output is deterministic for the same input and `ruleset_version`.
  - Treat the WASM spec/meta custom sections as **untrusted claims** (they can be absent or wrong).
  - Informational indicators (upgradeable, cross-call, creates contracts, old SDK) **never raise a level alone**.
  - Prefer `#![forbid(unsafe_code)]` unless a human approves an exception. Enforce module-size and section-count caps.
  - Every parser path has a fuzz target. Indicators come with a labeled-corpus test.
  - Never claim a contract is "safe"; always include what was not checked.
