### `sorosentinel-guard` (TypeScript)

- **Is:** an SDK/middleware called before signing: `analyze(xdr, ctx)`. Not a server.
- **Commands:** check everything `make verify` (strict typecheck, tests, fixtures up to date) · test `make test` · lint/typecheck `make lint` · regenerate fixtures `make gen` (never edit `fixtures/` by hand) · replay experiment E2 `make replay FILE=<txs.jsonl>` · build: none (no build step yet).
- **Rules:**
  - Strict TypeScript; no `any`. Use `switch` with an exhaustive `never` check over operation and credential types so new protocol variants fail at compile time.
  - v1 derives effects for ~7 operations (payment, path payments, create account, change trust, set options, account merge, contract invoke). Everything else: decode + `unanalyzable` with a generic summary.
  - Effects carry `account`, `asset`, `delta_min`, `delta_max`, and `assurance` (`ledger | contract_reported`). Never present event-derived values as ledger truth. Show the worst case first ("up to X").
  - Per-operation source accounts and fee-bump inner/outer must be handled; effects are per affected account from the signer's perspective.
  - Findings are severity-ordered and **never truncated**; always show the operation count and the transaction hash.
  - Local snapshot lookup first; API fallback only when needed. No telemetry by default. Network calls are limited to the configured RPC endpoint and Intel.
  - Verify snapshot signatures client-side; refuse snapshots older than the max age and show a "protection data stale" state.
  - One fixture per operation/credential type, plus hostile fixtures (padding, hash(x) signers, no time bounds, memo-required destination, unknown network).
  - Use the official JS Stellar SDK for XDR; don't hand-roll XDR parsing.
