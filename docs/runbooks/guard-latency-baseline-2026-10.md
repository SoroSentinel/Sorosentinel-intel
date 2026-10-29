# Guard latency baseline: 2026-10-29

Run of the PRD §7 latency targets using Guard's `make bench` (Guard issue #47).
Guard PR #55 carries the harness; this page records the measured numbers, so a
later change can be compared against a dated baseline rather than against a
re-interpretation of the target.

**Result: both targets met on this machine.** The RPC figure is weak and should
be re-measured before it is treated as settled — see §4.

## 1. Setup

| Item | Value |
|---|---|
| Date | 2026-10-29 |
| Guard commit | `d70819e` (branch `feat/guard-latency-bench`, PR #55, base `main` at `3171b6a`) |
| `@stellar/stellar-sdk` | 17.2.1 |
| Runner | `darwin/arm64`, Apple M1 Pro, node v26.9.0 |
| Snapshot | `intel-schemas/snapshot_signing.json`, pinned at `v0.1.0-next.0` (`2412303`), network `public`, key id `test-key-1` |
| RPC endpoint | `https://soroban-testnet.stellar.org` (free SDF testnet, protocol 29) |
| Fixtures | all 41 under `fixtures/tx/`: 37 pubnet, 3 testnet, 1 other-network; 39 analyzable, 2 decoder-rejected |

Signing uses the vector's documented test key only. No seed is printed, logged
or committed, and no transaction XDR, hash or account address appears in the
benchmark output — only aggregate timings, fixture names and status counts.

## 2. Targets, as PRD §7 words them

| Claim | Target |
|---|---|
| `analyze` local-snapshot path | p95 < 100 ms |
| `analyze` end-to-end, including RPC simulation | p95 < 800 ms |

The harness reports a p95 as a result only from 20 samples up; below that it
prints `not measurable: n=…`.

## 3. Measurements

### 3.1 Local path — `make bench` (n=200 per fixture, 20 warmup)

| Aggregate | fixtures | n | p50 | p95 | max |
|---|---|---|---|---|---|
| snapshot-verified (the PRD claim) | 35 pubnet | 7000 | 1.046 ms | **1.416 ms** | 1.762 ms |
| all analyzable | 39 | 7800 | 1.046 ms | 1.416 ms | 1.762 ms |
| decoder-rejected input | 2 | 400 | 0.008 ms | 0.012 ms | 0.024 ms |

**p95 1.416 ms against a 100 ms target: met**, with enough headroom that the
figure is dominated by XDR decode and effect derivation rather than by the
snapshot lookup. `rejected_input_stays_unanalyzable` confirms the two hostile
decode fixtures stayed `unanalyzable` across 400 samples — a fast result is not
a pass unless the status is one the product can act on.

### 3.2 End-to-end with simulation — `make bench RPC=https://soroban-testnet.stellar.org` (n=30, 3 warmup)

| Aggregate | fixtures | n | p50 | p95 | max |
|---|---|---|---|---|---|
| contract invocation, simulated | 1 (testnet) | 30 | 240.3 ms | **453.6 ms** | 544.3 ms |
| local path in the same run | 35 | 1050 | 1.290 ms | 1.613 ms | 1.724 ms |

**p95 454 ms against an 800 ms target: met.** The RPC leg is ~320× the local
leg, so essentially the whole budget is the network round trip.

## 4. Known weaknesses in these numbers

Stated so nobody re-derives them from the raw output later.

1. **The RPC figure rests on one fixture and 30 samples.** `benign/invoke_contract`
   is the only committed fixture with a Soroban invocation. The max was 544 ms of
   an 800 ms budget, so the margin is network variance, not measured headroom.
   Re-run against the endpoint an integrator actually deploys, with more samples.
2. **The RPC leg ran without a verified snapshot.** That fixture is signed for
   testnet, and the pinned vector is signed for `public`, so the lookup returned
   `network_mismatch` and counterparty checks were skipped. The end-to-end number
   therefore excludes the lookup, while §3.1 measures the lookup without network
   I/O. The two have not been measured together. A testnet-signed vector would
   close this; it is a schema-vector change, so it needs approval (§10).
3. **Local numbers come from one machine class.** An M1 Pro is faster than the
   low-end hardware a mobile wallet runs on. The 70× headroom on a 100 ms target
   makes that unlikely to matter, but it is not measured.
4. **Aggregates take the worst per-case p95, not pooled samples.** A 39-fixture
   pool would hide the slowest fixture under the fast ones; an integrator ships
   the worst transaction a wallet is asked to sign. Per-fixture rows are in the
   JSON output (`make bench` with `--json`).

## 5. Reproducing

```sh
git checkout d70819e            # or the merged commit once PR #55 lands
make deps
make bench                      # local path, no network
make bench RPC=https://soroban-testnet.stellar.org   # egresses the envelope to that endpoint
make bench N=200 > bench.txt    # add RPC=… for both legs; --json for per-fixture rows
```

`make verify` covers the harness's own arithmetic (percentiles, aggregation, the
warmup/status accounting, and that the pinned snapshot actually verifies).

## 6. Related

- Guard issue #47, PR #55
- PRD §7 (latency targets), §9 (Phase 1 exit)
- [phase1-exit-test-results-2026-10.md](phase1-exit-test-results-2026-10.md) — the
  end-to-end flag-and-warn run this baseline complements
