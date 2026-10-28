# Runbook: local testnet demo

One command runs SoroSentinel end to end on **testnet** on a laptop: Intel's
worker and read API in Docker, a look-alike asset issued with throwaway
accounts, and Guard analyzing a trustline to it. It is for development and for
recording a demo; it is not a deployment (no cloud provider is chosen yet).

Testnet only. The worker is fixed to testnet, and the script and the issuing
tool both refuse an RPC endpoint that does not report the testnet passphrase.
The snapshot signing key is a **throwaway test key** generated inside the stack
at startup; production keys live in KMS.

## 0. Before you start: Protocol 30

Intel pins `github.com/stellar/go-stellar-sdk` v0.7.3. The testnet Protocol 30
upgrade is on **2026-11-03**. From that ledger on, `intel-worker` halts by
design (`xdrcompat: unsupported protocol version`, `"alert":true`) and the demo
fails at step 4 with "intel-worker stopped". The demo works again once Intel's
XDR pin is bumped following ARCHITECTURE §12. Do not work around it by raising
`xdrcompat.MaxProtocol`.

## 1. Prerequisites

- Docker with Compose (`docker compose` or `docker-compose`). Colima is fine;
  the script runs `colima start` if Docker is not running. No buildx needed.
- Node 23.6 or newer (Guard's example runs through Node's type stripping),
  `curl`, `openssl`, `shasum`.
- The Guard repo checked out next to this one (`../Sorosentinel-guard`, or set
  `GUARD_REPO`) with `pnpm install` done and `examples/analyze-transaction/`
  present.
- Network access to `https://soroban-testnet.stellar.org`,
  `https://friendbot.stellar.org` and Docker Hub (first build only).

No Go toolchain is needed on the host: everything Intel runs is built in the
images.

## 2. The one command

```sh
make demo
```

It takes about 3-6 minutes after the first image build (the first build
downloads Go modules and can take longer). Every container and volume it
started is removed when it exits, on success, failure or Ctrl-C. To keep the
stack running afterwards (to poke at the API), run
`DEMO_KEEP_STACK=1 make demo`, then
`docker-compose -f deploy/docker-compose.yml down -v` when done.

Other knobs (environment): `GUARD_REPO`, `INTEL_API_PORT` (default 18080, bound
to 127.0.0.1), `INTEL_RPC_URL` (a testnet endpoint), `INTEL_SNAPSHOT_INTERVAL`
(default 30s), `DEMO_SNAPSHOT_TIMEOUT` (seconds, default 420).

## 3. What each step shows (demo script)

| Step | On screen | What to say |
|---|---|---|
| 1/7 Prerequisites | "RPC ... is testnet" | Everything runs on Stellar testnet. |
| 2/7 Stack | service states; `TEST-ONLY snapshot signing key generated; public key …` | Intel runs locally: Postgres, a one-shot migration, the worker ingesting testnet ledgers over Stellar RPC (no Horizon), and the read API. The snapshot key is a throwaway generated for this run. |
| 3/7 Look-alike | issuer, holder, signer addresses; trustline ledger | We create a new asset coded `USDC` from a fresh issuer (not the reference USDC issuer) and give it a `home_domain`. A holder opens a trustline to it on-chain, which is what Intel ingests. |
| 4/7 Snapshot | dots, then `snapshot version N, … entries, key_id demo-test-key` | The worker sees the trustline, the look-alike and home-domain detectors store evidence, the verdict is recomputed, and the next signed snapshot carries the asset's 16-byte hashed key. |
| 5/7 Read API | JSON for `GET /v1/entities/asset/USDC:<issuer>` | The public signal (`caution` / `high_caution` / `no_signals` / `consistent`), `as_of`, `ruleset_version` and the verifiable facts behind it (the reference asset it resembles, the issuer's `home_domain`). `statements` holds rendered text only for approved templates; when none renders, the API fails closed and returns facts without prose (on 2026-10-28 it was `[]`). Internal levels never leave Intel. |
| 6/7 Guard | `status: findings_present`, `snapshot: verified`, `G-TRUST-FLAGGED` | A wallet calls Guard before signing. Guard verifies the snapshot against the pinned public key, offline, and flags the trustline. The transaction is unsigned; Guard never sees a private key and sends nothing anywhere. |
| 7/7 Control | no `G-TRUST-FLAGGED` | The same transaction to the reference USDC issuer is not flagged. Its status is not "safe" either: Guard never says that. |
| Summary | one block | Recap of the above. |

The addresses printed are throwaway testnet accounts; no secret key is ever
printed or written outside the containers.

## 4. What runs where

| Piece | Source | Notes |
|---|---|---|
| `postgres` | `postgres:16.14-alpine` (pinned by digest) | Internal network only; random password per run. |
| `migrate` | `deploy/docker/Dockerfile.intel-worker` (`/app/migrate`) | Forward-only migrations, one shot. |
| `keygen` | `deploy/docker/Dockerfile.demo-tools` (`/app/gen-test-key`) | TEST ONLY: writes `signing-key.pem` (0600) and `pubkey.hex` into the `keys` volume. |
| `intel-worker` | `deploy/docker/Dockerfile.intel-worker` | `-network=testnet`, starts at the latest ledger, snapshots every 30s into the `snapshots` volume. Does not restart on a halt. |
| `intel-api` | `deploy/docker/Dockerfile.intel-api` | Reads the `snapshots` volume read-only; published on `127.0.0.1:18080`. |
| `demo-tools` | `deploy/docker/Dockerfile.demo-tools` (`/app/issue-lookalike`) | TEST ONLY: Friendbot accounts, issuance, unsigned transactions for Guard. |
| Guard | `$GUARD_REPO/examples/analyze-transaction/analyze.mts` | Runs on the host with the snapshot and pinned key. |

All Intel images are static Go binaries on `scratch`, running as uid 65532.
Configuration is environment variables only (header of
`deploy/docker-compose.yml`).

## 5. Troubleshooting

| Symptom | Meaning / action |
|---|---|
| `Docker is not running and Colima is not installed` | Start Docker Desktop or install Colima. |
| `building … failed`, `TLS handshake timeout` | Docker Hub or the Go module proxy is flaky; rerun. Builds are cached after the first success. |
| `… is not a testnet RPC endpoint` | `INTEL_RPC_URL` points somewhere else. Unset it. |
| `read API did not come up` | `docker-compose -f deploy/docker-compose.yml logs migrate intel-api`. Port 18080 taken: set `INTEL_API_PORT`. |
| `issue-lookalike: friendbot status 429` or `unreachable` | Friendbot rate limit or outage; wait and rerun. |
| `intel-worker stopped` | Read the printed worker log lines. `unsupported protocol version`: Protocol 30 reached testnet (§0). `ledger gap`: RPC lost the start ledger; rerun (each run starts from the latest ledger). |
| `no snapshot with the entry after 420s` | RPC was slow or the worker fell behind; rerun, or raise `DEMO_SNAPSHOT_TIMEOUT`. |
| `snapshot:` other than `verified` in Guard output | The demo checks this and fails. `stale`: the clock skew between host and snapshot exceeds Guard's max age. `bad_signature`/`unknown_key`: the key was regenerated; rerun from scratch. |
| `Node 23.6 or newer is required` | Upgrade Node. |
| `run 'pnpm install' in …` | Install Guard's dependencies (`pnpm install` in the Guard checkout). |
| Leftover containers after a hard kill | `docker-compose -f deploy/docker-compose.yml --profile tools down -v --remove-orphans`. |
