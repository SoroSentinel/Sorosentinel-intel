# Runbook: Phase 1 exit test on testnet

ADR 0002 exit test: a look-alike asset issued on testnet is flagged by Intel,
appears in the signed snapshot, and Guard warns on a trustline to it.

Internal runbook. Uses testnet only, a throwaway signing key, and synthetic
accounts. Nothing here touches mainnet or a production key.

## 0. Before you start: Protocol 30

Intel pins `github.com/stellar/go-stellar-sdk` v0.7.3 (Protocol 28 XDR, checked
against live Protocol 29 ledgers). The testnet Protocol 30 upgrade vote is
**2026-11-03**. From that ledger on, `intel-worker` **halts by design** with
`xdrcompat: unsupported protocol version` and an `"alert":true` log line.

- Run this test **before 2026-11-03**, or
- after the XDR bump to v0.8.0 (allowed from 2026-11-03 under the 14-day
  dependency rule) has landed, following ARCHITECTURE §12.

Do not work around a halt by raising `xdrcompat.MaxProtocol`.

## 1. Prerequisites

- Go (version in `go.mod`), Docker (Colima is fine), `openssl`, `curl`.
- The Guard repo checked out next to this one, with `pnpm install` done
  (Node >= 22.12).
- Network access to `https://soroban-testnet.stellar.org` (Intel's default
  testnet RPC) and `https://friendbot.stellar.org`.

## 2. Database

```sh
docker run -d --rm --name intel-exit-test -e POSTGRES_USER=intel \
  -e POSTGRES_PASSWORD=intel-test-only -p 127.0.0.1:55434:5432 postgres:16
export INTEL_DATABASE_URL=postgres://intel:intel-test-only@127.0.0.1:55434/postgres
make migrate
```

## 3. Throwaway snapshot signing key

KMS signing is not wired yet; the worker reads a PEM PKCS#8 Ed25519 file that
must be mode 0600. Keep it **outside the repo** and delete it after the test.
Never commit it, paste it, or reuse it.

```sh
mkdir -p ~/intel-exit-test/snapshots && cd ~/intel-exit-test
openssl genpkey -algorithm ed25519 -out signing-key.pem
chmod 600 signing-key.pem
# Public key Guard pins: 32 raw bytes, hex. Public, safe to share.
openssl pkey -in signing-key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 64 > pubkey.hex
```

## 4. Reference set

The worker loads `config/reference-assets.testnet.json` (`code -> [issuers]`).
It lists testnet `USDC` with issuer
`GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5` (on 2026-10-28 its
testnet `home_domain` was `centre.io`) and `XLM` with no issuers, so any issued
asset coded `XLM` (or a confusable such as `X1M`) is a look-alike. Changes to
this file need review like any detector config.

## 5. Start the worker

Start it a few ledgers before you create the asset, so the trustline ledger is
ingested. Get the latest ledger, then start from it:

```sh
LATEST=$(curl -s -X POST https://soroban-testnet.stellar.org -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["sequence"])')

go run ./cmd/intel-worker -network testnet -start-ledger "$LATEST" \
  -snapshot-dir ~/intel-exit-test/snapshots \
  -signing-key-file ~/intel-exit-test/signing-key.pem \
  -signing-key-id exit-test-key \
  -snapshot-interval 30s
```

`-start-ledger` only applies to the first run; later runs resume from the
`ingest_checkpoint` row. One worker per network: a second one exits with
"a writer is already active". Logs are JSON; they never contain addresses, XDR
or key material. A line with `"alert":true` means it stopped and needs you.

The default snapshot interval is 5 minutes; 30s keeps the test short.

## 6. Issue a look-alike on testnet

Create a fresh issuer and holder, and have the holder open a trustline to
`USDC` from the new issuer (not the reference issuer). Optionally set a
`home_domain` on the issuer first to exercise D-HOMEDOMAIN-MISMATCH as well.

Example with the JS Stellar SDK from the Guard checkout (RPC only, no Horizon).
TODO(verify): this script has not been run as written; check it against the
installed `@stellar/stellar-sdk` before relying on it.

```js
// issue-lookalike.mjs; save it in the Guard checkout's packages/core/ (where
// @stellar/stellar-sdk is installed) and run there: node issue-lookalike.mjs
import { Asset, BASE_FEE, Keypair, Networks, Operation, TransactionBuilder, rpc } from "@stellar/stellar-sdk";

const server = new rpc.Server("https://soroban-testnet.stellar.org");
const issuer = Keypair.random();
const holder = Keypair.random();
for (const kp of [issuer, holder]) {
  const r = await fetch(`https://friendbot.stellar.org/?addr=${kp.publicKey()}`);
  if (!r.ok) throw new Error(`friendbot ${r.status}`);
}
async function submit(kp, op) {
  const account = await server.getAccount(kp.publicKey());
  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: Networks.TESTNET })
    .addOperation(op).setTimeout(60).build();
  tx.sign(kp);
  const sent = await server.sendTransaction(tx);
  const done = await server.pollTransaction(sent.hash);
  if (done.status !== "SUCCESS") throw new Error(`tx ${sent.hash}: ${done.status}`);
}
await submit(issuer, Operation.setOptions({ homeDomain: "example.com" })); // optional
await submit(holder, Operation.changeTrust({ asset: new Asset("USDC", issuer.publicKey()) }));
console.log(JSON.stringify({ issuer: issuer.publicKey(), holder: holder.publicKey() }));
```

Write down the issuer and holder addresses for steps 7 and 8. They are testnet
throwaways; do not put them in the repo.

## 7. Check Intel

Within a few ledgers the worker logs `ledger processed` with
`evidence_appended` >= 1 and `verdicts_changed` 1, and the next publish logs
`snapshot published` with `entries` >= 1.

```sh
psql "$INTEL_DATABASE_URL" -c "SELECT e.key, v.level, v.rule_id, v.as_of
  FROM verdict v JOIN entity e ON e.id = v.entity_id WHERE e.network = 'testnet'"
cat ~/intel-exit-test/snapshots/snapshot-testnet-latest.json
```

The asset's snapshot entry is the first 16 bytes of
`SHA-256("testnet|asset|USDC:<issuer>")` in hex (schemas/canonical-key.md):

```sh
printf 'testnet|asset|USDC:%s' "$ISSUER" | shasum -a 256 | cut -c1-32
```

That value must be in `entries`.

## 8. Run Guard against the snapshot

Build an unsigned change-trust transaction from the holder to the look-alike,
then analyze it with the snapshot and the pinned public key. Guard never needs
the private key. Guard's source is run through vitest (it uses TypeScript
syntax that Node's type stripping does not accept), so the check is a
throwaway test file. Save it as `packages/core/exit-check.test.ts` in the
Guard checkout and do not commit it.

```ts
// exit-check.test.ts. Run from the Guard checkout's packages/core/:
//   ISSUER=<issuer> HOLDER=<holder> EXPECT=flagged pnpm exec vitest run exit-check.test.ts
// Control (reference issuer, must not be flagged):
//   ISSUER=GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5 HOLDER=<holder> EXPECT=clear pnpm exec vitest run exit-check.test.ts
import { readFileSync } from "node:fs";
import { Account, Asset, BASE_FEE, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { expect, test } from "vitest";
import { analyze } from "./src/index.ts";

const dir = `${process.env.HOME}/intel-exit-test`;

test("Phase 1 exit test", () => {
  const { ISSUER, HOLDER, EXPECT } = process.env;
  const tx = new TransactionBuilder(new Account(HOLDER!, "1"), { fee: BASE_FEE, networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.changeTrust({ asset: new Asset("USDC", ISSUER!) }))
    .setTimeout(300).build();
  const result = analyze(tx.toEnvelope().toXDR("base64"), {
    networkPassphrase: Networks.TESTNET,
    asOf: new Date(),
    snapshot: {
      data: JSON.parse(readFileSync(`${dir}/snapshots/snapshot-testnet-latest.json`, "utf8")),
      pinnedKeys: { "exit-test-key": Buffer.from(readFileSync(`${dir}/pubkey.hex`, "utf8").trim(), "hex") },
    },
  });
  // Amounts are bigint (stroops), which JSON.stringify does not handle.
  console.log(JSON.stringify(result, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
  expect(result.snapshotStatus).toBe("verified");
  const codes = result.findings.map((f) => f.code);
  if (EXPECT === "flagged") {
    expect(result.status).toBe("findings_present");
    expect(codes).toContain("G-TRUST-FLAGGED");
  } else {
    expect(codes).not.toContain("G-TRUST-FLAGGED");
  }
});
```

Pass criteria:

- Both runs pass. `snapshotStatus` is `verified` (anything else: check the
  key id, the pubkey file, the network, and that the snapshot is younger than
  Guard's max age).
- The look-alike run has status `findings_present` with `G-TRUST-FLAGGED`.
- The control run with the reference issuer has no `G-TRUST-FLAGGED`.

Record the date, worker commit, snapshot version and Guard output in the
Phase 1 exit-test issue.

## 9. Clean up

```sh
docker stop intel-exit-test
rm -rf ~/intel-exit-test   # removes the throwaway signing key
```

## Troubleshooting

| Symptom | Meaning / action |
|---|---|
| `ledger gap`, `next ledger ... older than the source's oldest` | The checkpoint fell out of RPC retention (~7 days). Use a fresh database and a recent `-start-ledger`. |
| `unsupported protocol version` | Protocol 30 reached testnet; see §0. |
| `a writer is already active` | Another worker holds the network's lock. Stop it first. |
| `signing key file must not be readable by group or others` | `chmod 600` the key file. |
| `snapshot publish failed` | Logged and retried each interval; Guard will show stale data if it persists. |
| Look-alike not flagged | Check the asset code/issuer against `config/reference-assets.testnet.json`, and that the trustline ledger is at or after `-start-ledger`. |
