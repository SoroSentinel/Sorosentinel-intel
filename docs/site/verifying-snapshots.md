# Verifying snapshots

A snapshot is a signed list of flagged entities that a wallet can check offline.
It is the only protection data Guard uses by default, so verifying it is the
first thing an integrator has to get right.

- Format spec: `sorosentinel-intel/schemas/snapshot-signing.md` (format version
  1, approved by the project owner on 2026-10-27; any change needs a new version)
- JSON schema: `schemas/jsonschema/Snapshot.json`
- Go builder and verifier: `internal/snapshot/snapshot.go`
- TypeScript verifier: `packages/core/src/intel/snapshot.ts`
- Test vectors: `schemas/vectors/snapshot_signing.json`, run by Intel's Go tests
  and Guard's contract tests. `schemas/canonical-key.md` says the vectors run "in
  all three repos' CI"; Scan has no vector test, because it never builds a
  canonical entity string — that sentence is the stale part, not the code.

## What a snapshot contains

```json
{
  "format_version": 1,
  "network": "public",
  "version": 1,
  "generated_at": "2026-10-27T00:00:00Z",
  "ruleset_version": "2026.10.1",
  "key_id": "test-key-1",
  "entries": ["<32 lowercase hex chars>", "..."],
  "signature": "<base64>"
}
```

`entries` are not account or contract addresses. Each one is the first 128 bits
of `SHA-256` over the canonical entity string `<network>|<type>|<key>`
(`schemas/canonical-key.md`), written as lowercase hex, sorted ascending, with no
duplicates. A snapshot therefore says "some entity is flagged" without naming it:
a wallet checks membership by computing the hash of the entity it is about to
transact with. The limit is 10,000,000 entries
([ARCHITECTURE](https://github.com/SoroSentinel/sorosentinel-intel/blob/main/docs/ARCHITECTURE.md)
§17 OE4).

## The signed bytes

The signature is **plain Ed25519 (PureEdDSA) over the whole payload**, not over a
digest. The payload is rebuilt from the snapshot's own fields:

```
SOROSENTINEL-SNAPSHOT-V1\n
network:<network>\n
version:<version, decimal>\n
generated_at:<RFC 3339 UTC with seconds>\n
ruleset_version:<ruleset_version>\n
key_id:<key_id>\n
entries:<number of entries, decimal>\n
<entry 1 as 16 raw bytes><entry 2 as 16 raw bytes>...
```

Header lines are ASCII and each value is validated against its schema pattern
first, so none can smuggle a newline. Entries are written as raw bytes, not hex.
The `entries:` count is signed, so dropping or appending an entry changes the
payload. `signature` is the 64-byte signature, standard base64.

Because the signer hashes internally, a provider that only accepts a pre-computed
digest cannot produce this signature. That constraint is what settled the KMS
provider decision — see [ADR 0006](https://github.com/SoroSentinel/sorosentinel-intel/blob/main/docs/adr/0006-gcp-provider-and-kms-signing.md)
and [`status.html`](status.html).

## Verification order

Guard runs these steps and stops at the first failure. The order matters:
the signature is checked before age or network, so an unsigned or forged
snapshot is rejected as `bad_signature`, not as stale.

1. **Parse strictly.** Exactly the eight fields, `format_version` is 1, network is
   `public` or `testnet`, `version` a safe integer ≥ 1, `generated_at` matching
   the RFC 3339 UTC-with-seconds pattern, `ruleset_version` matching
   `NNNN.NN.NN`, `key_id` matching `[a-z0-9-]{1,64}`, every entry 32 lowercase
   hex chars, sorted, unique, at most the entry cap. → `malformed`
2. **Find the pinned key** for `key_id` among the public keys the integrator
   shipped in the build (32 raw bytes each). → `unknown_key`
3. **Decode and verify** the base64 signature and run Ed25519 verify over the
   rebuilt payload. Any throw from the crypto library is a failure, not a
   pass. → `bad_signature`
4. **Match the network** the transaction is for. A testnet snapshot never
   protects a mainnet signing. → `network_mismatch`
5. **Check the age** against a caller-supplied `asOf`. Guard never reads the
   clock itself. Older than `maxAgeSeconds` (default 3600) → `stale`; more than
   300 seconds from the future → `from_future`.

## What a rejection does

Any failure means **the snapshot is not used at all**. It is never partially
trusted and never downgraded to "some entries might be right". The result's
`snapshotStatus` carries the rejection reason (`stale` is the "protection data
stale" state), and because counterparties were not checked against anything,
`notChecked` includes `NC-COUNTERPARTY-SIGNALS`. The viewer sees that counterparty
signals were not checked — which is a fact, not reassurance. Because any coverage
gap other than execution time makes a result incomplete, an analysis with a
rejected snapshot returns `partial`, never `no_issues_found`; `analyze()` never
reaches the network, and only `analyzeAsync` may ask Intel's API, and only if the
integrator opted in.

Two defaults carry `TODO: confirm the product value`: the 3600-second max age
and the 300-second future skew. They are engineering choices, not reviewed ones.

## Trying it yourself

The vectors file is the shortest path. It carries the input entities, the
snapshot built from them including its signature, the matching public key, and
`payload_sha256` — recomputed independently in Python from the spec text, so a
verifier can check the payload it rebuilds against something other than the Go
code it came from. The file also holds a signing seed: **a fixed test key (32
bytes of `0x07`), used only for vectors, never for a published snapshot.**

The measured end-to-end check is in
`docs/runbooks/phase1-exit-test-results-2026-10.md`: a snapshot built from real
testnet evidence verified with `Verify` OK, and changing one entry produced
`snapshot: bad signature` and the corresponding Guard rejection.

## Signing key status — read this before integrating

- **The snapshot format is approved and implemented. The production signer is
  not.** Intel signs through `internal/snapshot/keyfile.go`, an interim path that
  loads a PKCS#8 Ed25519 PEM from a file the operator chmods to 600. It refuses a
  group- or world-readable file, a non-regular file, and anything over 4 KiB, and
  no error message ever contains key bytes.
- No KMS signer exists yet. ADR 0006 chose GCP Cloud KMS `ec-sign-ed25519` as the
  only provider that can sign this format as specified; the remaining work is the
  deployment decision and the account, not the crypto.
- There is no key revocation list and no delta format, by design for v1. Rotation
  today means the integrator ships a new pinned key set in their own build, which
  is why `pinnedKeys` is a map from `key_id` rather than a single key.
- Nothing is deployed yet, so there is no public snapshot URL and no production
  public key to pin. See `status.html`.
