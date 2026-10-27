# Snapshot signing (format version 1)

Status: **approved by the project owner on 2026-10-27** (AGENTS.md §10: snapshot
format). Any change needs a new format version. Vector: `vectors/snapshot_signing.json`.

The signature in `Snapshot.json` is Ed25519 over these exact bytes:

```
SOROSENTINEL-SNAPSHOT-V1\n
network:<network>\n
version:<version, decimal>\n
generated_at:<RFC 3339 UTC with seconds, e.g. 2026-10-27T00:00:00Z>\n
ruleset_version:<ruleset_version>\n
key_id:<key_id>\n
entries:<number of entries, decimal>\n
<entry 1 as 16 raw bytes><entry 2 as 16 raw bytes>...
```

- Lines are ASCII and end with a single `\n`. Every header value is validated
  against its schema pattern first, so none can contain a newline.
- Entries are the 128-bit snapshot hashes from `canonical-key.md`, sorted
  ascending by their hex form, with no duplicates, written as raw bytes (not hex).
- `signature` is the 64-byte Ed25519 signature, standard base64.

## Verifying (Guard)

1. Rebuild the payload from the snapshot's own fields; reject the snapshot if any
   field fails its pattern, if entries are unsorted or duplicated, or if the
   entry count does not match.
2. Verify the signature against the public key pinned in the SDK for `key_id`.
3. Reject snapshots older than the configured max age and show the
   "protection data stale" state (v1 cut list: one KMS key plus one offline backup key).

Any failure means no snapshot is used, and lookups report `NC-COUNTERPARTY-SIGNALS`.
