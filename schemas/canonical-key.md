# Canonical entity-key encoding

Status: **draft 0.1, needs maintainer approval** before Scan/Guard depend on it.
Vectors: `vectors/canonical_keys.json` (run in all three repos' CI).

## Canonical string

```
<network>|<type>|<key>
```

| Field | Rule |
|---|---|
| `network` | `public` or `testnet`. Anything else is an error (`unknown_network`). |
| `type` | `account`, `asset`, `contract`, `wasm_hash`, `domain`. Else `unknown_type`. |
| `account` key | `G` + 55 base32 chars (`[A-Z2-7]`), 56 total. Muxed `M…` input is an error (`muxed_not_normalized`): normalize to `G…` at input first. |
| `asset` key | `native`, or `CODE:ISSUER`. CODE is 1–12 ASCII alphanumerics, **case preserved**. ISSUER follows the account rule. |
| `contract` key | `C` + 55 base32 chars. |
| `wasm_hash` key | 64 hex chars, lowercased. |
| `domain` key | ASCII only (IDN must already be a punycode A-label, else `non_ascii`), lowercased, one trailing dot removed, ≤ 253 chars, ≥ 2 labels, each label `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`. |

Any input longer than 300 bytes, or failing a rule above, is `invalid_key`.

## Snapshot entry hash

```
hex(SHA-256(canonical_string))[0:32]   # first 128 bits, lowercase hex
```

## Open items

- TODO(verify): strkey checksum (CRC16-XModem) validation is not done here; it
  needs the official Stellar SDK in each language. Shape-only checks for now.
- TODO(verify): are asset codes case-sensitive on the ledger? Encoding assumes yes.
- Muxed → `G…` normalization and IDN → A-label conversion belong to the input
  layer and get their own vectors once those libraries are approved.
