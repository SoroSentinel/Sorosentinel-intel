# Counsel review packet: the 12 draft wording templates

Status: for review · Date: 2026-10-28 · Requested by: issue #32 · Reviewed by: nobody yet

This file changes no template. It is the artifact counsel annotates: every sentence a signer can be
shown, rendered with realistic values, together with what an approval changes mechanically.
AGENTS.md §5 lets only counsel-approved text reach users, and §10 makes a template change its own PR
merged by someone other than its author, so nothing here proposes an edit.

## Where things stand

- All 12 templates in `wording/templates/en/` are `status: draft`, and
  `wording/attribution/standard_v1.yaml` is `draft` as well.
- Consequence today: `Render` returns `not_approved` for every finding, so the read API and Guard
  show structured facts and no sentence. Proven rather than asserted:
  `internal/wording/wording_test.go:28` asserts the error code, an empty `Text`, an empty
  `Attribution` and a complete facts fallback; `wording/vectors/render.json` covers the other half -
  an approved template renders, and a draft attribution fails closed the same way.
- `make lint` runs `go vet` and `cmd/wordlint -dir wording -docs docs/methodology`, which reports
  `wordlint: ok`; `TestEmbeddedRegistryLintsClean` lints the real shipped templates, not a copy.
- The one thing CI cannot do: the render vectors exercise their own fixture templates, so **no test
  reads the text of `wording/templates/en/`**. An accidental edit to an approved sentence stays
  invisible to `make verify`. That is precisely the hole this review is meant to close, which is why
  each entry below prints the stored text and the filled result side by side.

## What sign-off changes, mechanically

One line per file: `status: draft` → `status: counsel_approved`, across the 12 template files and the
attribution file. No code, schema, snapshot format or endpoint moves: the renderer already branches on
`Status`, and while drafts are in force the API and Guard already expect prose to be absent (AGENTS.md
§3.9 - absence of data is never reassurance). `make verify` is green before the flip and green after
it, which is another way of saying the check on this change is a human reading the strings.

Approval can be partial, and grouping is worth considering: `tx.signer_added.v1`,
`tx.signer_added_hash_x.v1` and `tx.signer_added_pre_auth.v1` are three key-type variants of one
finding, and `tx.account_control.v1`, `tx.master_weight_zero.v1` and `tx.signer_removed.v1` all hang
off `G-ACCOUNT-CONTROL`.

## How to review each entry

For every entry, the questions AGENTS.md §5 imposes:

1. Is each clause a verifiable observation, given the slot values it is filled from?
2. Does it describe an **effect of a transaction** rather than the character, intent or identity of
   whoever is on the other end?
3. Would a signer with no Stellar background follow it?
4. Is the alarm matched to the level it renders at - no stronger than the fact supports, no softer?
5. Does the attribution line carry the "indicator, not a determination of intent or wrongdoing"
   disclaimer, so the sentence itself does not have to hedge?

The blocklist is checked per entry and printed as `clean` or `HITS …`. §5 allows no exceptions, so a
hit means that template cannot ship as written.

## What is not being asked

- No sentence is being rewritten here. A wording change is a separate template PR (§10).
- No approval is recorded by this file. Acceptance criterion 1 of #32 wants a named sign-off - who,
  on what date, covering which set - in the flip PR's description or an ADR line. The table below is
  a convenience copy of that.

## Sign-off table

| Template or attribution | Approve / revise / decline | Counsel | Date |
|---|---|---|---|
| `asset.lookalike.v1` | | | |
| `asset.lookalike_similar.v1` | | | |
| `domain.homedomain_mismatch.v1` | | | |
| `domain.homedomain_unavailable.v1` | | | |
| `tx.account_control.v1` | | | |
| `tx.expiry_far.v1` | | | |
| `tx.master_weight_zero.v1` | | | |
| `tx.no_expiry.v1` | | | |
| `tx.signer_added.v1` | | | |
| `tx.signer_added_hash_x.v1` | | | |
| `tx.signer_added_pre_auth.v1` | | | |
| `tx.signer_removed.v1` | | | |
| `standard_v1` (attribution, shown under every entry) | | | |

## Entries

Built by loading the real registry (`wording.Load` over `wording/`), flipping `status` **in memory
only**, and rendering each template through the production renderer with the methodology and review
URLs `deploy/docker-compose.yml` passes to `intel-api`. Sample slot values are throwaway testnet-format
keys generated off fixed seeds, plus `example-acme.com`; no real account, asset or domain. `as_of` is
fixed at 2026-10-28 14:02 UTC and `ruleset_version` at `2026.10.1` so the output is reproducible.
Templates store their text as a folded YAML block, so the "stored text" line is that block unfolded.

### `asset.lookalike.v1`

- **Shown for:** detector D-ASSET-LOOKALIKE, asset entity
- **Shown at public level or finding severity:** caution, high_caution
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `known_asset` (asset_key) = `USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR`, `known_issuer` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Stored text:**

  ```text
  This asset uses the same code as {known_asset} but a different issuer account. The issuer of {known_asset} is {known_issuer}. Observed {as_of}.
  ```
- **Rendered with sample values:**

  > This asset uses the same code as USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR but a different issuer account. The issuer of USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR is GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U. Observed 2026-10-28 14:02 UTC.

  > Method: D-ASSET-LOOKALIKE, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `as_of=2026-10-28T14:02:00Z known_asset=USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR known_issuer=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Blocklist:** clean

### `asset.lookalike_similar.v1`

- **Shown for:** detector D-ASSET-LOOKALIKE, asset entity
- **Shown at public level or finding severity:** caution, high_caution
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `known_asset` (asset_key) = `USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR`
- **Stored text:**

  ```text
  This asset's code is similar to the code of {known_asset}, and its issuer account is different from the issuer of {known_asset}. Observed {as_of}.
  ```
- **Rendered with sample values:**

  > This asset's code is similar to the code of USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR, and its issuer account is different from the issuer of USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR. Observed 2026-10-28 14:02 UTC.

  > Method: D-ASSET-LOOKALIKE, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `as_of=2026-10-28T14:02:00Z known_asset=USDC:GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR`
- **Blocklist:** clean

### `domain.homedomain_mismatch.v1`

- **Shown for:** detector D-HOMEDOMAIN-MISMATCH, asset entity
- **Shown at public level or finding severity:** caution, high_caution
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `asset` (asset_key) = `USDC:GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`, `home_domain` (domain) = `example-acme.com`, `issuer` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Stored text:**

  ```text
  Issuer account {issuer} sets its home domain to {home_domain}. The stellar.toml file published at that domain does not list {asset} among its currencies. Checked {as_of}.
  ```
- **Rendered with sample values:**

  > Issuer account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U sets its home domain to example-acme.com. The stellar.toml file published at that domain does not list USDC:GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U among its currencies. Checked 2026-10-28 14:02 UTC.

  > Method: D-HOMEDOMAIN-MISMATCH, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `as_of=2026-10-28T14:02:00Z asset=USDC:GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U home_domain=example-acme.com issuer=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Blocklist:** clean

### `domain.homedomain_unavailable.v1`

- **Shown for:** detector D-HOMEDOMAIN-MISMATCH, asset entity
- **Shown at public level or finding severity:** caution
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `asset` (asset_key) = `USDC:GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`, `home_domain` (domain) = `example-acme.com`, `issuer` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Stored text:**

  ```text
  Issuer account {issuer} sets its home domain to {home_domain}. When checked on {as_of}, the stellar.toml file at that domain could not be retrieved or read, so it was not possible to confirm that the file lists {asset}.
  ```
- **Rendered with sample values:**

  > Issuer account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U sets its home domain to example-acme.com. When checked on 2026-10-28 14:02 UTC, the stellar.toml file at that domain could not be retrieved or read, so it was not possible to confirm that the file lists USDC:GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U.

  > Method: D-HOMEDOMAIN-MISMATCH, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `as_of=2026-10-28T14:02:00Z asset=USDC:GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U home_domain=example-acme.com issuer=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Blocklist:** clean

### `tx.account_control.v1`

- **Shown for:** Guard finding G-ACCOUNT-CONTROL
- **Shown at public level or finding severity:** critical
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `account` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Stored text:**

  ```text
  This transaction changes the signing weights or thresholds of account {account}. After it, a different set of signers may be required, or may be enough, to approve transactions from this account.
  ```
- **Rendered with sample values:**

  > This transaction changes the signing weights or thresholds of account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U. After it, a different set of signers may be required, or may be enough, to approve transactions from this account.

  > Method: G-ACCOUNT-CONTROL, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `account=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U as_of=2026-10-28T14:02:00Z`
- **Blocklist:** clean

### `tx.expiry_far.v1`

- **Shown for:** Guard finding G-NO-EXPIRY
- **Shown at public level or finding severity:** medium
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `max_time` (timestamp) = `2027-01-01T00:00:00Z`
- **Stored text:**

  ```text
  This transaction stays valid until {max_time}. Once signed, it can be submitted at any time before then.
  ```
- **Rendered with sample values:**

  > This transaction stays valid until 2027-01-01 00:00 UTC. Once signed, it can be submitted at any time before then.

  > Method: G-NO-EXPIRY, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `as_of=2026-10-28T14:02:00Z max_time=2027-01-01T00:00:00Z`
- **Blocklist:** clean

### `tx.master_weight_zero.v1`

- **Shown for:** Guard finding G-ACCOUNT-CONTROL
- **Shown at public level or finding severity:** critical
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `account` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`
- **Stored text:**

  ```text
  This transaction sets the master key weight of account {account} to 0. After it, the account's own key can no longer approve transactions. Only its other signers can.
  ```
- **Rendered with sample values:**

  > This transaction sets the master key weight of account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U to 0. After it, the account's own key can no longer approve transactions. Only its other signers can.

  > Method: G-ACCOUNT-CONTROL, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `account=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U as_of=2026-10-28T14:02:00Z`
- **Blocklist:** clean

### `tx.no_expiry.v1`

- **Shown for:** Guard finding G-NO-EXPIRY
- **Shown at public level or finding severity:** medium
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** none
- **Stored text:**

  ```text
  This transaction has no expiry time. Once signed, it stays valid until it is submitted or its sequence number is used, which can be much later than now.
  ```
- **Rendered with sample values:**

  > This transaction has no expiry time. Once signed, it stays valid until it is submitted or its sequence number is used, which can be much later than now.

  > Method: G-NO-EXPIRY, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `as_of=2026-10-28T14:02:00Z`
- **Blocklist:** clean

### `tx.signer_added.v1`

- **Shown for:** Guard finding G-SIGNER-ADDED
- **Shown at public level or finding severity:** high
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `account` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`, `signer` (signer_key) = `GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG`, `weight` (weight) = `10`
- **Stored text:**

  ```text
  This transaction adds {signer} as a signer on account {account} with weight {weight}. A signer can approve transactions from this account, alone or together with other signers, depending on the account's thresholds.
  ```
- **Rendered with sample values:**

  > This transaction adds GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG as a signer on account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U with weight 10. A signer can approve transactions from this account, alone or together with other signers, depending on the account's thresholds.

  > Method: G-SIGNER-ADDED, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `account=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U as_of=2026-10-28T14:02:00Z signer=GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG weight=10`
- **Blocklist:** clean

### `tx.signer_added_hash_x.v1`

- **Shown for:** Guard finding G-SIGNER-ADDED
- **Shown at public level or finding severity:** critical
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `account` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`, `signer` (signer_key) = `XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, `weight` (weight) = `10`
- **Stored text:**

  ```text
  This transaction adds a hash(x) signer to account {account} with weight {weight}. Anyone who learns the value behind this hash can use it to approve transactions from this account. It is not tied to a visible key. Signer: {signer}.
  ```
- **Rendered with sample values:**

  > This transaction adds a hash(x) signer to account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U with weight 10. Anyone who learns the value behind this hash can use it to approve transactions from this account. It is not tied to a visible key. Signer: XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.

  > Method: G-SIGNER-ADDED, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `account=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U as_of=2026-10-28T14:02:00Z signer=XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA weight=10`
- **Blocklist:** clean

### `tx.signer_added_pre_auth.v1`

- **Shown for:** Guard finding G-SIGNER-ADDED
- **Shown at public level or finding severity:** critical
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `account` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`, `signer` (signer_key) = `TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, `weight` (weight) = `10`
- **Stored text:**

  ```text
  This transaction adds a pre-authorized transaction signer to account {account} with weight {weight}. It approves one specific prepared transaction, identified by {signer}, for this account without a signature from any key.
  ```
- **Rendered with sample values:**

  > This transaction adds a pre-authorized transaction signer to account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U with weight 10. It approves one specific prepared transaction, identified by TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, for this account without a signature from any key.

  > Method: G-SIGNER-ADDED, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `account=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U as_of=2026-10-28T14:02:00Z signer=TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA weight=10`
- **Blocklist:** clean

### `tx.signer_removed.v1`

- **Shown for:** Guard finding G-ACCOUNT-CONTROL
- **Shown at public level or finding severity:** critical
- **Current status:** draft (renderer refuses it; APIs return facts only)
- **Slots:** `account` (account) = `GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U`, `removed_signer` (signer_key) = `GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG`
- **Stored text:**

  ```text
  This transaction removes {removed_signer} as a signer from account {account}. After it, that signer can no longer approve transactions from this account.
  ```
- **Rendered with sample values:**

  > This transaction removes GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG as a signer from account GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U. After it, that signer can no longer approve transactions from this account.

  > Method: G-ACCOUNT-CONTROL, ruleset 2026.10.1. Observed 2026-10-28 14:02 UTC. This is an indicator, not a determination of intent or wrongdoing. Methodology: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md. Request a review: https://github.com/SoroSentinel/Sorosentinel-intel/blob/main/docs/methodology/index.md#requesting-a-review.
- **What a signer sees today (facts only, no prose):** `account=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U as_of=2026-10-28T14:02:00Z removed_signer=GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG`
- **Blocklist:** clean

