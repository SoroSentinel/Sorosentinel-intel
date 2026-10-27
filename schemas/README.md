# schemas

The only source of truth for contracts between Intel, Scan and Guard.
Consumers pin a git tag of this repo and never hand-edit copies.

## Compatibility rules

- SemVer. Within a major version, changes are **additive only**: new optional
  fields, new enum values only where consumers already treat unknown values as
  `partial`/`unanalyzable`.
- A breaking change needs a new `/v2` and a dual-run period.
- Public schemas are allowlists (`additionalProperties: false`). Internal
  verdict fields (level, rationale, analyst notes) never appear here, so the
  internal `Verdict`/`Evidence` models are deliberately not shared schemas.
- Amounts are integer stroops encoded as decimal strings (`common.json#/$defs/stroops`).

## Changes

| Date | Schema | Change |
|---|---|---|
| 2026-10-27 | `Snapshot` | Signed bytes defined in `snapshot-signing.md` (format version 1). Approved by the owner. |
| 2026-10-27 | `AnalysisResult` | `effects[].delta_max` may be `null`, meaning no upper bound. Approved by the owner; safe before the first tagged release because no consumer is pinned yet. |

## Contents

| Path | What |
|---|---|
| `jsonschema/` | JSON Schema 2020-12, `$id` = `urn:sorosentinel:schema:v1:<Name>` |
| `openapi/intel.v1.yaml` | REST API (OpenAPI 3.1) |
| `canonical-key.md` | Canonical entity-key encoding spec (**draft**) |
| `snapshot-signing.md` | Exact bytes the snapshot signature covers (format version 1, approved) |
| `vectors/` | Test vectors every repo's CI must pass |
| `generated/` | Codegen output (gitignored; generator not chosen yet) |
