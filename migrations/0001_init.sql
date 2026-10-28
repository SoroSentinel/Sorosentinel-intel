-- 0001_init: Intel core tables (ARCHITECTURE §7.1 with the v1 cut list,
-- ARCHITECTURE_ESSENTIALS §12 HQ3, applied). Forward-only.
--
-- Cut for v1, deliberately absent: numeric score/weight/trust/confidence,
-- evidence partitioning, wording_template, report, dispute, webhook, scan_job,
-- api_key, and entity_link relations other than sac_of.

CREATE TYPE entity_type AS ENUM ('account', 'asset', 'contract', 'wasm_hash', 'domain');
-- Internal levels. Never leave the system (internal/signal maps them).
CREATE TYPE verdict_level AS ENUM ('benign', 'unknown', 'suspicious', 'malicious');
CREATE TYPE verdict_status AS ENUM ('active', 'revoked');
CREATE TYPE source_kind AS ENUM ('heuristic', 'scan', 'community', 'curated');

-- Rows are created lazily: on evidence, first lookup, or curated watchlist.
CREATE TABLE entity (
  id                BIGSERIAL PRIMARY KEY,
  network           TEXT NOT NULL CHECK (network IN ('public', 'testnet')),
  type              entity_type NOT NULL,
  key               TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 300),
  first_seen_ledger BIGINT CHECK (first_seen_ledger > 0),
  first_seen_at     TIMESTAMPTZ,
  attrs             JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attrs) = 'object'),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (network, type, key)
);

CREATE TABLE source (
  id     SMALLSERIAL PRIMARY KEY,
  name   TEXT UNIQUE NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
  kind   source_kind NOT NULL,
  config JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config) = 'object')
);

-- Write-once raw evidence. Public data only; reporter PII lives elsewhere.
-- A human confirmation is a D-CURATED row carrying confirmed_level/confirmed_by.
CREATE TABLE evidence (
  id              BIGSERIAL PRIMARY KEY,
  entity_id       BIGINT NOT NULL REFERENCES entity (id),
  source_id       SMALLINT NOT NULL REFERENCES source (id),
  detector        TEXT NOT NULL CHECK (detector ~ '^D-[A-Z0-9-]{1,48}$'),
  evidence_class  TEXT NOT NULL CHECK (evidence_class ~ '^[a-z][a-z-]{0,31}$'),
  category        TEXT NOT NULL CHECK (category ~ '^[a-z][a-z_]{0,63}$'),
  payload         JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  observed_at     TIMESTAMPTZ NOT NULL,
  ledger_seq      BIGINT CHECK (ledger_seq > 0),
  expires_at      TIMESTAMPTZ CHECK (expires_at > observed_at),
  artifact_refs   TEXT[] NOT NULL DEFAULT '{}',
  confirmed_level verdict_level,
  confirmed_by    TEXT CHECK (length(confirmed_by) BETWEEN 1 AND 128),
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((confirmed_level IS NULL) = (confirmed_by IS NULL)),
  CHECK (confirmed_level IS NULL OR detector = 'D-CURATED')
);
CREATE INDEX evidence_entity_observed ON evidence (entity_id, observed_at DESC);

-- One current verdict per entity; history in verdict_events. No numeric score:
-- the level comes from the rule table (internal/verdict) and records which
-- rule fired, over which evidence, at which as_of and ruleset_version.
CREATE TABLE verdict (
  id              BIGSERIAL PRIMARY KEY,
  entity_id       BIGINT NOT NULL UNIQUE REFERENCES entity (id),
  level           verdict_level NOT NULL,
  status          verdict_status NOT NULL,
  disputed        BOOLEAN NOT NULL DEFAULT false,
  category        TEXT,
  rule_id         TEXT NOT NULL,
  decided_by      TEXT NOT NULL,
  ruleset_version TEXT NOT NULL CHECK (ruleset_version ~ '^[0-9]{4}\.[0-9]{2}\.[0-9]+$'),
  as_of           TIMESTAMPTZ NOT NULL,
  evidence_ids    BIGINT[] NOT NULL,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX verdict_flagged ON verdict (entity_id)
  WHERE status = 'active' AND level IN ('suspicious', 'malicious');

-- Append-only audit log: every verdict change, dispute flag and revocation.
-- Also the v1 manual log for disputes (no dispute table).
CREATE TABLE verdict_events (
  id              BIGSERIAL PRIMARY KEY,
  entity_id       BIGINT NOT NULL REFERENCES entity (id),
  verdict_id      BIGINT NOT NULL REFERENCES verdict (id),
  from_level      verdict_level,
  to_level        verdict_level NOT NULL,
  from_status     verdict_status,
  to_status       verdict_status NOT NULL,
  from_disputed   BOOLEAN,
  to_disputed     BOOLEAN NOT NULL,
  rule_id         TEXT NOT NULL,
  ruleset_version TEXT NOT NULL,
  as_of           TIMESTAMPTZ NOT NULL,
  evidence_ids    BIGINT[] NOT NULL,
  actor           TEXT NOT NULL,
  reason          TEXT,                 -- internal; never serialized publicly
  at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX verdict_events_entity ON verdict_events (entity_id, id);

-- Immutable record of what was shown publicly. Only superseded_at may be set, once.
CREATE TABLE public_statement (
  id                 BIGSERIAL PRIMARY KEY,
  entity_id          BIGINT NOT NULL REFERENCES entity (id),
  verdict_id         BIGINT REFERENCES verdict (id),
  template_id        TEXT NOT NULL,
  template_version   INT NOT NULL CHECK (template_version > 0),
  signal_level       TEXT NOT NULL CHECK (signal_level IN ('consistent', 'no_signals', 'caution', 'high_caution')),
  rendered_text      TEXT NOT NULL,
  facts              JSONB NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
  as_of              TIMESTAMPTZ NOT NULL,
  evidence_artifacts TEXT[] NOT NULL,
  superseded_at      TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Alternate identities: v1 links a classic asset and its Stellar Asset Contract only.
CREATE TABLE entity_link (
  from_entity_id BIGINT NOT NULL REFERENCES entity (id),
  to_entity_id   BIGINT NOT NULL REFERENCES entity (id),
  relation       TEXT NOT NULL CHECK (relation = 'sac_of'),
  PRIMARY KEY (from_entity_id, to_entity_id, relation),
  CHECK (from_entity_id <> to_entity_id)
);

CREATE TABLE snapshot (
  network         TEXT NOT NULL CHECK (network IN ('public', 'testnet')),
  version         BIGINT NOT NULL CHECK (version > 0),
  generated_at    TIMESTAMPTZ NOT NULL,
  ruleset_version TEXT NOT NULL,
  entry_count     INT NOT NULL CHECK (entry_count >= 0),
  object_key      TEXT NOT NULL,
  signing_key_id  TEXT NOT NULL,
  signature       BYTEA NOT NULL,
  PRIMARY KEY (network, version)
);

CREATE TABLE ingest_checkpoint (
  network     TEXT PRIMARY KEY CHECK (network IN ('public', 'testnet')),
  last_ledger BIGINT NOT NULL CHECK (last_ledger > 0),
  updated_at  TIMESTAMPTZ NOT NULL
);

-- Append-only enforcement for evidence and verdict_events.
CREATE FUNCTION reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON evidence
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON evidence
  FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER verdict_events_append_only BEFORE UPDATE OR DELETE ON verdict_events
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER verdict_events_no_truncate BEFORE TRUNCATE ON verdict_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();

CREATE FUNCTION public_statement_supersede_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR OLD.superseded_at IS NOT NULL OR NEW.superseded_at IS NULL
     OR (to_jsonb(NEW) - 'superseded_at') <> (to_jsonb(OLD) - 'superseded_at') THEN
    RAISE EXCEPTION 'public_statement is immutable except a single superseded_at'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER public_statement_immutable BEFORE UPDATE OR DELETE ON public_statement
  FOR EACH ROW EXECUTE FUNCTION public_statement_supersede_only();
CREATE TRIGGER public_statement_no_truncate BEFORE TRUNCATE ON public_statement
  FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();
