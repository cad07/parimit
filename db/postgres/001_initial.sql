-- Parimit PostgreSQL schema track (not wired into the alpha runtime).
-- Target: PostgreSQL 14 or newer.
-- Apply exactly once with ON_ERROR_STOP enabled as a migration-owner role.

BEGIN;

CREATE SCHEMA parimit;

CREATE DOMAIN parimit.sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

-- JavaScript Date#toISOString output is stored byte-for-byte because these
-- timestamp strings participate in intent, approval, and audit digests.
CREATE DOMAIN parimit.canonical_timestamp AS text
  CHECK (
    VALUE ~ '^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9][.][0-9]{3}Z$'
    AND substring(VALUE FROM 1 FOR 4)::integer BETWEEN 1 AND 9999
    AND to_char(
      VALUE::timestamptz AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
    ) = VALUE
  );

CREATE TABLE parimit.policy_subjects (
  tenant_id text NOT NULL
    CHECK (
      char_length(tenant_id) BETWEEN 1 AND 128
      AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
    ),
  agent_id text NOT NULL
    CHECK (
      char_length(agent_id) BETWEEN 1 AND 128
      AND agent_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
    ),
  PRIMARY KEY (tenant_id, agent_id)
);

CREATE TABLE parimit.intents (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL
    CHECK (
      char_length(tenant_id) BETWEEN 1 AND 128
      AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
    ),
  idempotency_key text NOT NULL
    CHECK (
      char_length(idempotency_key) BETWEEN 1 AND 128
      AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
    ),
  request_fingerprint parimit.sha256_hex NOT NULL,
  agent_id text NOT NULL
    CHECK (
      char_length(agent_id) BETWEEN 1 AND 128
      AND agent_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
    ),
  on_behalf_of text
    CHECK (
      on_behalf_of IS NULL
      OR (
        char_length(on_behalf_of) BETWEEN 1 AND 128
        AND on_behalf_of ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
      )
    ),
  amount_minor bigint NOT NULL
    CHECK (amount_minor BETWEEN 1 AND 9007199254740991),
  currency text NOT NULL CHECK (currency = 'INR'),
  payee_reference text NOT NULL
    CHECK (payee_reference ~ '^[A-Za-z][A-Za-z0-9:_-]{5,63}$'),
  purpose text NOT NULL
    CHECK (
      char_length(purpose) BETWEEN 1 AND 500
      AND purpose !~ '[[:cntrl:]]'
    ),
  status text NOT NULL
    CHECK (
      status IN (
        'POLICY_DENIED',
        'AWAITING_APPROVAL',
        'AUTHORIZED_NO_DISPATCH',
        'REJECTED',
        'CANCELLED',
        'EXPIRED'
      )
    ),
  required_approvals smallint NOT NULL CHECK (required_approvals IN (1, 2)),
  policy_allowed boolean NOT NULL,
  policy_reasons jsonb NOT NULL CHECK (jsonb_typeof(policy_reasons) = 'array'),
  rules_version text NOT NULL CHECK (char_length(rules_version) BETWEEN 1 AND 128),
  intent_version text NOT NULL
    CHECK (
      intent_version IN (
        'parimit-payment-intent-v1',
        'parimit-payment-intent-v2',
        'parimit-payment-intent-v3'
      )
    ),
  initial_status text NOT NULL
    CHECK (initial_status IN ('POLICY_DENIED', 'AWAITING_APPROVAL')),
  state_version bigint NOT NULL CHECK (state_version >= 1),
  intent_hash parimit.sha256_hex NOT NULL,
  created_at parimit.canonical_timestamp NOT NULL,
  expires_at parimit.canonical_timestamp NOT NULL,
  CONSTRAINT intents_policy_subject_fk
    FOREIGN KEY (tenant_id, agent_id)
    REFERENCES parimit.policy_subjects(tenant_id, agent_id),
  CONSTRAINT intents_agent_idempotency_unique UNIQUE (tenant_id, agent_id, idempotency_key),
  CONSTRAINT intents_tenant_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT intents_policy_initial_status_consistent CHECK (
    (policy_allowed AND initial_status = 'AWAITING_APPROVAL')
    OR (NOT policy_allowed AND initial_status = 'POLICY_DENIED')
  ),
  CONSTRAINT intents_expiry_after_creation CHECK (expires_at > created_at)
);

CREATE TABLE parimit.approvals (
  id uuid PRIMARY KEY,
  intent_id uuid NOT NULL REFERENCES parimit.intents(id),
  actor_id text NOT NULL
    CHECK (
      char_length(actor_id) BETWEEN 1 AND 128
      AND actor_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
    ),
  actor_role text NOT NULL CHECK (actor_role IN ('approver', 'admin')),
  decision text NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
  intent_hash parimit.sha256_hex NOT NULL,
  created_at parimit.canonical_timestamp NOT NULL,
  receipt_hmac text NOT NULL CHECK (receipt_hmac ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT approvals_distinct_actor UNIQUE (intent_id, actor_id)
);

CREATE TABLE parimit.observations (
  sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  id uuid PRIMARY KEY,
  intent_id uuid NOT NULL REFERENCES parimit.intents(id),
  status text NOT NULL
    CHECK (status IN ('UNKNOWN', 'PENDING', 'SUCCEEDED', 'FAILED', 'REVERSED', 'DISPUTED', 'IN_DOUBT')),
  provider_reference text
    CHECK (
      provider_reference IS NULL
      OR char_length(provider_reference) BETWEEN 1 AND 200
    ),
  observed_at parimit.canonical_timestamp NOT NULL,
  source text NOT NULL CHECK (source = 'DEMO_MOCK')
);

CREATE TABLE parimit.audit_events (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  intent_id uuid NOT NULL REFERENCES parimit.intents(id),
  event_type text NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 128),
  actor_id text NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 128),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  occurred_at parimit.canonical_timestamp NOT NULL,
  previous_hash text NOT NULL
    CHECK (previous_hash = 'GENESIS' OR previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash parimit.sha256_hex NOT NULL,
  -- No two events may form competing branches from the same predecessor.
  CONSTRAINT audit_events_no_forks UNIQUE (intent_id, previous_hash)
);

CREATE TABLE parimit.envelope_signing_keys (
  key_id text PRIMARY KEY CHECK (char_length(key_id) BETWEEN 1 AND 128),
  public_jwk jsonb NOT NULL CHECK (jsonb_typeof(public_jwk) = 'object'),
  created_at parimit.canonical_timestamp NOT NULL,
  attestation_hmac text NOT NULL CHECK (attestation_hmac ~ '^[A-Za-z0-9_-]{43}$')
);

-- Mutable HMAC checkpoint over the complete semantic signing-key registry,
-- sorted by key_id. It must be inserted with the empty registry and replaced
-- in the same transaction as every signing-key insert. Deletion is forbidden.
CREATE TABLE parimit.envelope_signing_key_registry_state (
  name text PRIMARY KEY CHECK (name = 'envelope_signing_key_registry_state_v1'),
  value text NOT NULL CHECK (value ~ '^[A-Za-z0-9_-]{43}$')
);

-- This is the PostgreSQL equivalent of SQLite service_metadata's
-- receipt_integrity_root_v1 row. The value is the receipt-secret HMAC of the
-- canonical {version, tenant_id, envelope_issuer, envelope_audience,
-- envelope_maximum_lifetime_seconds, authentication_mode,
-- identity_trust_domain_id, policy_configuration_digest} root payload. The
-- fixed name permits exactly one database-bound trust root; alpha.3 does not
-- support rotating it.
CREATE TABLE parimit.service_integrity_roots (
  name text PRIMARY KEY CHECK (name = 'receipt_integrity_root_v1'),
  value text NOT NULL CHECK (value ~ '^[A-Za-z0-9_-]{43}$')
);

CREATE TABLE parimit.authorization_envelopes (
  id uuid PRIMARY KEY,
  intent_id uuid NOT NULL,
  tenant_id text NOT NULL,
  state_version bigint NOT NULL CHECK (state_version >= 1),
  audience text NOT NULL CHECK (char_length(audience) BETWEEN 1 AND 512),
  issuance_idempotency_key text NOT NULL
    CHECK (
      char_length(issuance_idempotency_key) BETWEEN 1 AND 128
      AND issuance_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
    ),
  key_id text NOT NULL REFERENCES parimit.envelope_signing_keys(key_id),
  compact_jws text NOT NULL UNIQUE CHECK (octet_length(compact_jws) <= 65536),
  claims_hash parimit.sha256_hex NOT NULL,
  nonce_hash parimit.sha256_hex NOT NULL,
  issued_at parimit.canonical_timestamp NOT NULL,
  expires_at parimit.canonical_timestamp NOT NULL,
  consumed_at parimit.canonical_timestamp,
  consumed_by text
    CHECK (
      consumed_by IS NULL
      OR (
        char_length(consumed_by) BETWEEN 1 AND 128
        AND consumed_by ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
      )
    ),
  consumption_idempotency_key text
    CHECK (
      consumption_idempotency_key IS NULL
      OR (
        char_length(consumption_idempotency_key) BETWEEN 1 AND 128
        AND consumption_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$'
      )
    ),
  CONSTRAINT authorization_envelope_scope_unique
    UNIQUE (tenant_id, intent_id, state_version, audience),
  CONSTRAINT authorization_envelope_nonce_unique UNIQUE (tenant_id, nonce_hash),
  CONSTRAINT authorization_envelope_tenant_intent_fk
    FOREIGN KEY (tenant_id, intent_id)
    REFERENCES parimit.intents(tenant_id, id),
  CONSTRAINT authorization_envelope_expiry_after_issue CHECK (expires_at > issued_at),
  CONSTRAINT authorization_envelope_consumption_consistent CHECK (
    (consumed_at IS NULL AND consumed_by IS NULL AND consumption_idempotency_key IS NULL)
    OR (
      consumed_at IS NOT NULL
      AND consumed_by IS NOT NULL
      AND consumption_idempotency_key IS NOT NULL
      AND consumed_at >= issued_at
      AND consumed_at < expires_at
    )
  )
);

CREATE INDEX intents_agent_created_idx
  ON parimit.intents (agent_id, created_at);
CREATE INDEX intents_status_expiry_idx
  ON parimit.intents (status, expires_at);
CREATE INDEX approvals_intent_order_idx
  ON parimit.approvals (intent_id, created_at, id);
CREATE INDEX observations_intent_sequence_idx
  ON parimit.observations (intent_id, sequence);
CREATE INDEX audit_events_intent_sequence_idx
  ON parimit.audit_events (intent_id, sequence);
CREATE INDEX authorization_envelopes_expiry_idx
  ON parimit.authorization_envelopes (expires_at);

CREATE FUNCTION parimit.reject_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  RAISE EXCEPTION '% is append-only; % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END;
$function$;

CREATE TRIGGER approvals_append_only
  BEFORE UPDATE OR DELETE ON parimit.approvals
  FOR EACH ROW EXECUTE FUNCTION parimit.reject_evidence_mutation();

CREATE TRIGGER observations_append_only
  BEFORE UPDATE OR DELETE ON parimit.observations
  FOR EACH ROW EXECUTE FUNCTION parimit.reject_evidence_mutation();

CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON parimit.audit_events
  FOR EACH ROW EXECUTE FUNCTION parimit.reject_evidence_mutation();

CREATE TRIGGER envelope_signing_keys_append_only
  BEFORE UPDATE OR DELETE ON parimit.envelope_signing_keys
  FOR EACH ROW EXECUTE FUNCTION parimit.reject_evidence_mutation();

CREATE TRIGGER envelope_signing_key_registry_state_no_delete
  BEFORE DELETE ON parimit.envelope_signing_key_registry_state
  FOR EACH ROW EXECUTE FUNCTION parimit.reject_evidence_mutation();

CREATE TRIGGER service_integrity_roots_append_only
  BEFORE UPDATE OR DELETE ON parimit.service_integrity_roots
  FOR EACH ROW EXECUTE FUNCTION parimit.reject_evidence_mutation();

CREATE FUNCTION parimit.protect_authorization_envelope()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.consumed_at IS NOT NULL
      OR NEW.consumed_by IS NOT NULL
      OR NEW.consumption_idempotency_key IS NOT NULL
    THEN
      RAISE EXCEPTION 'authorization envelopes must be inserted unconsumed'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'authorization envelopes are retained evidence; DELETE is forbidden'
      USING ERRCODE = '55000';
  END IF;

  IF ROW(
    NEW.id,
    NEW.intent_id,
    NEW.tenant_id,
    NEW.state_version,
    NEW.audience,
    NEW.issuance_idempotency_key,
    NEW.key_id,
    NEW.compact_jws,
    NEW.claims_hash,
    NEW.nonce_hash,
    NEW.issued_at,
    NEW.expires_at
  ) IS DISTINCT FROM ROW(
    OLD.id,
    OLD.intent_id,
    OLD.tenant_id,
    OLD.state_version,
    OLD.audience,
    OLD.issuance_idempotency_key,
    OLD.key_id,
    OLD.compact_jws,
    OLD.claims_hash,
    OLD.nonce_hash,
    OLD.issued_at,
    OLD.expires_at
  ) THEN
    RAISE EXCEPTION 'immutable authorization-envelope evidence cannot be changed'
      USING ERRCODE = '55000';
  END IF;

  IF OLD.consumed_at IS NOT NULL
    OR OLD.consumed_by IS NOT NULL
    OR OLD.consumption_idempotency_key IS NOT NULL
    OR NEW.consumed_at IS NULL
    OR NEW.consumed_by IS NULL
    OR NEW.consumption_idempotency_key IS NULL
  THEN
    RAISE EXCEPTION 'authorization-envelope consumption is a one-time transition'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

CREATE TRIGGER authorization_envelopes_protected
  BEFORE INSERT OR UPDATE OR DELETE ON parimit.authorization_envelopes
  FOR EACH ROW EXECUTE FUNCTION parimit.protect_authorization_envelope();

CREATE FUNCTION parimit.protect_intent()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'intents are retained evidence; DELETE is forbidden'
      USING ERRCODE = '55000';
  END IF;

  IF ROW(
    NEW.id,
    NEW.tenant_id,
    NEW.idempotency_key,
    NEW.request_fingerprint,
    NEW.agent_id,
    NEW.on_behalf_of,
    NEW.amount_minor,
    NEW.currency,
    NEW.payee_reference,
    NEW.purpose,
    NEW.required_approvals,
    NEW.policy_allowed,
    NEW.policy_reasons,
    NEW.rules_version,
    NEW.intent_version,
    NEW.initial_status,
    NEW.intent_hash,
    NEW.created_at,
    NEW.expires_at
  ) IS DISTINCT FROM ROW(
    OLD.id,
    OLD.tenant_id,
    OLD.idempotency_key,
    OLD.request_fingerprint,
    OLD.agent_id,
    OLD.on_behalf_of,
    OLD.amount_minor,
    OLD.currency,
    OLD.payee_reference,
    OLD.purpose,
    OLD.required_approvals,
    OLD.policy_allowed,
    OLD.policy_reasons,
    OLD.rules_version,
    OLD.intent_version,
    OLD.initial_status,
    OLD.intent_hash,
    OLD.created_at,
    OLD.expires_at
  ) THEN
    RAISE EXCEPTION 'immutable intent evidence cannot be changed'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.status = OLD.status THEN
    IF OLD.status <> 'AWAITING_APPROVAL' THEN
      RAISE EXCEPTION 'authorization state cannot advance without a valid transition from %', OLD.status
        USING ERRCODE = '23514';
    END IF;
  ELSIF (
    OLD.status <> 'AWAITING_APPROVAL'
    OR NEW.status NOT IN ('AUTHORIZED_NO_DISPATCH', 'REJECTED', 'CANCELLED', 'EXPIRED')
  ) THEN
    RAISE EXCEPTION 'invalid intent status transition: % -> %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;

  IF NEW.state_version <> OLD.state_version + 1 THEN
    RAISE EXCEPTION 'authorization state version must increment exactly once'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

CREATE TRIGGER intents_protected
  BEFORE UPDATE OR DELETE ON parimit.intents
  FOR EACH ROW EXECUTE FUNCTION parimit.protect_intent();

-- Locking the parent serializes the tail read for every event belonging to an
-- intent. The no-forks constraint remains a backstop if a client races using
-- a stale snapshot. Application verification still recomputes every hash.
CREATE FUNCTION parimit.enforce_audit_append()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  latest_hash text;
BEGIN
  PERFORM id
    FROM parimit.intents
   WHERE id = NEW.intent_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit parent intent does not exist: %', NEW.intent_id
      USING ERRCODE = '23503';
  END IF;

  SELECT event_hash
    INTO latest_hash
    FROM parimit.audit_events
   WHERE intent_id = NEW.intent_id
   ORDER BY sequence DESC
   LIMIT 1;

  IF NEW.previous_hash <> COALESCE(latest_hash, 'GENESIS') THEN
    RAISE EXCEPTION 'audit previous_hash does not match the locked chain tail'
      USING ERRCODE = '40001';
  END IF;

  RETURN NEW;
END;
$function$;

CREATE TRIGGER audit_events_chain_tail
  BEFORE INSERT ON parimit.audit_events
  FOR EACH ROW EXECUTE FUNCTION parimit.enforce_audit_append();

COMMENT ON SCHEMA parimit IS
  'Proposal-only Parimit evidence store; contains no payment execution or provider credential tables.';
COMMENT ON TABLE parimit.policy_subjects IS
  'Stable rows used only for per-agent policy serialization.';
COMMENT ON COLUMN parimit.observations.sequence IS
  'Insertion order replacing SQLite rowid; integrity comparison must order by this column.';

COMMIT;
