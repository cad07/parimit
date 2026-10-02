-- Runtime-foundation constraints and tenant-prefixed access paths.
-- PostgreSQL remains non-selectable until the complete parity gate passes.

BEGIN;

ALTER TABLE parimit.intents
  ADD CONSTRAINT intents_state_version_safe_integer
  CHECK (state_version BETWEEN 1 AND 9007199254740991);

ALTER TABLE parimit.authorization_envelopes
  ADD CONSTRAINT authorization_envelopes_state_version_safe_integer
  CHECK (state_version BETWEEN 1 AND 9007199254740991);

CREATE INDEX intents_tenant_agent_created_idx
  ON parimit.intents (tenant_id, agent_id, created_at);

CREATE INDEX intents_tenant_status_expiry_idx
  ON parimit.intents (tenant_id, status, expires_at);

-- SELECT ... FOR UPDATE requires the runtime role to hold UPDATE privilege.
-- Keep the lock identity immutable even if that privilege is misused directly.
CREATE TRIGGER policy_subjects_stable
  BEFORE UPDATE OR DELETE ON parimit.policy_subjects
  FOR EACH ROW EXECUTE FUNCTION parimit.reject_evidence_mutation();

COMMENT ON CONSTRAINT intents_state_version_safe_integer ON parimit.intents IS
  'Keeps the current number-valued API representation inside JavaScript safe-integer bounds.';

COMMENT ON CONSTRAINT authorization_envelopes_state_version_safe_integer
  ON parimit.authorization_envelopes IS
  'Keeps the current number-valued API representation inside JavaScript safe-integer bounds.';

COMMIT;
