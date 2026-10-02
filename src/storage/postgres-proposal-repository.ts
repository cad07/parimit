import { safeEqualText } from "../crypto.ts";
import {
  INTENT_STATUSES,
  PAYMENT_INTENT_VERSIONS,
  type InitialIntentStatus,
  type IntentStatus,
  type PaymentIntentVersion,
} from "../types.ts";
import {
  appendAuditEvent,
  lockPolicySubject,
  withConsistentReadTransaction,
  withSerializablePoolTransaction,
  type PostgresClientLike,
  type PostgresPoolLike,
  type SerializableRetryOptions,
} from "./postgres-contract.ts";
import type {
  CreateProposalRequest,
  CreateProposalResult,
  PreparedProposal,
  ProposalRepository,
  StoredIntentRecord,
} from "./repository.ts";

const SHA256_HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type PostgresIntentRow = Record<string, unknown> & {
  id: string;
  tenant_id: string;
  idempotency_key: string;
  request_fingerprint: string;
  agent_id: string;
  on_behalf_of: string | null;
  amount_minor: string;
  currency: string;
  payee_reference: string;
  purpose: string;
  status: string;
  required_approvals: number;
  policy_allowed: boolean;
  policy_reasons: unknown;
  rules_version: string;
  intent_version: string;
  initial_status: string;
  state_version: string;
  intent_hash: string;
  created_at: string;
  expires_at: string;
};

export class PostgresRepositoryError extends Error {
  readonly code:
    | "IDEMPOTENCY_CONFLICT"
    | "INVALID_PREPARED_PROPOSAL"
    | "INVALID_DATABASE_RESULT";

  constructor(
    code: PostgresRepositoryError["code"],
    message: string,
  ) {
    super(message);
    this.name = "PostgresRepositoryError";
    this.code = code;
  }
}

function canonicalTimestamp(value: string): boolean {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function safeIntegerFromDecimal(value: unknown, field: string): number {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
    throw new PostgresRepositoryError(
      "INVALID_DATABASE_RESULT",
      `${field} was not returned as a positive decimal string`,
    );
  }
  const result = Number(value);
  if (!Number.isSafeInteger(result)) {
    throw new PostgresRepositoryError(
      "INVALID_DATABASE_RESULT",
      `${field} exceeds JavaScript's safe integer range`,
    );
  }
  return result;
}

function stringArray(value: unknown, field: string): readonly string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new PostgresRepositoryError(
      "INVALID_DATABASE_RESULT",
      `${field} is not a JSON string array`,
    );
  }
  return Object.freeze([...value]);
}

function isIntentStatus(value: string): value is IntentStatus {
  return (INTENT_STATUSES as readonly string[]).includes(value);
}

function isIntentVersion(value: string): value is PaymentIntentVersion {
  return (PAYMENT_INTENT_VERSIONS as readonly string[]).includes(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function equalsDenseStringArray(value: unknown, expected: readonly string[]): boolean {
  if (!Array.isArray(value) || value.length !== expected.length) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!(index in value) || typeof value[index] !== "string" || value[index] !== expected[index]) {
      return false;
    }
  }
  return true;
}

function deepFreeze(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value !== "object" || value === null || seen.has(value)) return value;
  seen.add(value);
  for (const member of Object.values(value)) deepFreeze(member, seen);
  return Object.freeze(value);
}

function snapshotPreparedProposal(value: PreparedProposal): PreparedProposal {
  try {
    const intent = value.intent;
    const audit = value.audit;
    const policyReasons = Array.isArray(intent.policyReasons)
      ? Object.freeze([...intent.policyReasons])
      : intent.policyReasons;
    const payload = structuredClone(audit.payload);
    if (
      typeof payload !== "object" ||
      payload === null ||
      Array.isArray(payload) ||
      !Array.isArray(policyReasons)
    ) {
      throw new TypeError("Prepared policy reasons or audit payload have an invalid shape");
    }
    return Object.freeze({
      intent: Object.freeze({
        id: intent.id,
        tenantId: intent.tenantId,
        idempotencyKey: intent.idempotencyKey,
        requestFingerprint: intent.requestFingerprint,
        agentId: intent.agentId,
        onBehalfOf: intent.onBehalfOf,
        amountMinor: intent.amountMinor,
        currency: intent.currency,
        payeeReference: intent.payeeReference,
        purpose: intent.purpose,
        status: intent.status,
        requiredApprovals: intent.requiredApprovals,
        policyAllowed: intent.policyAllowed,
        policyReasons,
        rulesVersion: intent.rulesVersion,
        intentVersion: intent.intentVersion,
        initialStatus: intent.initialStatus,
        stateVersion: intent.stateVersion,
        intentHash: intent.intentHash,
        createdAt: intent.createdAt,
        expiresAt: intent.expiresAt,
      }),
      audit: Object.freeze({
        eventType: audit.eventType,
        actorId: audit.actorId,
        payload: deepFreeze(payload) as Readonly<Record<string, unknown>>,
        occurredAt: audit.occurredAt,
      }),
    });
  } catch (error) {
    if (error instanceof PostgresRepositoryError) throw error;
    throw new PostgresRepositoryError(
      "INVALID_PREPARED_PROPOSAL",
      `Prepared proposal could not be snapshotted: ${error instanceof Error ? error.message : "invalid value"}`,
    );
  }
}

function rowToIntent(row: PostgresIntentRow): StoredIntentRecord {
  if (
    typeof row.id !== "string" ||
    typeof row.tenant_id !== "string" ||
    typeof row.idempotency_key !== "string" ||
    typeof row.request_fingerprint !== "string" ||
    typeof row.agent_id !== "string" ||
    (row.on_behalf_of !== null && typeof row.on_behalf_of !== "string") ||
    typeof row.currency !== "string" ||
    typeof row.payee_reference !== "string" ||
    typeof row.purpose !== "string" ||
    typeof row.status !== "string" ||
    typeof row.policy_allowed !== "boolean" ||
    typeof row.rules_version !== "string" ||
    typeof row.intent_version !== "string" ||
    typeof row.initial_status !== "string" ||
    typeof row.state_version !== "string" ||
    typeof row.intent_hash !== "string" ||
    typeof row.created_at !== "string" ||
    typeof row.expires_at !== "string"
  ) {
    throw new PostgresRepositoryError(
      "INVALID_DATABASE_RESULT",
      "PostgreSQL returned an intent with an unexpected scalar type",
    );
  }
  if (
    !UUID.test(row.id) ||
    !SHA256_HEX.test(row.request_fingerprint) ||
    !SHA256_HEX.test(row.intent_hash) ||
    row.currency !== "INR" ||
    !isIntentStatus(row.status) ||
    !isIntentVersion(row.intent_version) ||
    (row.initial_status !== "POLICY_DENIED" && row.initial_status !== "AWAITING_APPROVAL") ||
    (row.required_approvals !== 1 && row.required_approvals !== 2) ||
    !/^[1-9][0-9]*$/.test(row.state_version) ||
    Number(row.state_version) > Number.MAX_SAFE_INTEGER ||
    !canonicalTimestamp(row.created_at) ||
    !canonicalTimestamp(row.expires_at)
  ) {
    throw new PostgresRepositoryError(
      "INVALID_DATABASE_RESULT",
      "PostgreSQL returned an intent outside the repository contract",
    );
  }
  return Object.freeze({
    id: row.id,
    tenantId: row.tenant_id,
    idempotencyKey: row.idempotency_key,
    requestFingerprint: row.request_fingerprint,
    agentId: row.agent_id,
    onBehalfOf: row.on_behalf_of,
    amountMinor: safeIntegerFromDecimal(row.amount_minor, "amount_minor"),
    currency: "INR",
    payeeReference: row.payee_reference,
    purpose: row.purpose,
    status: row.status,
    requiredApprovals: row.required_approvals,
    policyAllowed: row.policy_allowed,
    policyReasons: stringArray(row.policy_reasons, "policy_reasons"),
    rulesVersion: row.rules_version,
    intentVersion: row.intent_version,
    initialStatus: row.initial_status as InitialIntentStatus,
    stateVersion: row.state_version,
    intentHash: row.intent_hash,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  });
}

function assertPreparedProposal(
  request: CreateProposalRequest,
  prepared: PreparedProposal,
  currentDailyExposureMinor: number,
): void {
  const intent = prepared.intent;
  const expectedEvent = intent.policyAllowed ? "PROPOSAL_CREATED" : "PROPOSAL_POLICY_DENIED";
  const payload = prepared.audit.payload;
  const policy = isPlainRecord(payload) && isPlainRecord(payload.policy) ? payload.policy : null;
  const nextPolicyDay = new Date(
    Date.parse(request.policyDayStartsAt) + 24 * 60 * 60 * 1_000,
  ).toISOString();
  const projectedDailyExposureMinor = currentDailyExposureMinor + intent.amountMinor;
  if (
    !UUID.test(intent.id) ||
    intent.tenantId !== request.tenantId ||
    intent.agentId !== request.agentId ||
    intent.idempotencyKey !== request.idempotencyKey ||
    !safeEqualText(intent.requestFingerprint, request.requestFingerprint) ||
    intent.currency !== "INR" ||
    intent.intentVersion !== "parimit-payment-intent-v3" ||
    intent.stateVersion !== "1" ||
    intent.status !== intent.initialStatus ||
    intent.policyAllowed !== (intent.initialStatus === "AWAITING_APPROVAL") ||
    !Number.isSafeInteger(intent.amountMinor) ||
    intent.amountMinor < 1 ||
    (intent.requiredApprovals !== 1 && intent.requiredApprovals !== 2) ||
    !Array.isArray(intent.policyReasons) ||
    !intent.policyReasons.every((reason) => typeof reason === "string") ||
    !SHA256_HEX.test(intent.requestFingerprint) ||
    !SHA256_HEX.test(intent.intentHash) ||
    !canonicalTimestamp(intent.createdAt) ||
    !canonicalTimestamp(intent.expiresAt) ||
    intent.createdAt < request.policyDayStartsAt ||
    intent.createdAt >= nextPolicyDay ||
    intent.expiresAt <= intent.createdAt ||
    prepared.audit.eventType !== expectedEvent ||
    prepared.audit.actorId !== request.agentId ||
    !canonicalTimestamp(prepared.audit.occurredAt) ||
    prepared.audit.occurredAt !== intent.createdAt ||
    !isPlainRecord(payload) ||
    payload.intent_hash !== intent.intentHash ||
    payload.tenant_id !== request.tenantId ||
    payload.state_version !== 1 ||
    payload.status !== intent.initialStatus ||
    payload.boundary !== "PROPOSAL_ONLY_NO_VALUE_MOVEMENT" ||
    !policy ||
    policy.allowed !== intent.policyAllowed ||
    !equalsDenseStringArray(policy.reasons, intent.policyReasons) ||
    policy.rules_version !== intent.rulesVersion ||
    policy.config_digest !== request.policyConfigurationDigest ||
    policy.required_approvals !== intent.requiredApprovals ||
    policy.current_daily_exposure_minor !== String(currentDailyExposureMinor) ||
    !Number.isSafeInteger(projectedDailyExposureMinor) ||
    policy.projected_daily_exposure_minor !== String(projectedDailyExposureMinor)
  ) {
    throw new PostgresRepositoryError(
      "INVALID_PREPARED_PROPOSAL",
      "Prepared proposal does not match its locked creation request",
    );
  }
}

const INTENT_COLUMNS = `
  id::text AS id,
  tenant_id,
  idempotency_key,
  request_fingerprint::text AS request_fingerprint,
  agent_id,
  on_behalf_of,
  amount_minor::text AS amount_minor,
  currency,
  payee_reference,
  purpose,
  status,
  required_approvals::integer AS required_approvals,
  policy_allowed,
  policy_reasons,
  rules_version,
  intent_version,
  initial_status,
  state_version::text AS state_version,
  intent_hash::text AS intent_hash,
  created_at::text AS created_at,
  expires_at::text AS expires_at`;

async function selectIntent(
  client: PostgresClientLike,
  tenantId: string,
  intentId: string,
): Promise<StoredIntentRecord | null> {
  const result = await client.query<PostgresIntentRow>(
    `SELECT ${INTENT_COLUMNS}
       FROM parimit.intents
      WHERE tenant_id = $1 AND id = $2::uuid`,
    [tenantId, intentId],
  );
  if (result.rows.length === 0 && result.rowCount === 0) return null;
  if (result.rows.length !== 1 || (result.rowCount !== null && result.rowCount !== 1)) {
    throw new PostgresRepositoryError(
      "INVALID_DATABASE_RESULT",
      "Intent lookup returned an unexpected number of rows",
    );
  }
  return rowToIntent(result.rows[0]);
}

export class PostgresProposalRepository implements ProposalRepository {
  readonly #pool: PostgresPoolLike;
  readonly #retryOptions: SerializableRetryOptions;

  constructor(pool: PostgresPoolLike, retryOptions: SerializableRetryOptions = {}) {
    this.#pool = pool;
    this.#retryOptions = retryOptions;
  }

  async createOrReplay(request: CreateProposalRequest): Promise<CreateProposalResult> {
    const requestSnapshot = Object.freeze({
      tenantId: request.tenantId,
      agentId: request.agentId,
      idempotencyKey: request.idempotencyKey,
      requestFingerprint: request.requestFingerprint,
      policyConfigurationDigest: request.policyConfigurationDigest,
      policyDayStartsAt: request.policyDayStartsAt,
      prepare: request.prepare,
    });
    if (
      !SHA256_HEX.test(requestSnapshot.requestFingerprint) ||
      !SHA256_HEX.test(requestSnapshot.policyConfigurationDigest) ||
      !canonicalTimestamp(requestSnapshot.policyDayStartsAt) ||
      !requestSnapshot.policyDayStartsAt.endsWith("T00:00:00.000Z")
    ) {
      throw new PostgresRepositoryError(
        "INVALID_PREPARED_PROPOSAL",
        "Creation request has an invalid fingerprint or policy-day timestamp",
      );
    }

    const nextPolicyDay = new Date(
      Date.parse(requestSnapshot.policyDayStartsAt) + 24 * 60 * 60 * 1_000,
    ).toISOString();

    return withSerializablePoolTransaction(
      this.#pool,
      async (transaction) => {
        await lockPolicySubject(transaction, requestSnapshot.tenantId, requestSnapshot.agentId);

        const replay = await transaction.query<{
          id: string;
          request_fingerprint: string;
        }>(
          `SELECT id::text AS id, request_fingerprint::text AS request_fingerprint
             FROM parimit.intents
            WHERE tenant_id = $1 AND agent_id = $2 AND idempotency_key = $3`,
          [requestSnapshot.tenantId, requestSnapshot.agentId, requestSnapshot.idempotencyKey],
        );
        if (replay.rows.length > 1 || (replay.rowCount !== null && replay.rowCount !== replay.rows.length)) {
          throw new PostgresRepositoryError(
            "INVALID_DATABASE_RESULT",
            "Idempotency lookup returned an inconsistent result",
          );
        }
        if (replay.rows.length === 1) {
          const existing = replay.rows[0];
          if (!safeEqualText(existing.request_fingerprint, requestSnapshot.requestFingerprint)) {
            throw new PostgresRepositoryError(
              "IDEMPOTENCY_CONFLICT",
              "This agent already used the idempotency key for a different proposal",
            );
          }
          const intent = await selectIntent(transaction, requestSnapshot.tenantId, existing.id);
          if (intent === null) {
            throw new PostgresRepositoryError(
              "INVALID_DATABASE_RESULT",
              "Idempotency lookup referenced a missing intent",
            );
          }
          return { intent, idempotentReplay: true, auditSequence: null };
        }

        const exposureResult = await transaction.query<{ exposure: string }>(
          `SELECT COALESCE(SUM(amount_minor), 0)::text AS exposure
             FROM parimit.intents
            WHERE tenant_id = $1
              AND agent_id = $2
              AND created_at >= $3
              AND created_at < $4
              AND policy_allowed = true
              AND status IN ('AWAITING_APPROVAL', 'AUTHORIZED_NO_DISPATCH')`,
          [
            requestSnapshot.tenantId,
            requestSnapshot.agentId,
            requestSnapshot.policyDayStartsAt,
            nextPolicyDay,
          ],
        );
        if (
          exposureResult.rows.length !== 1 ||
          (exposureResult.rowCount !== null && exposureResult.rowCount !== 1)
        ) {
          throw new PostgresRepositoryError(
            "INVALID_DATABASE_RESULT",
            "Daily-exposure query returned an unexpected result",
          );
        }
        const exposureText = exposureResult.rows[0]?.exposure;
        const currentDailyExposureMinor =
          exposureText === "0" ? 0 : safeIntegerFromDecimal(exposureText, "daily exposure");
        const prepared = snapshotPreparedProposal(
          await requestSnapshot.prepare({ currentDailyExposureMinor }),
        );
        assertPreparedProposal(requestSnapshot, prepared, currentDailyExposureMinor);
        const intent = prepared.intent;

        const inserted = await transaction.query(
          `INSERT INTO parimit.intents
            (id, tenant_id, idempotency_key, request_fingerprint, agent_id, on_behalf_of,
             amount_minor, currency, payee_reference, purpose, status, required_approvals,
             policy_allowed, policy_reasons, rules_version, intent_version, initial_status,
             state_version, intent_hash, created_at, expires_at)
           VALUES
            ($1::uuid, $2, $3, $4, $5, $6, $7, 'INR', $8, $9, $10, $11,
             $12, $13::jsonb, $14, $15, $16, 1, $17, $18, $19)`,
          [
            intent.id,
            intent.tenantId,
            intent.idempotencyKey,
            intent.requestFingerprint,
            intent.agentId,
            intent.onBehalfOf,
            String(intent.amountMinor),
            intent.payeeReference,
            intent.purpose,
            intent.status,
            intent.requiredApprovals,
            intent.policyAllowed,
            JSON.stringify(intent.policyReasons),
            intent.rulesVersion,
            intent.intentVersion,
            intent.initialStatus,
            intent.intentHash,
            intent.createdAt,
            intent.expiresAt,
          ],
        );
        if (inserted.rowCount !== 1) {
          throw new PostgresRepositoryError(
            "INVALID_DATABASE_RESULT",
            "Proposal insert did not affect exactly one row",
          );
        }

        const audit = await appendAuditEvent(transaction, {
          tenantId: intent.tenantId,
          intentId: intent.id,
          eventType: prepared.audit.eventType,
          actorId: prepared.audit.actorId,
          payload: prepared.audit.payload,
          occurredAt: prepared.audit.occurredAt,
        });
        const stored = await selectIntent(transaction, intent.tenantId, intent.id);
        if (stored === null) {
          throw new PostgresRepositoryError(
            "INVALID_DATABASE_RESULT",
            "Newly inserted proposal could not be read back",
          );
        }
        return { intent: stored, idempotentReplay: false, auditSequence: audit.sequence };
      },
      this.#retryOptions,
    );
  }

  async readIntent(tenantId: string, intentId: string): Promise<StoredIntentRecord | null> {
    const client = await this.#pool.connect();
    let discard: Error | undefined;
    try {
      return await withConsistentReadTransaction(client, (transaction) =>
        selectIntent(transaction, tenantId, intentId),
      );
    } catch (error) {
      if (error instanceof AggregateError) discard = error;
      throw error;
    } finally {
      client.release(discard);
    }
  }
}
