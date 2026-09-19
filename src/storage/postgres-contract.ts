import { canonicalJson, sha256 } from "../crypto.ts";

export type PostgresValue = string | number | boolean | null;

export interface PostgresQueryResult<Row> {
  rows: Row[];
  rowCount: number | null;
}

/**
 * The deliberately small surface Parimit needs from a PostgreSQL driver.
 * It is structurally compatible with a checked-out node-postgres client, but
 * this module does not add a driver or switch the alpha runtime to PostgreSQL.
 */
export interface PostgresClientLike {
  query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: readonly PostgresValue[],
  ): Promise<PostgresQueryResult<Row>>;
}

declare const transactionClient: unique symbol;

/** A client that is known to be inside one of this module's transactions. */
export type PostgresTransactionClient = PostgresClientLike & {
  readonly [transactionClient]: true;
};

export class PostgresContractError extends Error {
  readonly code: "INTENT_NOT_FOUND" | "INVALID_DATABASE_RESULT";

  constructor(code: "INTENT_NOT_FOUND" | "INVALID_DATABASE_RESULT", message: string) {
    super(message);
    this.name = "PostgresContractError";
    this.code = code;
  }
}

async function rollbackAfterFailure(client: PostgresClientLike, originalError: unknown): Promise<never> {
  try {
    await client.query("ROLLBACK");
  } catch (rollbackError) {
    throw new AggregateError(
      [originalError, rollbackError],
      "PostgreSQL transaction failed and rollback also failed; discard this connection",
    );
  }
  throw originalError;
}

/**
 * Mutations use SERIALIZABLE and must retry the entire callback after SQLSTATE
 * 40001 or 40P01. A retry belongs in the eventual edge adapter so it can be
 * bounded, observed, and coupled to request idempotency.
 */
export async function withSerializableWriteTransaction<T>(
  client: PostgresClientLike,
  work: (transaction: PostgresTransactionClient) => Promise<T>,
): Promise<T> {
  await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
  try {
    const result = await work(client as PostgresTransactionClient);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    return rollbackAfterFailure(client, error);
  }
}

/** Integrity verification must see one database snapshot, not mixed commits. */
export async function withConsistentReadTransaction<T>(
  client: PostgresClientLike,
  work: (transaction: PostgresTransactionClient) => Promise<T>,
): Promise<T> {
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  try {
    const result = await work(client as PostgresTransactionClient);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    return rollbackAfterFailure(client, error);
  }
}

/**
 * Serialize policy evaluation and proposal creation for one agent so two
 * concurrent requests cannot both pass the daily-exposure limit.
 */
export async function lockPolicySubject(
  transaction: PostgresTransactionClient,
  agentId: string,
): Promise<void> {
  await transaction.query(
    `INSERT INTO parimit.policy_subjects (agent_id)
     VALUES ($1)
     ON CONFLICT (agent_id) DO NOTHING`,
    [agentId],
  );
  const result = await transaction.query<{ agent_id: string }>(
    `SELECT agent_id
       FROM parimit.policy_subjects
      WHERE agent_id = $1
      FOR UPDATE`,
    [agentId],
  );
  if (result.rowCount !== 1 || result.rows.length !== 1) {
    throw new PostgresContractError(
      "INVALID_DATABASE_RESULT",
      "Failed to acquire the per-agent policy lock",
    );
  }
}

/** Lock before integrity verification and every state-affecting mutation. */
export async function lockIntentForMutation(
  transaction: PostgresTransactionClient,
  intentId: string,
): Promise<boolean> {
  const result = await transaction.query<{ id: string }>(
    `SELECT id
       FROM parimit.intents
      WHERE id = $1::uuid
      FOR UPDATE`,
    [intentId],
  );
  if (result.rowCount === 0 && result.rows.length === 0) return false;
  if (result.rowCount !== 1 || result.rows.length !== 1) {
    throw new PostgresContractError(
      "INVALID_DATABASE_RESULT",
      "Intent lock returned an unexpected number of rows",
    );
  }
  return true;
}

export interface PostgresAuditAppendInput {
  intentId: string;
  eventType: string;
  actorId: string;
  payload: unknown;
  occurredAt: string;
}

export interface PostgresAuditAppendResult {
  /** Kept as text because PostgreSQL BIGINT can exceed JavaScript's safe range. */
  sequence: string;
  previousHash: string;
  eventHash: string;
}

/**
 * Append one event while holding the parent intent lock. The migration also
 * rejects audit forks and all updates/deletes as defence in depth.
 */
export async function appendAuditEvent(
  transaction: PostgresTransactionClient,
  input: PostgresAuditAppendInput,
): Promise<PostgresAuditAppendResult> {
  if (!(await lockIntentForMutation(transaction, input.intentId))) {
    throw new PostgresContractError("INTENT_NOT_FOUND", "Payment proposal not found");
  }

  const tail = await transaction.query<{ event_hash: string }>(
    `SELECT event_hash
       FROM parimit.audit_events
      WHERE intent_id = $1::uuid
      ORDER BY sequence DESC
      LIMIT 1`,
    [input.intentId],
  );
  if (tail.rows.length > 1 || (tail.rowCount !== null && tail.rowCount !== tail.rows.length)) {
    throw new PostgresContractError(
      "INVALID_DATABASE_RESULT",
      "Audit-tail query returned an inconsistent result",
    );
  }
  const previousHash = tail.rows[0]?.event_hash ?? "GENESIS";
  const normalizedPayload = canonicalJson(input.payload);
  const eventHash = sha256(
    canonicalJson({
      intent_id: input.intentId,
      event_type: input.eventType,
      actor_id: input.actorId,
      payload: JSON.parse(normalizedPayload) as unknown,
      occurred_at: input.occurredAt,
      previous_hash: previousHash,
    }),
  );

  const inserted = await transaction.query<{ sequence: string }>(
    `INSERT INTO parimit.audit_events
       (intent_id, event_type, actor_id, payload, occurred_at, previous_hash, event_hash)
     VALUES ($1::uuid, $2, $3, $4::jsonb, $5, $6, $7)
     RETURNING sequence::text AS sequence`,
    [
      input.intentId,
      input.eventType,
      input.actorId,
      normalizedPayload,
      input.occurredAt,
      previousHash,
      eventHash,
    ],
  );
  const sequence = inserted.rows[0]?.sequence;
  if (inserted.rowCount !== 1 || inserted.rows.length !== 1 || typeof sequence !== "string") {
    throw new PostgresContractError(
      "INVALID_DATABASE_RESULT",
      "Audit append did not return exactly one sequence",
    );
  }
  return { sequence, previousHash, eventHash };
}

/**
 * This is an integration track, not a runtime feature flag. It becomes true
 * only after the async service port and live PostgreSQL parity suite land.
 */
export const POSTGRES_RUNTIME_SUPPORT = Object.freeze({
  runtimeSelectable: false,
  schemaAvailable: true,
  transactionContractAvailable: true,
  reason:
    "ParimitService is synchronous and SQLite-specific; an async repository port and live PostgreSQL parity tests are still required.",
});
