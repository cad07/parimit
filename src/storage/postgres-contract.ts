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

/** A checked-out pool client. Passing an error to release discards it. */
export interface PostgresPoolClientLike extends PostgresClientLike {
  release(error?: Error | boolean): void;
}

/** Structurally compatible with the subset of node-postgres Pool we use. */
export interface PostgresPoolLike {
  connect(): Promise<PostgresPoolClientLike>;
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

async function beginTransaction(client: PostgresClientLike, statement: string): Promise<void> {
  try {
    await client.query(statement);
  } catch (error) {
    // A failed BEGIN gives us no trustworthy transaction state. Pool callers
    // recognize AggregateError and destroy this checkout rather than reuse it.
    throw new AggregateError(
      [error],
      "PostgreSQL transaction could not begin; discard this connection",
    );
  }
}

/**
 * Mutations use SERIALIZABLE. Retry policy belongs in the pool adapter so the
 * complete callback can be bounded, observed, and coupled to idempotency.
 */
export async function withSerializableWriteTransaction<T>(
  client: PostgresClientLike,
  work: (transaction: PostgresTransactionClient) => Promise<T>,
): Promise<T> {
  await beginTransaction(client, "BEGIN ISOLATION LEVEL SERIALIZABLE");
  try {
    const result = await work(client as PostgresTransactionClient);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    return rollbackAfterFailure(client, error);
  }
}

export interface SerializableRetryOptions {
  maxAttempts?: number;
  onRetry?: (details: {
    attempt: number;
    nextAttempt: number;
    sqlState: "40001" | "40P01" | "23505";
    constraint?: "audit_events_no_forks";
  }) => void;
}

function sqlState(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) return undefined;
  return typeof error.code === "string" ? error.code : undefined;
}

export function isRetryablePostgresTransactionError(error: unknown): boolean {
  const code = sqlState(error);
  if (code === "40001" || code === "40P01") return true;
  // Two SERIALIZABLE transactions can take their snapshots before the second
  // waits on the parent intent lock. The database's no-forks constraint then
  // reports the stale audit predecessor as this one exact unique violation.
  // It is safe only as a whole-transaction retry, never as a statement retry.
  return (
    code === "23505" &&
    typeof error === "object" &&
    error !== null &&
    "schema" in error &&
    error.schema === "parimit" &&
    "table" in error &&
    error.table === "audit_events" &&
    "constraint" in error &&
    error.constraint === "audit_events_no_forks"
  );
}

/**
 * Acquire a fresh pool checkout for each complete SERIALIZABLE attempt. The
 * pool may return the same physical connection after release, but every attempt
 * begins a new transaction. Retrying an individual statement could combine
 * decisions from different snapshots, so only the whole idempotent transaction
 * is retried.
 */
export async function withSerializablePoolTransaction<T>(
  pool: PostgresPoolLike,
  work: (transaction: PostgresTransactionClient) => Promise<T>,
  options: SerializableRetryOptions = {},
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) {
    throw new RangeError("maxAttempts must be an integer between 1 and 10");
  }

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const client = await pool.connect();
    let discard: Error | undefined;
    try {
      return await withSerializableWriteTransaction(client, work);
    } catch (error) {
      if (error instanceof AggregateError) {
        discard = error;
      }
      if (!isRetryablePostgresTransactionError(error) || attempt === maxAttempts) {
        throw error;
      }
      options.onRetry?.({
        attempt,
        nextAttempt: attempt + 1,
        sqlState: sqlState(error) as "40001" | "40P01" | "23505",
        ...(sqlState(error) === "23505" ? { constraint: "audit_events_no_forks" as const } : {}),
      });
    } finally {
      client.release(discard);
    }
  }

  throw new Error("Unreachable PostgreSQL retry state");
}

/** Integrity verification must see one database snapshot, not mixed commits. */
export async function withConsistentReadTransaction<T>(
  client: PostgresClientLike,
  work: (transaction: PostgresTransactionClient) => Promise<T>,
): Promise<T> {
  await beginTransaction(client, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
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
  tenantId: string,
  agentId: string,
): Promise<void> {
  await transaction.query(
    `INSERT INTO parimit.policy_subjects (tenant_id, agent_id)
     VALUES ($1, $2)
     ON CONFLICT (tenant_id, agent_id) DO NOTHING`,
    [tenantId, agentId],
  );
  const result = await transaction.query<{ tenant_id: string; agent_id: string }>(
    `SELECT tenant_id, agent_id
       FROM parimit.policy_subjects
      WHERE tenant_id = $1 AND agent_id = $2
      FOR UPDATE`,
    [tenantId, agentId],
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
  tenantId: string,
  intentId: string,
): Promise<boolean> {
  const result = await transaction.query<{ id: string }>(
    `SELECT id
      FROM parimit.intents
      WHERE tenant_id = $1 AND id = $2::uuid
      FOR UPDATE`,
    [tenantId, intentId],
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
  tenantId: string;
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
  if (!(await lockIntentForMutation(transaction, input.tenantId, input.intentId))) {
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
 * This is integration-track metadata, not a runtime feature flag.
 * runtimeSelectable must remain false until the complete async service port
 * and live PostgreSQL parity suite land.
 */
export const POSTGRES_RUNTIME_SUPPORT = Object.freeze({
  runtimeSelectable: false,
  schemaAvailable: true,
  transactionContractAvailable: true,
  createReadVerticalSliceAvailable: true,
  liveConcurrencyGateAvailable: true,
  reason:
    "ParimitService is still synchronous and SQLite-specific; approvals, envelopes, observations, integrity parity, operations, and runtime selection remain unported.",
});
