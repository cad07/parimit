import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { canonicalJson, sha256 } from "../src/crypto.ts";
import {
  POSTGRES_RUNTIME_SUPPORT,
  PostgresContractError,
  appendAuditEvent,
  isRetryablePostgresTransactionError,
  lockIntentForMutation,
  lockPolicySubject,
  withConsistentReadTransaction,
  withSerializablePoolTransaction,
  withSerializableWriteTransaction,
  type PostgresClientLike,
  type PostgresPoolClientLike,
  type PostgresPoolLike,
  type PostgresQueryResult,
  type PostgresTransactionClient,
  type PostgresValue,
} from "../src/storage/postgres-contract.ts";

interface QueryCall {
  text: string;
  values: readonly PostgresValue[];
}

type QueryHandler = (
  text: string,
  values: readonly PostgresValue[],
  callNumber: number,
) => PostgresQueryResult<Record<string, unknown>> | Promise<PostgresQueryResult<Record<string, unknown>>>;

class FakePostgresClient implements PostgresClientLike {
  readonly calls: QueryCall[] = [];
  private readonly handler: QueryHandler;

  constructor(handler: QueryHandler = () => ({ rows: [], rowCount: 0 })) {
    this.handler = handler;
  }

  async query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values: readonly PostgresValue[] = [],
  ): Promise<PostgresQueryResult<Row>> {
    this.calls.push({ text, values });
    return (await this.handler(text, values, this.calls.length)) as PostgresQueryResult<Row>;
  }
}

class FakePoolClient extends FakePostgresClient implements PostgresPoolClientLike {
  readonly releases: Array<Error | boolean | undefined> = [];

  release(error?: Error | boolean): void {
    this.releases.push(error);
  }
}

class FakePool implements PostgresPoolLike {
  readonly clients: FakePoolClient[] = [];
  private readonly createClient: (attempt: number) => FakePoolClient;

  constructor(createClient: (attempt: number) => FakePoolClient) {
    this.createClient = createClient;
  }

  async connect(): Promise<FakePoolClient> {
    const client = this.createClient(this.clients.length + 1);
    this.clients.push(client);
    return client;
  }
}

test("PostgreSQL write transactions are serializable and atomic", async () => {
  const success = new FakePostgresClient();
  const value = await withSerializableWriteTransaction(success, async (transaction) => {
    await transaction.query("SELECT 1");
    return "committed";
  });
  assert.equal(value, "committed");
  assert.deepEqual(
    success.calls.map((call) => call.text),
    ["BEGIN ISOLATION LEVEL SERIALIZABLE", "SELECT 1", "COMMIT"],
  );

  const failure = new FakePostgresClient();
  const sentinel = new Error("mutation failed");
  await assert.rejects(
    withSerializableWriteTransaction(failure, async () => {
      throw sentinel;
    }),
    (error: unknown) => error === sentinel,
  );
  assert.deepEqual(
    failure.calls.map((call) => call.text),
    ["BEGIN ISOLATION LEVEL SERIALIZABLE", "ROLLBACK"],
  );
});

test("pool transaction retries the complete unit with a fresh checkout and transaction", async () => {
  const retries: Array<{
    attempt: number;
    nextAttempt: number;
    sqlState: string;
    constraint?: string;
  }> = [];
  const pool = new FakePool((attempt) =>
    new FakePoolClient((text) => {
      if (text === "SELECT mutation" && attempt < 3) {
        const error = Object.assign(new Error("serialization conflict"), {
          code: attempt === 1 ? "40001" : "40P01",
        });
        throw error;
      }
      return { rows: [], rowCount: 0 };
    }),
  );

  const result = await withSerializablePoolTransaction(
    pool,
    async (transaction) => {
      await transaction.query("SELECT mutation");
      return "committed";
    },
    { maxAttempts: 3, onRetry: (details) => retries.push(details) },
  );

  assert.equal(result, "committed");
  assert.equal(pool.clients.length, 3);
  assert.deepEqual(
    pool.clients.map((client) => client.calls.map((call) => call.text)),
    [
      ["BEGIN ISOLATION LEVEL SERIALIZABLE", "SELECT mutation", "ROLLBACK"],
      ["BEGIN ISOLATION LEVEL SERIALIZABLE", "SELECT mutation", "ROLLBACK"],
      ["BEGIN ISOLATION LEVEL SERIALIZABLE", "SELECT mutation", "COMMIT"],
    ],
  );
  assert.deepEqual(retries, [
    { attempt: 1, nextAttempt: 2, sqlState: "40001" },
    { attempt: 2, nextAttempt: 3, sqlState: "40P01" },
  ]);
  assert.deepEqual(pool.clients.map((client) => client.releases), [[undefined], [undefined], [undefined]]);
});

test("pool transaction never retries non-transaction errors or beyond the bound", async () => {
  assert.equal(isRetryablePostgresTransactionError({ code: "40001" }), true);
  assert.equal(isRetryablePostgresTransactionError({ code: "40P01" }), true);
  assert.equal(isRetryablePostgresTransactionError({ code: "23505" }), false);
  assert.equal(
    isRetryablePostgresTransactionError({
      code: "23505",
      schema: "parimit",
      table: "audit_events",
      constraint: "audit_events_no_forks",
    }),
    true,
  );
  assert.equal(
    isRetryablePostgresTransactionError({ code: "23505", constraint: "another_unique" }),
    false,
  );
  assert.equal(
    isRetryablePostgresTransactionError({
      code: "23505",
      schema: "untrusted",
      table: "audit_events",
      constraint: "audit_events_no_forks",
    }),
    false,
  );

  const nonRetryable = Object.assign(new Error("unique violation"), { code: "23505" });
  const firstPool = new FakePool(() =>
    new FakePoolClient((text) => {
      if (text === "SELECT mutation") throw nonRetryable;
      return { rows: [], rowCount: 0 };
    }),
  );
  await assert.rejects(
    withSerializablePoolTransaction(firstPool, async (transaction) => {
      await transaction.query("SELECT mutation");
    }),
    (error: unknown) => error === nonRetryable,
  );
  assert.equal(firstPool.clients.length, 1);

  const retryable = Object.assign(new Error("serialization conflict"), { code: "40001" });
  const boundedPool = new FakePool(() =>
    new FakePoolClient((text) => {
      if (text === "SELECT mutation") throw retryable;
      return { rows: [], rowCount: 0 };
    }),
  );
  await assert.rejects(
    withSerializablePoolTransaction(
      boundedPool,
      async (transaction) => {
        await transaction.query("SELECT mutation");
      },
      { maxAttempts: 2 },
    ),
    (error: unknown) => error === retryable,
  );
  assert.equal(boundedPool.clients.length, 2);
  await assert.rejects(
    withSerializablePoolTransaction(boundedPool, async () => undefined, { maxAttempts: 0 }),
    /maxAttempts/,
  );
});

test("a failed BEGIN discards the pool checkout without attempting unsafe work", async () => {
  const beginFailure = Object.assign(new Error("begin failed"), { code: "08006" });
  const pool = new FakePool(
    () =>
      new FakePoolClient((text) => {
        if (text === "BEGIN ISOLATION LEVEL SERIALIZABLE") throw beginFailure;
        return { rows: [], rowCount: 0 };
      }),
  );
  let workCalled = false;
  await assert.rejects(
    withSerializablePoolTransaction(pool, async () => {
      workCalled = true;
    }),
    (error: unknown) =>
      error instanceof AggregateError &&
      error.errors.length === 1 &&
      error.errors[0] === beginFailure,
  );
  assert.equal(workCalled, false);
  assert.equal(pool.clients.length, 1);
  assert.deepEqual(
    pool.clients[0].calls.map((call) => call.text),
    ["BEGIN ISOLATION LEVEL SERIALIZABLE"],
  );
  assert.equal(pool.clients[0].releases.length, 1);
  assert.ok(pool.clients[0].releases[0] instanceof AggregateError);

  const readClient = new FakePostgresClient((text) => {
    if (text === "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY") throw beginFailure;
    return { rows: [], rowCount: 0 };
  });
  await assert.rejects(
    withConsistentReadTransaction(readClient, async () => {
      workCalled = true;
    }),
    (error: unknown) => error instanceof AggregateError && error.errors[0] === beginFailure,
  );
  assert.equal(workCalled, false);
  assert.deepEqual(
    readClient.calls.map((call) => call.text),
    ["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"],
  );
});

test("PostgreSQL integrity reads use one repeatable read-only snapshot", async () => {
  const client = new FakePostgresClient();
  await withConsistentReadTransaction(client, async (transaction) => {
    await transaction.query("SELECT * FROM parimit.intents");
  });
  assert.deepEqual(
    client.calls.map((call) => call.text),
    [
      "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
      "SELECT * FROM parimit.intents",
      "COMMIT",
    ],
  );
});

test("policy and intent locks use stable database rows", async () => {
  const client = new FakePostgresClient((text) => {
    if (/SELECT tenant_id, agent_id/.test(text)) {
      return { rows: [{ tenant_id: "tenant-1", agent_id: "agent-1" }], rowCount: 1 };
    }
    if (/SELECT id/.test(text)) {
      return { rows: [{ id: "11111111-1111-4111-8111-111111111111" }], rowCount: 1 };
    }
    return { rows: [], rowCount: 1 };
  });
  const transaction = client as PostgresTransactionClient;

  await lockPolicySubject(transaction, "tenant-1", "agent-1");
  assert.equal(
    await lockIntentForMutation(
      transaction,
      "tenant-1",
      "11111111-1111-4111-8111-111111111111",
    ),
    true,
  );

  assert.match(client.calls[0].text, /INSERT INTO parimit[.]policy_subjects/);
  assert.match(client.calls[1].text, /FOR UPDATE/);
  assert.match(client.calls[2].text, /FROM parimit[.]intents[\s\S]*FOR UPDATE/);
  assert.deepEqual(client.calls.map((call) => call.values), [
    ["tenant-1", "agent-1"],
    ["tenant-1", "agent-1"],
    ["tenant-1", "11111111-1111-4111-8111-111111111111"],
  ]);
});

test("audit append locks its intent and reproduces the existing canonical hash", async () => {
  const intentId = "11111111-1111-4111-8111-111111111111";
  const input = {
    tenantId: "tenant-1",
    intentId,
    eventType: "PROPOSAL_CREATED",
    actorId: "agent-1",
    payload: { status: "AWAITING_APPROVAL", boundary: "PROPOSAL_ONLY_NO_VALUE_MOVEMENT" },
    occurredAt: "2026-09-19T10:00:00.000Z",
  };
  const client = new FakePostgresClient((text) => {
    if (/FROM parimit[.]intents/.test(text)) return { rows: [{ id: intentId }], rowCount: 1 };
    if (/FROM parimit[.]audit_events/.test(text)) return { rows: [], rowCount: 0 };
    if (/INSERT INTO parimit[.]audit_events/.test(text)) {
      return { rows: [{ sequence: "9007199254740992" }], rowCount: 1 };
    }
    throw new Error(`Unexpected query: ${text}`);
  });

  const result = await appendAuditEvent(client as PostgresTransactionClient, input);
  const expectedHash = sha256(
    canonicalJson({
      intent_id: intentId,
      event_type: input.eventType,
      actor_id: input.actorId,
      payload: input.payload,
      occurred_at: input.occurredAt,
      previous_hash: "GENESIS",
    }),
  );

  assert.deepEqual(result, {
    sequence: "9007199254740992",
    previousHash: "GENESIS",
    eventHash: expectedHash,
  });
  assert.match(client.calls[0].text, /FOR UPDATE/);
  assert.match(client.calls[1].text, /ORDER BY sequence DESC/);
  assert.match(client.calls[2].text, /RETURNING sequence::text/);
  assert.equal(client.calls[2].values[3], canonicalJson(input.payload));
  assert.equal(client.calls[2].values[5], "GENESIS");
  assert.equal(client.calls[2].values[6], expectedHash);
});

test("audit append fails closed when the parent intent is absent", async () => {
  const client = new FakePostgresClient(() => ({ rows: [], rowCount: 0 }));
  await assert.rejects(
    appendAuditEvent(client as PostgresTransactionClient, {
      tenantId: "tenant-1",
      intentId: "11111111-1111-4111-8111-111111111111",
      eventType: "PROPOSAL_CREATED",
      actorId: "agent-1",
      payload: {},
      occurredAt: "2026-09-19T10:00:00.000Z",
    }),
    (error: unknown) =>
      error instanceof PostgresContractError && error.code === "INTENT_NOT_FOUND",
  );
  assert.equal(client.calls.length, 1);
});

test("PostgreSQL migration preserves evidence and proposal-only invariants", () => {
  const migration = readFileSync(
    new URL("../db/postgres/001_initial.sql", import.meta.url),
    "utf8",
  );

  for (const table of [
    "policy_subjects",
    "intents",
    "approvals",
    "observations",
    "audit_events",
    "envelope_signing_keys",
    "envelope_signing_key_registry_state",
    "service_integrity_roots",
    "authorization_envelopes",
  ]) {
    assert.match(migration, new RegExp(`CREATE TABLE parimit[.]${table} \\(`));
  }
  assert.match(migration, /amount_minor BETWEEN 1 AND 9007199254740991/);
  assert.match(migration, /FOREIGN KEY \(tenant_id, agent_id\)/);
  assert.match(migration, /UNIQUE \(tenant_id, agent_id, idempotency_key\)/);
  assert.match(migration, /currency = 'INR'/);
  assert.match(migration, /AUTHORIZED_NO_DISPATCH/);
  assert.match(migration, /source = 'DEMO_MOCK'/);
  assert.match(migration, /audit_events_no_forks UNIQUE \(intent_id, previous_hash\)/);
  assert.match(migration, /observations_append_only/);
  assert.match(migration, /audit_events_append_only/);
  assert.match(migration, /BEFORE INSERT ON parimit[.]audit_events/);
  assert.match(migration, /FOR UPDATE/);
  assert.match(migration, /invalid intent status transition/);
  assert.match(migration, /authorization state cannot advance without a valid transition/);
  assert.match(migration, /authorization state version must increment exactly once/);
  assert.match(migration, /name = 'receipt_integrity_root_v1'/);
  assert.match(migration, /service_integrity_roots_append_only/);
  assert.match(migration, /name = 'envelope_signing_key_registry_state_v1'/);
  assert.match(migration, /envelope_signing_key_registry_state_no_delete/);
  assert.match(migration, /authorization envelopes must be inserted unconsumed/);
  assert.match(
    migration,
    /BEFORE INSERT OR UPDATE OR DELETE ON parimit[.]authorization_envelopes/,
  );
  assert.match(migration, /authorization-envelope consumption is a one-time transition/);
  assert.match(migration, /consumed_at >= issued_at[\s\S]*consumed_at < expires_at/);
  assert.match(
    migration,
    /OLD[.]consumed_at IS NOT NULL[\s\S]*OLD[.]consumed_by IS NOT NULL[\s\S]*OLD[.]consumption_idempotency_key IS NOT NULL[\s\S]*NEW[.]consumed_at IS NULL[\s\S]*NEW[.]consumed_by IS NULL[\s\S]*NEW[.]consumption_idempotency_key IS NULL/,
  );
  assert.match(migration, /authorization_envelope_nonce_unique UNIQUE \(tenant_id, nonce_hash\)/);
  assert.match(
    migration,
    /FOREIGN KEY \(tenant_id, intent_id\)[\s\S]*REFERENCES parimit[.]intents\(tenant_id, id\)/,
  );
  assert.match(migration, /contains no payment execution or provider credential tables/);
  assert.doesNotMatch(migration, /CREATE TABLE\s+(?:parimit[.])?(?:payments|executions|transfers)\b/i);

  assert.deepEqual(POSTGRES_RUNTIME_SUPPORT, {
    runtimeSelectable: false,
    schemaAvailable: true,
    transactionContractAvailable: true,
    createReadVerticalSliceAvailable: true,
    liveConcurrencyGateAvailable: true,
    reason:
      "ParimitService is still synchronous and SQLite-specific; approvals, envelopes, observations, integrity parity, operations, and runtime selection remain unported.",
  });
});
