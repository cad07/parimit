import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { canonicalJson, sha256 } from "../src/crypto.ts";
import {
  POSTGRES_RUNTIME_SUPPORT,
  PostgresContractError,
  appendAuditEvent,
  lockIntentForMutation,
  lockPolicySubject,
  withConsistentReadTransaction,
  withSerializableWriteTransaction,
  type PostgresClientLike,
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
    if (/SELECT agent_id/.test(text)) return { rows: [{ agent_id: "agent-1" }], rowCount: 1 };
    if (/SELECT id/.test(text)) {
      return { rows: [{ id: "11111111-1111-4111-8111-111111111111" }], rowCount: 1 };
    }
    return { rows: [], rowCount: 1 };
  });
  const transaction = client as PostgresTransactionClient;

  await lockPolicySubject(transaction, "agent-1");
  assert.equal(await lockIntentForMutation(transaction, "11111111-1111-4111-8111-111111111111"), true);

  assert.match(client.calls[0].text, /INSERT INTO parimit[.]policy_subjects/);
  assert.match(client.calls[1].text, /FOR UPDATE/);
  assert.match(client.calls[2].text, /FROM parimit[.]intents[\s\S]*FOR UPDATE/);
  assert.deepEqual(client.calls.map((call) => call.values), [
    ["agent-1"],
    ["agent-1"],
    ["11111111-1111-4111-8111-111111111111"],
  ]);
});

test("audit append locks its intent and reproduces the existing canonical hash", async () => {
  const intentId = "11111111-1111-4111-8111-111111111111";
  const input = {
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

  for (const table of ["policy_subjects", "intents", "approvals", "observations", "audit_events"]) {
    assert.match(migration, new RegExp(`CREATE TABLE parimit[.]${table} \\(`));
  }
  assert.match(migration, /amount_minor BETWEEN 1 AND 9007199254740991/);
  assert.match(migration, /agent_id text NOT NULL REFERENCES parimit[.]policy_subjects\(agent_id\)/);
  assert.match(migration, /currency = 'INR'/);
  assert.match(migration, /AUTHORIZED_NO_DISPATCH/);
  assert.match(migration, /source = 'DEMO_MOCK'/);
  assert.match(migration, /audit_events_no_forks UNIQUE \(intent_id, previous_hash\)/);
  assert.match(migration, /observations_append_only/);
  assert.match(migration, /audit_events_append_only/);
  assert.match(migration, /BEFORE INSERT ON parimit[.]audit_events/);
  assert.match(migration, /FOR UPDATE/);
  assert.match(migration, /invalid intent status transition/);
  assert.match(migration, /contains no payment execution or provider credential tables/);
  assert.doesNotMatch(migration, /CREATE TABLE\s+(?:parimit[.])?(?:payments|executions|transfers)\b/i);

  assert.deepEqual(POSTGRES_RUNTIME_SUPPORT, {
    runtimeSelectable: false,
    schemaAvailable: true,
    transactionContractAvailable: true,
    reason:
      "ParimitService is synchronous and SQLite-specific; an async repository port and live PostgreSQL parity tests are still required.",
  });
});
