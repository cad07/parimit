import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { canonicalJson, sha256 } from "../src/crypto.ts";
import { currentPaymentIntentPayload } from "../src/intent-payload.ts";
import {
  appendAuditEvent,
  withSerializablePoolTransaction,
} from "../src/storage/postgres-contract.ts";
import {
  PostgresProposalRepository,
  PostgresRepositoryError,
} from "../src/storage/postgres-proposal-repository.ts";
import type {
  PostgresPoolClientLike,
  PostgresPoolLike,
  PostgresQueryResult,
  PostgresValue,
} from "../src/storage/postgres-contract.ts";
import type {
  CreateProposalRequest,
  PreparedProposal,
} from "../src/storage/repository.ts";

const databaseUrl = process.env.PARIMIT_TEST_POSTGRES_URL;
const destructiveOptIn = process.env.PARIMIT_ALLOW_POSTGRES_TEST_DDL;
const requireLive = process.env.PARIMIT_REQUIRE_POSTGRES_LIVE === "1";
const privateContainerOptIn = process.env.PARIMIT_ALLOW_PRIVATE_CONTAINER_POSTGRES;
const REQUIRED_DESTRUCTIVE_OPT_IN = "I_UNDERSTAND_THIS_DATABASE_WILL_BE_MODIFIED";
const REQUIRED_PRIVATE_CONTAINER_OPT_IN =
  "I_UNDERSTAND_THE_TEST_DATABASE_USES_A_PRIVATE_CONTAINER_ADDRESS";
const defaultPolicyDayStartsAt = "2026-10-02T00:00:00.000Z";
const defaultCreatedAt = "2026-10-02T10:00:00.000Z";
const defaultExpiresAt = "2026-10-02T10:30:00.000Z";
const syntheticPolicyConfigurationDigest = sha256(
  canonicalJson({ fixture: "parimit-postgres-live-policy-v1" }),
);

class QueryBarrier {
  readonly #parties: number;
  readonly #released: Promise<void>;
  #release!: () => void;
  #arrivals = 0;

  constructor(parties: number) {
    this.#parties = parties;
    this.#released = new Promise((resolve) => {
      this.#release = resolve;
    });
  }

  get arrivals(): number {
    return this.#arrivals;
  }

  async arrive(): Promise<void> {
    if (this.#arrivals >= this.#parties) return;
    this.#arrivals += 1;
    if (this.#arrivals === this.#parties) this.#release();
    await this.#released;
  }
}

class BarrierPoolClient implements PostgresPoolClientLike {
  readonly #inner: PostgresPoolClientLike;
  readonly #pattern: RegExp;
  readonly #barrier: QueryBarrier;

  constructor(inner: PostgresPoolClientLike, pattern: RegExp, barrier: QueryBarrier) {
    this.#inner = inner;
    this.#pattern = pattern;
    this.#barrier = barrier;
  }

  async query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values: readonly PostgresValue[] = [],
  ): Promise<PostgresQueryResult<Row>> {
    if (this.#pattern.test(text)) await this.#barrier.arrive();
    return this.#inner.query<Row>(text, values);
  }

  release(error?: Error | boolean): void {
    this.#inner.release(error);
  }
}

class BarrierPool implements PostgresPoolLike {
  readonly #inner: PostgresPoolLike;
  readonly #pattern: RegExp;
  readonly #barrier: QueryBarrier;

  constructor(inner: PostgresPoolLike, pattern: RegExp, barrier: QueryBarrier) {
    this.#inner = inner;
    this.#pattern = pattern;
    this.#barrier = barrier;
  }

  async connect(): Promise<PostgresPoolClientLike> {
    return new BarrierPoolClient(await this.#inner.connect(), this.#pattern, this.#barrier);
  }
}

function proposalRequest(options: {
  tenantId: string;
  agentId: string;
  idempotencyKey: string;
  bodyLabel: string;
  amountMinor: number;
  dailyLimitMinor: number;
  policyDayStartsAt?: string;
  createdAt?: string;
  expiresAt?: string;
}): CreateProposalRequest {
  const policyDayStartsAt = options.policyDayStartsAt ?? defaultPolicyDayStartsAt;
  const createdAt = options.createdAt ?? defaultCreatedAt;
  const expiresAt = options.expiresAt ?? defaultExpiresAt;
  const requestFingerprint = sha256(
    canonicalJson({
      idempotency_key: options.idempotencyKey,
      body_label: options.bodyLabel,
      amount_minor: String(options.amountMinor),
    }),
  );
  return {
    tenantId: options.tenantId,
    agentId: options.agentId,
    idempotencyKey: options.idempotencyKey,
    requestFingerprint,
    policyConfigurationDigest: syntheticPolicyConfigurationDigest,
    policyDayStartsAt,
    prepare: ({ currentDailyExposureMinor }): PreparedProposal => {
      const projected = currentDailyExposureMinor + options.amountMinor;
      const policyAllowed = projected <= options.dailyLimitMinor;
      const status = policyAllowed ? "AWAITING_APPROVAL" : "POLICY_DENIED";
      const policyReasons = [
        ...(policyAllowed ? [] : ["DAILY_AGENT_LIMIT_EXCEEDED"]),
        "HUMAN_APPROVAL_REQUIRED",
      ];
      const id = randomUUID();
      const payeeReference = "merchant_demo";
      const purpose = `Synthetic PostgreSQL fixture ${options.bodyLabel}`;
      const policy = {
        allowed: policyAllowed,
        reasons: policyReasons,
        rules_version: "parimit-policy-v1",
        config_digest: syntheticPolicyConfigurationDigest,
        required_approvals: 1 as const,
        current_daily_exposure_minor: String(currentDailyExposureMinor),
        projected_daily_exposure_minor: String(projected),
      };
      const intentHash = sha256(
        canonicalJson(currentPaymentIntentPayload({
          id,
          tenantId: options.tenantId,
          proposal: {
            idempotencyKey: options.idempotencyKey,
            agentId: options.agentId,
            onBehalfOf: null,
            amountMinor: options.amountMinor,
            currency: "INR",
            payeeReference,
            purpose,
            expiresInSeconds: (Date.parse(expiresAt) - Date.parse(createdAt)) / 1_000,
          },
          createdAt,
          expiresAt,
          policy,
          initialStatus: status,
        })),
      );
      return {
        intent: {
          id,
          tenantId: options.tenantId,
          idempotencyKey: options.idempotencyKey,
          requestFingerprint,
          agentId: options.agentId,
          onBehalfOf: null,
          amountMinor: options.amountMinor,
          currency: "INR",
          payeeReference,
          purpose,
          status,
          requiredApprovals: 1,
          policyAllowed,
          policyReasons,
          rulesVersion: "parimit-policy-v1",
          intentVersion: "parimit-payment-intent-v3",
          initialStatus: status,
          stateVersion: "1",
          intentHash,
          createdAt,
          expiresAt,
        },
        audit: {
          eventType: policyAllowed ? "PROPOSAL_CREATED" : "PROPOSAL_POLICY_DENIED",
          actorId: options.agentId,
          payload: {
            intent_hash: intentHash,
            tenant_id: options.tenantId,
            state_version: 1,
            status,
            policy,
            boundary: "PROPOSAL_ONLY_NO_VALUE_MOVEMENT",
          },
          occurredAt: createdAt,
        },
      };
    },
  };
}

const liveSkipReason = !databaseUrl
  ? "PARIMIT_TEST_POSTGRES_URL is not set"
  : destructiveOptIn !== REQUIRED_DESTRUCTIVE_OPT_IN
    ? "PARIMIT_ALLOW_POSTGRES_TEST_DDL does not contain the required explicit opt-in"
    : false;

test(
  "live PostgreSQL create/read slice preserves idempotency and daily exposure under concurrency",
  { skip: requireLive ? false : liveSkipReason, timeout: 30_000 },
  async (t) => {
    if (liveSkipReason) {
      throw new Error(`Live PostgreSQL gate is required but unavailable: ${liveSkipReason}`);
    }
    const { Pool } = await import("pg");
    const target = new URL(databaseUrl!);
    if (
      !["127.0.0.1", "localhost", "[::1]"].includes(target.hostname) ||
      target.pathname !== "/parimit_test" ||
      target.search !== "" ||
      target.hash !== ""
    ) {
      throw new Error(
        "Live PostgreSQL tests require a parameter-free loopback URL for a database named exactly parimit_test",
      );
    }
    const ownerPool = new Pool({ connectionString: databaseUrl, max: 2 });
    const runtimePools: Array<{ end(): Promise<void> }> = [];
    const runtimeRole = `parimit_runtime_${randomUUID().replaceAll("-", "")}`;
    const runtimePassword = `parimit_${randomUUID().replaceAll("-", "")}`;
    let runtimeRoleCreated = false;

    try {
      const connectedServer = await ownerPool.query<{
        database_name: string;
        server_address: string | null;
        server_is_loopback: boolean;
        server_is_private: boolean;
      }>(
        `SELECT current_database()::text AS database_name,
                inet_server_addr()::text AS server_address,
                (
                  inet_server_addr() <<= inet '127.0.0.0/8'
                  OR inet_server_addr() <<= inet '::1/128'
                ) AS server_is_loopback,
                (
                  inet_server_addr() <<= inet '10.0.0.0/8'
                  OR inet_server_addr() <<= inet '172.16.0.0/12'
                  OR inet_server_addr() <<= inet '192.168.0.0/16'
                ) AS server_is_private`,
      );
      const server = connectedServer.rows[0];
      const privateContainerAllowed =
        privateContainerOptIn === REQUIRED_PRIVATE_CONTAINER_OPT_IN;
      if (
        connectedServer.rows.length !== 1 ||
        server?.database_name !== "parimit_test" ||
        server.server_address === null ||
        (!server.server_is_loopback && !(server.server_is_private && privateContainerAllowed))
      ) {
        throw new Error(
          "Refusing PostgreSQL test DDL because the connected server is not an allowed loopback or explicitly opted-in private-container parimit_test database",
        );
      }

      const preflight = await ownerPool.query<{ schema_name: string }>(
        `SELECT nspname AS schema_name
           FROM pg_namespace
          WHERE nspname NOT LIKE 'pg_%'
            AND nspname NOT IN ('information_schema', 'public')
          ORDER BY nspname`,
      );
      if (preflight.rows.length !== 0) {
        throw new Error(
          `Refusing PostgreSQL test DDL because user schemas already exist: ${preflight.rows
            .map((row) => row.schema_name)
            .join(", ")}`,
        );
      }

      const publicObjects = await ownerPool.query<{ object_description: string }>(
        `SELECT pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid)
                  AS object_description
           FROM pg_catalog.pg_depend d
          WHERE d.refclassid = 'pg_catalog.pg_namespace'::regclass
            AND d.refobjid = 'public'::regnamespace
            AND d.deptype = 'n'
          ORDER BY object_description`,
      );
      if (publicObjects.rows.length !== 0) {
        throw new Error(
          `Refusing PostgreSQL test DDL because public already contains objects: ${publicObjects.rows
            .map((row) => row.object_description)
            .join(", ")}`,
        );
      }

      // PostgreSQL 14 grants CREATE on public to PUBLIC by default. Apply the
      // version-independent boundary only after every refusal check has passed,
      // so an unsafe target is left completely untouched.
      await ownerPool.query(`
        BEGIN;
        REVOKE CREATE ON SCHEMA public FROM PUBLIC;
        REVOKE CONNECT ON DATABASE parimit_test FROM PUBLIC;
        COMMIT;
      `);

      for (const file of ["001_initial.sql", "002_runtime_foundation.sql"]) {
        const migration = await readFile(
          new URL(`../db/postgres/${file}`, import.meta.url),
          "utf8",
        );
        await ownerPool.query(migration);
      }

      await ownerPool.query(`
        CREATE ROLE ${runtimeRole}
          LOGIN PASSWORD '${runtimePassword}'
          NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
        GRANT CONNECT ON DATABASE parimit_test TO ${runtimeRole};
        GRANT USAGE ON SCHEMA parimit TO ${runtimeRole};
        GRANT SELECT, INSERT, UPDATE ON parimit.policy_subjects TO ${runtimeRole};
        GRANT SELECT, INSERT ON parimit.intents TO ${runtimeRole};
        GRANT UPDATE (status, state_version) ON parimit.intents TO ${runtimeRole};
        GRANT SELECT, INSERT ON parimit.audit_events TO ${runtimeRole};
        GRANT USAGE, SELECT ON SEQUENCE parimit.audit_events_sequence_seq
          TO ${runtimeRole};
      `);
      runtimeRoleCreated = true;

      const runtimeUrl = new URL(target);
      runtimeUrl.username = runtimeRole;
      runtimeUrl.password = runtimePassword;
      const firstRuntimePool = new Pool({ connectionString: runtimeUrl.href, max: 2 });
      const secondRuntimePool = new Pool({ connectionString: runtimeUrl.href, max: 2 });
      runtimePools.push(firstRuntimePool, secondRuntimePool);
      const firstPool = firstRuntimePool as unknown as PostgresPoolLike;
      const secondPool = secondRuntimePool as unknown as PostgresPoolLike;
      const firstRepository = new PostgresProposalRepository(firstPool);
      const secondRepository = new PostgresProposalRepository(secondPool);

      await t.test("repository pools use a restricted runtime role", async () => {
        for (const statement of [
          "DELETE FROM parimit.intents",
          "UPDATE parimit.intents SET purpose = 'forbidden'",
          "CREATE TABLE parimit.forbidden_runtime_ddl (id integer)",
          "CREATE TABLE public.forbidden_runtime_ddl (id integer)",
        ]) {
          await assert.rejects(
            firstRuntimePool.query(statement),
            (error: unknown) =>
              typeof error === "object" && error !== null && "code" in error && error.code === "42501",
          );
        }
        await firstRuntimePool.query(
          `INSERT INTO parimit.policy_subjects (tenant_id, agent_id) VALUES ($1, $2)`,
          ["tenant-privilege-test", "agent-privilege-test"],
        );
        await assert.rejects(
          firstRuntimePool.query(
            `UPDATE parimit.policy_subjects
                SET agent_id = agent_id
              WHERE tenant_id = $1 AND agent_id = $2`,
            ["tenant-privilege-test", "agent-privilege-test"],
          ),
          (error: unknown) =>
            typeof error === "object" && error !== null && "code" in error && error.code === "55000",
        );
      });

      await t.test("two pools create one row for the same idempotent request", async () => {
        const barrier = new QueryBarrier(2);
        const firstConcurrentRepository = new PostgresProposalRepository(
          new BarrierPool(firstPool, /INSERT INTO parimit[.]policy_subjects/, barrier),
        );
        const secondConcurrentRepository = new PostgresProposalRepository(
          new BarrierPool(secondPool, /INSERT INTO parimit[.]policy_subjects/, barrier),
        );
        const tenantId = `tenant-idempotency-${randomUUID()}`;
        const request = proposalRequest({
          tenantId,
          agentId: "agent-concurrent",
          idempotencyKey: "same-request",
          bodyLabel: "same-body",
          amountMinor: 100,
          dailyLimitMinor: 500,
        });
        const [left, right] = await Promise.all([
          firstConcurrentRepository.createOrReplay(request),
          secondConcurrentRepository.createOrReplay(request),
        ]);

        assert.equal(barrier.arrivals, 2);
        assert.equal(left.intent.id, right.intent.id);
        assert.deepEqual(
          [left.idempotentReplay, right.idempotentReplay].sort(),
          [false, true],
        );
        const count = await ownerPool.query<{ intents: string; events: string }>(
          `SELECT
             (SELECT COUNT(*)::text FROM parimit.intents WHERE tenant_id = $1) AS intents,
             (SELECT COUNT(*)::text
                FROM parimit.audit_events audit
                JOIN parimit.intents intent ON intent.id = audit.intent_id
               WHERE intent.tenant_id = $1) AS events`,
          [tenantId],
        );
        assert.deepEqual(count.rows[0], { intents: "1", events: "1" });
        assert.deepEqual(
          await firstRepository.readIntent(tenantId, left.intent.id),
          left.intent,
        );
      });

      await t.test("same idempotency key with another body fails closed", async () => {
        const barrier = new QueryBarrier(2);
        const firstConcurrentRepository = new PostgresProposalRepository(
          new BarrierPool(firstPool, /INSERT INTO parimit[.]policy_subjects/, barrier),
        );
        const secondConcurrentRepository = new PostgresProposalRepository(
          new BarrierPool(secondPool, /INSERT INTO parimit[.]policy_subjects/, barrier),
        );
        const tenantId = `tenant-conflict-${randomUUID()}`;
        const common = {
          tenantId,
          agentId: "agent-conflict",
          idempotencyKey: "conflicting-request",
          amountMinor: 100,
          dailyLimitMinor: 500,
        };
        const results = await Promise.allSettled([
          firstConcurrentRepository.createOrReplay(
            proposalRequest({ ...common, bodyLabel: "left" }),
          ),
          secondConcurrentRepository.createOrReplay(
            proposalRequest({ ...common, bodyLabel: "right" }),
          ),
        ]);
        assert.equal(barrier.arrivals, 2);
        assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
        const rejection = results.find(
          (result): result is PromiseRejectedResult => result.status === "rejected",
        );
        assert.ok(rejection);
        assert.ok(rejection.reason instanceof PostgresRepositoryError);
        assert.equal(rejection.reason.code, "IDEMPOTENCY_CONFLICT");
        const count = await ownerPool.query<{ intents: string; events: string }>(
          `SELECT
             (SELECT COUNT(*)::text FROM parimit.intents WHERE tenant_id = $1) AS intents,
             (SELECT COUNT(*)::text
                FROM parimit.audit_events audit
                JOIN parimit.intents intent ON intent.id = audit.intent_id
               WHERE intent.tenant_id = $1) AS events`,
          [tenantId],
        );
        assert.deepEqual(count.rows[0], { intents: "1", events: "1" });
      });

      await t.test("per-agent lock prevents a daily-exposure race", async () => {
        const barrier = new QueryBarrier(2);
        const firstConcurrentRepository = new PostgresProposalRepository(
          new BarrierPool(firstPool, /INSERT INTO parimit[.]policy_subjects/, barrier),
        );
        const secondConcurrentRepository = new PostgresProposalRepository(
          new BarrierPool(secondPool, /INSERT INTO parimit[.]policy_subjects/, barrier),
        );
        const tenantId = `tenant-exposure-${randomUUID()}`;
        const common = {
          tenantId,
          agentId: "agent-exposure",
          amountMinor: 300,
          dailyLimitMinor: 500,
        };
        const [left, right] = await Promise.all([
          firstConcurrentRepository.createOrReplay(
            proposalRequest({ ...common, idempotencyKey: "daily-left", bodyLabel: "left" }),
          ),
          secondConcurrentRepository.createOrReplay(
            proposalRequest({ ...common, idempotencyKey: "daily-right", bodyLabel: "right" }),
          ),
        ]);
        assert.equal(barrier.arrivals, 2);
        assert.deepEqual(
          [left.intent.status, right.intent.status].sort(),
          ["AWAITING_APPROVAL", "POLICY_DENIED"],
        );
        const allowed = [left.intent, right.intent].find((intent) => intent.policyAllowed);
        const denied = [left.intent, right.intent].find((intent) => !intent.policyAllowed);
        assert.ok(allowed);
        assert.ok(denied);
        assert.deepEqual(denied.policyReasons, [
          "DAILY_AGENT_LIMIT_EXCEEDED",
          "HUMAN_APPROVAL_REQUIRED",
        ]);
        const exposure = await ownerPool.query<{ exposure: string }>(
          `SELECT COALESCE(SUM(amount_minor), 0)::text AS exposure
             FROM parimit.intents
            WHERE tenant_id = $1 AND policy_allowed = true`,
          [tenantId],
        );
        assert.equal(exposure.rows[0].exposure, "300");
      });

      await t.test("daily exposure excludes rows from a later UTC policy day", async () => {
        const tenantId = `tenant-day-bound-${randomUUID()}`;
        const common = {
          tenantId,
          agentId: "agent-day-bound",
          amountMinor: 300,
          dailyLimitMinor: 500,
        };
        const future = await firstRepository.createOrReplay(
          proposalRequest({
            ...common,
            idempotencyKey: "future-day",
            bodyLabel: "future",
            policyDayStartsAt: "2026-10-03T00:00:00.000Z",
            createdAt: "2026-10-03T10:00:00.000Z",
            expiresAt: "2026-10-03T10:30:00.000Z",
          }),
        );
        const earlier = await secondRepository.createOrReplay(
          proposalRequest({
            ...common,
            idempotencyKey: "earlier-day",
            bodyLabel: "earlier",
            policyDayStartsAt: "2026-10-02T00:00:00.000Z",
            createdAt: "2026-10-02T10:00:00.000Z",
            expiresAt: "2026-10-02T10:30:00.000Z",
          }),
        );
        assert.equal(future.intent.status, "AWAITING_APPROVAL");
        assert.equal(earlier.intent.status, "AWAITING_APPROVAL");
      });

      await t.test("a failure after intent insertion rolls back intent and audit together", async () => {
        const tenantId = `tenant-rollback-${randomUUID()}`;
        const base = proposalRequest({
          tenantId,
          agentId: "agent-rollback",
          idempotencyKey: "rollback-request",
          bodyLabel: "rollback",
          amountMinor: 100,
          dailyLimitMinor: 500,
        });
        const failing: CreateProposalRequest = {
          ...base,
          prepare: async (context) => {
            const prepared = await base.prepare(context);
            return {
              ...prepared,
              audit: {
                ...prepared.audit,
                payload: {
                  ...prepared.audit.payload,
                  invalid_non_finite_value: Number.NaN,
                },
              },
            };
          },
        };
        await assert.rejects(firstRepository.createOrReplay(failing), /non-finite/);
        const count = await ownerPool.query<{ intents: string; events: string }>(
          `SELECT
             (SELECT COUNT(*)::text FROM parimit.intents WHERE tenant_id = $1) AS intents,
             (SELECT COUNT(*)::text
                FROM parimit.audit_events audit
                JOIN parimit.intents intent ON intent.id = audit.intent_id
               WHERE intent.tenant_id = $1) AS events`,
          [tenantId],
        );
        assert.deepEqual(count.rows[0], { intents: "0", events: "0" });
      });

      await t.test("corrupt initial audit evidence is rejected before insertion", async () => {
        const tenantId = `tenant-invalid-evidence-${randomUUID()}`;
        const base = proposalRequest({
          tenantId,
          agentId: "agent-invalid-evidence",
          idempotencyKey: "invalid-evidence-request",
          bodyLabel: "invalid-evidence",
          amountMinor: 100,
          dailyLimitMinor: 500,
        });
        const corrupt: CreateProposalRequest = {
          ...base,
          prepare: async (context) => {
            const prepared = await base.prepare(context);
            return {
              ...prepared,
              audit: {
                ...prepared.audit,
                payload: { ...prepared.audit.payload, state_version: 2 },
              },
            };
          },
        };
        await assert.rejects(
          firstRepository.createOrReplay(corrupt),
          (error: unknown) =>
            error instanceof PostgresRepositoryError &&
            error.code === "INVALID_PREPARED_PROPOSAL",
        );
        const count = await ownerPool.query<{ intents: string; events: string }>(
          `SELECT
             (SELECT COUNT(*)::text FROM parimit.intents WHERE tenant_id = $1) AS intents,
             (SELECT COUNT(*)::text
                FROM parimit.audit_events audit
                JOIN parimit.intents intent ON intent.id = audit.intent_id
               WHERE intent.tenant_id = $1) AS events`,
          [tenantId],
        );
        assert.deepEqual(count.rows[0], { intents: "0", events: "0" });
      });

      await t.test("competing audit appends remain one linear chain", async () => {
        const tenantId = `tenant-audit-${randomUUID()}`;
        const created = await firstRepository.createOrReplay(
          proposalRequest({
            tenantId,
            agentId: "agent-audit",
            idempotencyKey: "audit-parent",
            bodyLabel: "audit-parent",
            amountMinor: 100,
            dailyLimitMinor: 500,
          }),
        );
        const barrier = new QueryBarrier(2);
        const retries: Array<{ sqlState: string; constraint?: string }> = [];
        const append = (pool: PostgresPoolLike, actorId: string) =>
          withSerializablePoolTransaction(
            new BarrierPool(pool, /FROM parimit[.]intents[\s\S]*FOR UPDATE/, barrier),
            (transaction) =>
              appendAuditEvent(transaction, {
                tenantId,
                intentId: created.intent.id,
                eventType: "TEST_CONCURRENT_APPEND",
                actorId,
                payload: { fixture: actorId },
                occurredAt: "2026-10-02T10:01:00.000Z",
              }),
            { onRetry: (details) => retries.push(details) },
          );
        await Promise.all([
          append(firstPool, "fixture-left"),
          append(secondPool, "fixture-right"),
        ]);
        assert.equal(barrier.arrivals, 2);
        assert.ok(
          retries.some(
            (retry) =>
              retry.sqlState === "23505" && retry.constraint === "audit_events_no_forks",
          ),
        );
        const events = await ownerPool.query<{
          previous_hash: string;
          event_hash: string;
        }>(
          `SELECT previous_hash, event_hash::text AS event_hash
             FROM parimit.audit_events
            WHERE intent_id = $1::uuid
            ORDER BY sequence`,
          [created.intent.id],
        );
        assert.equal(events.rows.length, 3);
        assert.equal(events.rows[0].previous_hash, "GENESIS");
        assert.equal(events.rows[1].previous_hash, events.rows[0].event_hash);
        assert.equal(events.rows[2].previous_hash, events.rows[1].event_hash);
      });
    } finally {
      await Promise.all(runtimePools.map((pool) => pool.end()));
      if (runtimeRoleCreated) {
        await ownerPool.query(`DROP OWNED BY ${runtimeRole}`);
        await ownerPool.query(`DROP ROLE ${runtimeRole}`);
      }
      await ownerPool.end();
    }
  },
);
