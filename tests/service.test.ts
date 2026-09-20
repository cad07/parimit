import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { canonicalJson, hmacSha256, sha256 } from "../src/crypto.ts";
import { ParimitError } from "../src/errors.ts";
import { ParimitService } from "../src/service.ts";

function proposal(
  idempotencyKey: string,
  amountMinor = "100",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    idempotency_key: idempotencyKey,
    requested_by: { type: "agent", id: "agent-demo" },
    amount: { currency: "INR", minor: amountMinor },
    payee_reference: "merchant_demo_001",
    purpose: "Buy a test item",
    expires_in_seconds: 60,
    ...overrides,
  };
}

function appendForgedAuditEvent(
  service: ParimitService,
  intentId: string,
  eventType: string,
  actorId: string,
  payload: unknown,
  occurredAt: string,
): void {
  const previous = service.database
    .prepare(
      "SELECT event_hash FROM audit_events WHERE intent_id = ? ORDER BY sequence DESC LIMIT 1",
    )
    .get(intentId) as Record<string, string>;
  const previousHash = previous.event_hash;
  const eventHash = sha256(
    canonicalJson({
      intent_id: intentId,
      event_type: eventType,
      actor_id: actorId,
      payload,
      occurred_at: occurredAt,
      previous_hash: previousHash,
    }),
  );
  service.database
    .prepare(
      `INSERT INTO audit_events
        (intent_id, event_type, actor_id, payload, occurred_at, previous_hash, event_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      intentId,
      eventType,
      actorId,
      canonicalJson(payload),
      occurredAt,
      previousHash,
      eventHash,
    );
}

test("validates INR minor units and creates proposal-only immutable intents", (t) => {
  const service = new ParimitService({ receiptSecret: "test-secret" });
  t.after(() => service.close());

  const intent = service.createIntent(proposal("proposal-001", "499"));
  assert.equal(intent.amount.currency, "INR");
  assert.equal(intent.amount.minor, "499");
  assert.equal(intent.status, "AWAITING_APPROVAL");
  assert.equal(intent.intent_version, "parimit-payment-intent-v3");
  assert.equal(intent.tenant_id, "local-demo");
  assert.equal(intent.state_version, 1);
  assert.equal(intent.initial_status, "AWAITING_APPROVAL");
  assert.equal(intent.required_approvals, 1);
  assert.equal(intent.policy.rules_version, "parimit-policy-v1");
  assert.match(intent.intent_hash, /^[a-f0-9]{64}$/);
  assert.deepEqual(service.verifyIntegrity(intent.id), {
    valid: true,
    intent_hash_valid: true,
    approval_receipts_valid: true,
    audit_chain_valid: true,
    state_consistency_valid: true,
    failures: [],
  });

  assert.throws(
    () => service.createIntent(proposal("bad-zero", "0")),
    (error: unknown) => error instanceof ParimitError && error.code === "VALIDATION_ERROR",
  );
  assert.throws(
    () =>
      service.createIntent({
        ...proposal("bad-currency"),
        amount: { currency: "USD", minor: "100" },
      }),
    (error: unknown) => error instanceof ParimitError && error.code === "VALIDATION_ERROR",
  );
  assert.throws(
    () =>
      service.createIntent({
        ...proposal("bad-number"),
        amount: { currency: "INR", minor: 100 },
      }),
    (error: unknown) => error instanceof ParimitError && error.code === "VALIDATION_ERROR",
  );
  assert.throws(
    () =>
      service.createIntent(
        proposal("real-looking-payee", "100", { payee_reference: "person@bank" }),
      ),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "VALIDATION_ERROR" &&
      /opaque/.test(error.message),
  );
  assert.throws(
    () => service.createIntent({ ...proposal("unknown-field"), dispatch: true }),
    (error: unknown) => error instanceof ParimitError && error.code === "VALIDATION_ERROR",
  );
  assert.throws(
    () =>
      service.createIntent({
        ...proposal("unknown-nested-field"),
        requested_by: { type: "agent", id: "agent-demo", role: "admin" },
      }),
    (error: unknown) => error instanceof ParimitError && error.code === "VALIDATION_ERROR",
  );
});

test("atomically repairs a partial legacy migration without rewriting v1 hashes", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-v1-migration-"));
  const databasePath = join(directory, "legacy.db");
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const legacyDatabase = new DatabaseSync(databasePath);
  legacyDatabase.exec(`
    CREATE TABLE intents (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL DEFAULT 'local-demo',
      idempotency_key TEXT NOT NULL,
      request_fingerprint TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      on_behalf_of TEXT,
      amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
      currency TEXT NOT NULL CHECK (currency = 'INR'),
      payee_reference TEXT NOT NULL,
      purpose TEXT NOT NULL,
      status TEXT NOT NULL,
      required_approvals INTEGER NOT NULL CHECK (required_approvals IN (1, 2)),
      policy_allowed INTEGER NOT NULL CHECK (policy_allowed IN (0, 1)),
      policy_reasons TEXT NOT NULL,
      rules_version TEXT NOT NULL,
      state_version INTEGER NOT NULL DEFAULT 1,
      intent_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      UNIQUE (agent_id, idempotency_key)
    );
    CREATE TABLE audit_events (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      intent_id TEXT NOT NULL REFERENCES intents(id),
      event_type TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      payload TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      event_hash TEXT NOT NULL
    );
  `);
  const id = "11111111-1111-4111-8111-111111111111";
  const createdAt = "2099-01-01T00:00:00.000Z";
  const expiresAt = "2099-01-01T00:01:00.000Z";
  const legacyPayload = {
    version: "parimit-payment-intent-v1",
    id,
    idempotency_key: "legacy-v1-row",
    requested_by: { type: "agent", id: "agent-demo" },
    on_behalf_of: null,
    amount: { currency: "INR", minor: "100" },
    payee_reference: "merchant_demo_001",
    purpose: "Legacy compatibility fixture",
    created_at: createdAt,
    expires_at: expiresAt,
  };
  const intentHash = sha256(canonicalJson(legacyPayload));
  const policy = {
    allowed: true,
    reasons: ["HUMAN_APPROVAL_REQUIRED"],
    rules_version: "parimit-policy-v1",
    required_approvals: 1,
    current_daily_exposure_minor: "0",
    projected_daily_exposure_minor: "100",
  };
  legacyDatabase
    .prepare(
      `INSERT INTO intents
        (id, idempotency_key, request_fingerprint, agent_id, on_behalf_of, amount_minor,
         currency, payee_reference, purpose, status, required_approvals, policy_allowed,
         policy_reasons, rules_version, intent_hash, created_at, expires_at)
       VALUES (?, ?, ?, ?, NULL, ?, 'INR', ?, ?, 'AWAITING_APPROVAL', 1, 1, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      "legacy-v1-row",
      "legacy-request-fingerprint",
      "agent-demo",
      100,
      "merchant_demo_001",
      "Legacy compatibility fixture",
      canonicalJson(policy.reasons),
      policy.rules_version,
      intentHash,
      createdAt,
      expiresAt,
    );
  const auditPayload = {
    intent_hash: intentHash,
    status: "AWAITING_APPROVAL",
    policy,
    boundary: "PROPOSAL_ONLY_NO_VALUE_MOVEMENT",
  };
  const eventHash = sha256(
    canonicalJson({
      intent_id: id,
      event_type: "PROPOSAL_CREATED",
      actor_id: "agent-demo",
      payload: auditPayload,
      occurred_at: createdAt,
      previous_hash: "GENESIS",
    }),
  );
  legacyDatabase
    .prepare(
      `INSERT INTO audit_events
        (intent_id, event_type, actor_id, payload, occurred_at, previous_hash, event_hash)
       VALUES (?, 'PROPOSAL_CREATED', 'agent-demo', ?, ?, 'GENESIS', ?)`,
    )
    .run(id, canonicalJson(auditPayload), createdAt, eventHash);
  legacyDatabase.close();

  const service = new ParimitService({
    databasePath,
    receiptSecret: "legacy-secret",
    tenantId: "migrated-tenant",
  });
  t.after(() => service.close());
  const migrated = service.getIntent(id);
  assert.equal(migrated.intent_version, "parimit-payment-intent-v1");
  assert.equal(migrated.tenant_id, "migrated-tenant");
  assert.equal(migrated.initial_status, "AWAITING_APPROVAL");
  assert.equal(migrated.intent_hash, intentHash);
  assert.equal(service.verifyIntegrity(id).valid, true);
});

test("migration preserves an existing v2 initial-state mismatch as detected corruption", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-v2-corruption-migration-"));
  const databasePath = join(directory, "legacy.db");
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const legacyDatabase = new DatabaseSync(databasePath);
  legacyDatabase.exec(`
    CREATE TABLE intents (
      id TEXT PRIMARY KEY,
      idempotency_key TEXT NOT NULL,
      request_fingerprint TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      on_behalf_of TEXT,
      amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
      currency TEXT NOT NULL CHECK (currency = 'INR'),
      payee_reference TEXT NOT NULL,
      purpose TEXT NOT NULL,
      status TEXT NOT NULL,
      required_approvals INTEGER NOT NULL CHECK (required_approvals IN (1, 2)),
      policy_allowed INTEGER NOT NULL CHECK (policy_allowed IN (0, 1)),
      policy_reasons TEXT NOT NULL,
      rules_version TEXT NOT NULL,
      intent_version TEXT NOT NULL CHECK (
        intent_version IN ('parimit-payment-intent-v1', 'parimit-payment-intent-v2')
      ),
      initial_status TEXT NOT NULL CHECK (initial_status IN ('POLICY_DENIED', 'AWAITING_APPROVAL')),
      intent_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      UNIQUE (agent_id, idempotency_key)
    );
    CREATE TABLE audit_events (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      intent_id TEXT NOT NULL REFERENCES intents(id),
      event_type TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      payload TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      event_hash TEXT NOT NULL
    );
  `);
  const id = "22222222-2222-4222-8222-222222222222";
  const createdAt = "2099-01-01T00:00:00.000Z";
  const expiresAt = "2099-01-01T00:01:00.000Z";
  const policy = {
    allowed: true,
    reasons: ["HUMAN_APPROVAL_REQUIRED"],
    rules_version: "parimit-policy-v1",
    required_approvals: 1,
    current_daily_exposure_minor: "0",
    projected_daily_exposure_minor: "100",
  };
  const intentHash = sha256(
    canonicalJson({
      version: "parimit-payment-intent-v2",
      id,
      idempotency_key: "legacy-v2-corrupt-state",
      requested_by: { type: "agent", id: "agent-demo" },
      on_behalf_of: null,
      amount: { currency: "INR", minor: "100" },
      payee_reference: "merchant_demo_001",
      purpose: "Preserve migration corruption evidence",
      initial_status: "AWAITING_APPROVAL",
      policy: {
        allowed: true,
        reasons: policy.reasons,
        rules_version: policy.rules_version,
        required_approvals: 1,
      },
      created_at: createdAt,
      expires_at: expiresAt,
    }),
  );
  legacyDatabase
    .prepare(
      `INSERT INTO intents
        (id, idempotency_key, request_fingerprint, agent_id, on_behalf_of, amount_minor,
         currency, payee_reference, purpose, status, required_approvals, policy_allowed,
         policy_reasons, rules_version, intent_version, initial_status, intent_hash,
         created_at, expires_at)
       VALUES (?, ?, ?, 'agent-demo', NULL, 100, 'INR', 'merchant_demo_001', ?,
               'AWAITING_APPROVAL', 1, 1, ?, ?, 'parimit-payment-intent-v2',
               'POLICY_DENIED', ?, ?, ?)`,
    )
    .run(
      id,
      "legacy-v2-corrupt-state",
      "legacy-v2-request-fingerprint",
      "Preserve migration corruption evidence",
      canonicalJson(policy.reasons),
      policy.rules_version,
      intentHash,
      createdAt,
      expiresAt,
    );
  const auditPayload = {
    intent_hash: intentHash,
    status: "AWAITING_APPROVAL",
    policy,
    boundary: "PROPOSAL_ONLY_NO_VALUE_MOVEMENT",
  };
  const eventHash = sha256(
    canonicalJson({
      intent_id: id,
      event_type: "PROPOSAL_CREATED",
      actor_id: "agent-demo",
      payload: auditPayload,
      occurred_at: createdAt,
      previous_hash: "GENESIS",
    }),
  );
  legacyDatabase
    .prepare(
      `INSERT INTO audit_events
        (intent_id, event_type, actor_id, payload, occurred_at, previous_hash, event_hash)
       VALUES (?, 'PROPOSAL_CREATED', 'agent-demo', ?, ?, 'GENESIS', ?)`,
    )
    .run(id, canonicalJson(auditPayload), createdAt, eventHash);
  legacyDatabase.close();

  const service = new ParimitService({
    databasePath,
    receiptSecret: "legacy-corruption-preservation-secret",
    tenantId: "migrated-tenant",
  });
  t.after(() => service.close());
  const migratedRow = service.database
    .prepare("SELECT initial_status FROM intents WHERE id = ?")
    .get(id) as { initial_status: string };
  assert.equal(migratedRow.initial_status, "POLICY_DENIED");
  const report = service.verifyIntegrity(id);
  assert.equal(report.valid, false);
  assert.ok(report.failures.includes("INTENT_HASH_MISMATCH"));
  assert.throws(
    () => service.getIntent(id),
    (error: unknown) => error instanceof ParimitError && error.code === "INTEGRITY_FAILURE",
  );
});

test("legacy receipt preflight rejects unsafe startup before migration and permits a clean retry", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-legacy-receipt-preflight-"));
  const databasePath = join(directory, "legacy.db");
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const correctReceiptSecret = "legacy-preflight-correct-receipt-secret";
  const id = "33333333-3333-4333-8333-333333333333";
  const approvalId = "44444444-4444-4444-8444-444444444444";
  const createdAt = "2099-01-01T00:00:00.000Z";
  const approvedAt = "2099-01-01T00:00:10.000Z";
  const expiresAt = "2099-01-01T00:01:00.000Z";
  const reviewerId = "legacy-human-reviewer";
  const policy = {
    allowed: true,
    reasons: ["HUMAN_APPROVAL_REQUIRED"],
    rules_version: "parimit-policy-v1",
    required_approvals: 1,
    current_daily_exposure_minor: "0",
    projected_daily_exposure_minor: "100",
  };
  const intentHash = sha256(
    canonicalJson({
      version: "parimit-payment-intent-v2",
      id,
      idempotency_key: "legacy-preflight-v2",
      requested_by: { type: "agent", id: "agent-demo" },
      on_behalf_of: null,
      amount: { currency: "INR", minor: "100" },
      payee_reference: "merchant_demo_001",
      purpose: "Verify failed startup leaves legacy evidence untouched",
      initial_status: "AWAITING_APPROVAL",
      policy: {
        allowed: true,
        reasons: policy.reasons,
        rules_version: policy.rules_version,
        required_approvals: 1,
      },
      created_at: createdAt,
      expires_at: expiresAt,
    }),
  );
  const receiptHmac = hmacSha256(correctReceiptSecret, {
    version: "parimit-approval-receipt-v1",
    intent_id: id,
    intent_hash: intentHash,
    actor_id: reviewerId,
    actor_role: "approver",
    decision: "APPROVE",
    created_at: approvedAt,
  });

  const legacyDatabase = new DatabaseSync(databasePath);
  legacyDatabase.exec(`
    CREATE TABLE intents (
      id TEXT PRIMARY KEY,
      idempotency_key TEXT NOT NULL,
      request_fingerprint TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      on_behalf_of TEXT,
      amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
      currency TEXT NOT NULL CHECK (currency = 'INR'),
      payee_reference TEXT NOT NULL,
      purpose TEXT NOT NULL,
      status TEXT NOT NULL,
      required_approvals INTEGER NOT NULL CHECK (required_approvals IN (1, 2)),
      policy_allowed INTEGER NOT NULL CHECK (policy_allowed IN (0, 1)),
      policy_reasons TEXT NOT NULL,
      rules_version TEXT NOT NULL,
      intent_version TEXT NOT NULL CHECK (
        intent_version IN ('parimit-payment-intent-v1', 'parimit-payment-intent-v2')
      ),
      initial_status TEXT NOT NULL CHECK (initial_status IN ('POLICY_DENIED', 'AWAITING_APPROVAL')),
      intent_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      UNIQUE (agent_id, idempotency_key)
    );
    CREATE TABLE approvals (
      id TEXT PRIMARY KEY,
      intent_id TEXT NOT NULL REFERENCES intents(id),
      actor_id TEXT NOT NULL,
      actor_role TEXT NOT NULL CHECK (actor_role IN ('approver', 'admin')),
      decision TEXT NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
      intent_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      receipt_hmac TEXT NOT NULL,
      UNIQUE (intent_id, actor_id)
    );
    CREATE TABLE audit_events (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      intent_id TEXT NOT NULL REFERENCES intents(id),
      event_type TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      payload TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      event_hash TEXT NOT NULL
    );
  `);
  legacyDatabase
    .prepare(
      `INSERT INTO intents
        (id, idempotency_key, request_fingerprint, agent_id, on_behalf_of, amount_minor,
         currency, payee_reference, purpose, status, required_approvals, policy_allowed,
         policy_reasons, rules_version, intent_version, initial_status, intent_hash,
         created_at, expires_at)
       VALUES (?, 'legacy-preflight-v2', 'legacy-preflight-fingerprint', 'agent-demo', NULL,
               100, 'INR', 'merchant_demo_001', ?, 'AUTHORIZED_NO_DISPATCH', 1, 1,
               ?, ?, 'parimit-payment-intent-v2', 'AWAITING_APPROVAL', ?, ?, ?)`,
    )
    .run(
      id,
      "Verify failed startup leaves legacy evidence untouched",
      canonicalJson(policy.reasons),
      policy.rules_version,
      intentHash,
      createdAt,
      expiresAt,
    );
  legacyDatabase
    .prepare(
      `INSERT INTO approvals
        (id, intent_id, actor_id, actor_role, decision, intent_hash, created_at, receipt_hmac)
       VALUES (?, ?, ?, 'approver', 'APPROVE', ?, ?, ?)`,
    )
    .run(approvalId, id, reviewerId, intentHash, approvedAt, receiptHmac);

  const initialAuditPayload = {
    intent_hash: intentHash,
    status: "AWAITING_APPROVAL",
    policy,
    boundary: "PROPOSAL_ONLY_NO_VALUE_MOVEMENT",
  };
  const initialEventHash = sha256(
    canonicalJson({
      intent_id: id,
      event_type: "PROPOSAL_CREATED",
      actor_id: "agent-demo",
      payload: initialAuditPayload,
      occurred_at: createdAt,
      previous_hash: "GENESIS",
    }),
  );
  legacyDatabase
    .prepare(
      `INSERT INTO audit_events
        (intent_id, event_type, actor_id, payload, occurred_at, previous_hash, event_hash)
       VALUES (?, 'PROPOSAL_CREATED', 'agent-demo', ?, ?, 'GENESIS', ?)`,
    )
    .run(id, canonicalJson(initialAuditPayload), createdAt, initialEventHash);

  const approvalAuditPayload = {
    actor_role: "approver",
    decision: "APPROVE",
    intent_hash: intentHash,
    receipt_hmac: receiptHmac,
    resulting_status: "AUTHORIZED_NO_DISPATCH",
  };
  const approvalEventHash = sha256(
    canonicalJson({
      intent_id: id,
      event_type: "HUMAN_APPROVAL_RECORDED",
      actor_id: reviewerId,
      payload: approvalAuditPayload,
      occurred_at: approvedAt,
      previous_hash: initialEventHash,
    }),
  );
  legacyDatabase
    .prepare(
      `INSERT INTO audit_events
        (intent_id, event_type, actor_id, payload, occurred_at, previous_hash, event_hash)
       VALUES (?, 'HUMAN_APPROVAL_RECORDED', ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      reviewerId,
      canonicalJson(approvalAuditPayload),
      approvedAt,
      initialEventHash,
      approvalEventHash,
    );
  legacyDatabase.close();

  const assertLegacyDatabaseUntouched = (): void => {
    const database = new DatabaseSync(databasePath);
    try {
      const columns = new Set(
        (database.prepare("PRAGMA table_info(intents)").all() as Array<{ name: string }>).map(
          (column) => column.name,
        ),
      );
      assert.equal(columns.has("tenant_id"), false);
      assert.equal(columns.has("state_version"), false);
      assert.equal(
        (
          database
            .prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = ?")
            .get("service_metadata") as { count: number }
        ).count,
        0,
      );
      const intentRow = database
        .prepare("SELECT status, intent_hash FROM intents WHERE id = ?")
        .get(id) as { status: string; intent_hash: string };
      assert.equal(intentRow.status, "AUTHORIZED_NO_DISPATCH");
      assert.equal(intentRow.intent_hash, intentHash);
      assert.equal(
        (
          database
            .prepare("SELECT receipt_hmac FROM approvals WHERE id = ?")
            .get(approvalId) as { receipt_hmac: string }
        ).receipt_hmac,
        receiptHmac,
      );
    } finally {
      database.close();
    }
  };

  assert.throws(
    () =>
      new ParimitService({
        databasePath,
        receiptSecret: "wrong-legacy-preflight-receipt-secret",
        tenantId: "mistyped-tenant",
      }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "RECEIPT_KEY_MISMATCH" &&
      error.statusCode === 500,
  );
  assertLegacyDatabaseUntouched();

  assert.throws(
    () =>
      new ParimitService({
        databasePath,
        receiptSecret: correctReceiptSecret,
        authenticationMode: "oidc",
        identityTrustDomainId: `sha256:${"a".repeat(64)}`,
        tenantId: "oidc-tenant",
      }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "UNATTESTED_IDENTITY_HISTORY" &&
      error.statusCode === 500,
  );
  assertLegacyDatabaseUntouched();

  const recoveredService = new ParimitService({
    databasePath,
    receiptSecret: correctReceiptSecret,
    tenantId: "intended-tenant",
  });
  t.after(() => recoveredService.close());
  const migrated = recoveredService.getIntent(id);
  assert.equal(migrated.intent_version, "parimit-payment-intent-v2");
  assert.equal(migrated.tenant_id, "intended-tenant");
  assert.equal(migrated.state_version, 2);
  assert.equal(migrated.status, "AUTHORIZED_NO_DISPATCH");
  assert.equal(migrated.approval_count, 1);
  assert.equal(migrated.receipt?.approvals[0]?.receipt_hmac, receiptHmac);
  assert.deepEqual(recoveredService.verifyIntegrity(id), {
    valid: true,
    intent_hash_valid: true,
    approval_receipts_valid: true,
    audit_chain_valid: true,
    state_consistency_valid: true,
    failures: [],
  });
});

test("schema migration and receipt-root registration commit atomically", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-atomic-bootstrap-"));
  const databasePath = join(directory, "parimit.db");
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const prototype = ParimitService.prototype as unknown as {
    registerReceiptIntegrityRoot: () => void;
  };
  const original = prototype.registerReceiptIntegrityRoot;
  prototype.registerReceiptIntegrityRoot = () => {
    throw new Error("injected root-registration failure");
  };
  try {
    assert.throws(
      () =>
        new ParimitService({
          databasePath,
          receiptSecret: "atomic-bootstrap-receipt-secret",
        }),
      /injected root-registration failure/,
    );
  } finally {
    prototype.registerReceiptIntegrityRoot = original;
  }

  const failedDatabase = new DatabaseSync(databasePath);
  assert.equal(
    (
      failedDatabase
        .prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table'")
        .get() as { count: number }
    ).count,
    0,
  );
  failedDatabase.close();

  const recovered = new ParimitService({
    databasePath,
    receiptSecret: "atomic-bootstrap-receipt-secret",
  });
  t.after(() => recovered.close());
  const metadata = recovered.database
    .prepare("SELECT value FROM service_metadata WHERE name = ?")
    .get("receipt_integrity_root_v1") as { value: string };
  assert.match(metadata.value, /^[A-Za-z0-9_-]{43}$/);
});

test("policy configuration and its payee sets are immutable after digest binding", (t) => {
  const sourceBlocked = new Set(["blocked_demo_001"]);
  const service = new ParimitService({
    receiptSecret: "immutable-policy-configuration-secret",
    policy: {
      perTransactionLimitMinor: 1_000,
      blockedPayees: sourceBlocked,
      allowedPayees: ["merchant_demo_001"],
    },
  });
  t.after(() => service.close());
  const digest = service.policyConfigurationDigest;

  assert.throws(() => {
    (service.policy as { perTransactionLimitMinor: number }).perTransactionLimitMinor = 300_000;
  }, TypeError);
  assert.throws(() => {
    (service as unknown as { policy: unknown }).policy = {
      ...service.policy,
      perTransactionLimitMinor: 300_000,
    };
  }, TypeError);
  assert.equal(service.policy.perTransactionLimitMinor, 1_000);
  assert.equal(
    typeof (service.policy.blockedPayees as unknown as { add?: unknown }).add,
    "undefined",
  );
  assert.throws(() =>
    Set.prototype.add.call(service.policy.blockedPayees, "merchant_demo_001"),
  );
  sourceBlocked.add("merchant_demo_001");
  const envelopeAudiences = (
    service as unknown as { envelopeAudiences: ReadonlySet<string> }
  ).envelopeAudiences;
  assert.equal(typeof (envelopeAudiences as unknown as { add?: unknown }).add, "undefined");
  assert.throws(() => Set.prototype.add.call(envelopeAudiences, "urn:consumer:other"));
  assert.equal(service.policy.blockedPayees.has("merchant_demo_001"), false);
  assert.equal(service.policyConfigurationDigest, digest);
  assert.equal(service.createIntent(proposal("immutable-policy-denial", "1001")).status, "POLICY_DENIED");
});

test("invalid policy metadata and over-broad expiry fail before opening the database", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-invalid-policy-config-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const invalidRulesDatabase = join(directory, "invalid-rules.db");
  assert.throws(
    () =>
      new ParimitService({
        databasePath: invalidRulesDatabase,
        receiptSecret: "r".repeat(32),
        policy: { rulesVersion: "" },
      }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "INVALID_CONFIGURATION" &&
      error.statusCode === 500,
  );
  assert.equal(existsSync(invalidRulesDatabase), false);

  const overBroadExpiryDatabase = join(directory, "over-broad-expiry.db");
  assert.throws(
    () =>
      new ParimitService({
        databasePath: overBroadExpiryDatabase,
        receiptSecret: "e".repeat(32),
        policy: { maxExpirySeconds: 86_401 },
      }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "INVALID_CONFIGURATION" &&
      error.statusCode === 500,
  );
  assert.equal(existsSync(overBroadExpiryDatabase), false);
});

test("alpha.3 rejects ambiguous multi-audience consumer authorization", () => {
  assert.throws(
    () =>
      new ParimitService({
        receiptSecret: "multi-audience-configuration-test-secret",
        envelopeAudiences: ["urn:consumer:one", "urn:consumer:two"],
      }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "INVALID_CONFIGURATION" &&
      /exactly one envelope audience/.test(error.message),
  );
});

test("issuer and audience trust URIs preserve exact trailing slashes", (t) => {
  const service = new ParimitService({
    receiptSecret: "u".repeat(32),
    envelopeIssuer: "https://issuer.example/",
    envelopeAudiences: ["https://consumer.example/"],
  });
  t.after(() => service.close());
  const evidence = service.safetyMetadata().evidence_envelopes as {
    issuer: string;
    audiences: string[];
  };
  assert.equal(evidence.issuer, "https://issuer.example/");
  assert.deepEqual(evidence.audiences, ["https://consumer.example/"]);
});

test("legacy v1 rows cannot be promoted by lowering the threshold and rewriting the audit chain", (t) => {
  const receiptSecret = "legacy-v1-attack-fixture-secret";
  const service = new ParimitService({
    receiptSecret,
    policy: {
      perTransactionLimitMinor: 10_000,
      dailyAgentLimitMinor: 20_000,
      dualApprovalThresholdMinor: 500,
    },
  });
  t.after(() => service.close());
  const created = service.createIntent(proposal("legacy-v1-threshold-attack", "501"));
  service.approveIntent(created.id, "human-a", "approver", "APPROVE");

  const intentRow = service.database
    .prepare("SELECT * FROM intents WHERE id = ?")
    .get(created.id) as Record<string, string | number | bigint | null>;
  const legacyIntentHash = sha256(
    canonicalJson({
      version: "parimit-payment-intent-v1",
      id: created.id,
      idempotency_key: String(intentRow.idempotency_key),
      requested_by: { type: "agent", id: String(intentRow.agent_id) },
      on_behalf_of: intentRow.on_behalf_of,
      amount: { currency: "INR", minor: String(intentRow.amount_minor) },
      payee_reference: String(intentRow.payee_reference),
      purpose: String(intentRow.purpose),
      created_at: String(intentRow.created_at),
      expires_at: String(intentRow.expires_at),
    }),
  );
  const approvalRow = service.database
    .prepare("SELECT * FROM approvals WHERE intent_id = ?")
    .get(created.id) as Record<string, string | number | bigint | null>;
  const legacyReceipt = hmacSha256(receiptSecret, {
    version: "parimit-approval-receipt-v1",
    intent_id: created.id,
    intent_hash: legacyIntentHash,
    actor_id: String(approvalRow.actor_id),
    actor_role: String(approvalRow.actor_role),
    decision: String(approvalRow.decision),
    created_at: String(approvalRow.created_at),
  });
  service.database
    .prepare(
      `UPDATE intents
          SET intent_version = 'parimit-payment-intent-v1', intent_hash = ?
        WHERE id = ?`,
    )
    .run(legacyIntentHash, created.id);
  service.database
    .prepare("UPDATE approvals SET intent_hash = ?, receipt_hmac = ? WHERE intent_id = ?")
    .run(legacyIntentHash, legacyReceipt, created.id);

  const rewriteUnkeyedAuditChain = (lowerThreshold: boolean): void => {
    const rows = service.database
      .prepare("SELECT * FROM audit_events WHERE intent_id = ? ORDER BY sequence")
      .all(created.id) as Array<Record<string, string | number | bigint | null>>;
    let previousHash = "GENESIS";
    for (const row of rows) {
      const payload = JSON.parse(String(row.payload)) as Record<string, unknown>;
      if (String(row.event_type) === "PROPOSAL_CREATED") {
        payload.intent_hash = legacyIntentHash;
        const storedPolicy = payload.policy as Record<string, unknown>;
        storedPolicy.required_approvals = lowerThreshold ? 1 : 2;
        storedPolicy.reasons = [
          lowerThreshold ? "HUMAN_APPROVAL_REQUIRED" : "DISTINCT_DUAL_APPROVAL_REQUIRED",
        ];
      } else if (String(row.event_type) === "HUMAN_APPROVAL_RECORDED") {
        payload.intent_hash = legacyIntentHash;
        payload.receipt_hmac = legacyReceipt;
        payload.resulting_status = lowerThreshold
          ? "AUTHORIZED_NO_DISPATCH"
          : "AWAITING_APPROVAL";
      }
      const normalizedPayload = canonicalJson(payload);
      const eventHash = sha256(
        canonicalJson({
          intent_id: created.id,
          event_type: String(row.event_type),
          actor_id: String(row.actor_id),
          payload,
          occurred_at: String(row.occurred_at),
          previous_hash: previousHash,
        }),
      );
      service.database
        .prepare(
          `UPDATE audit_events
              SET payload = ?, previous_hash = ?, event_hash = ?
            WHERE sequence = ?`,
        )
        .run(normalizedPayload, previousHash, eventHash, row.sequence);
      previousHash = eventHash;
    }
  };

  // Establish a coherent pre-hardening v1 fixture with one of two approvals.
  rewriteUnkeyedAuditChain(false);
  assert.equal(service.verifyIntegrity(created.id).valid, true);
  assert.throws(
    () => service.approveIntent(created.id, "human-b", "admin", "APPROVE"),
    (error: unknown) =>
      error instanceof ParimitError && error.code === "LEGACY_INTENT_READ_ONLY",
  );

  // The attacker has database access but not the receipt secret. They retain
  // the one valid HMAC and rewrite only unkeyed state, policy, and audit data.
  service.database
    .prepare(
      `UPDATE intents
          SET required_approvals = 1,
              policy_reasons = ?,
              status = 'AUTHORIZED_NO_DISPATCH'
        WHERE id = ?`,
    )
    .run(canonicalJson(["HUMAN_APPROVAL_REQUIRED"]), created.id);
  rewriteUnkeyedAuditChain(true);
  const receiptAfterAttack = service.database
    .prepare("SELECT receipt_hmac FROM approvals WHERE intent_id = ?")
    .get(created.id) as Record<string, string | number | bigint | null>;
  assert.equal(receiptAfterAttack.receipt_hmac, legacyReceipt);

  const report = service.verifyIntegrity(created.id);
  assert.equal(report.intent_hash_valid, true);
  assert.equal(report.approval_receipts_valid, true);
  assert.equal(report.audit_chain_valid, true);
  assert.equal(report.state_consistency_valid, false);
  assert.equal(report.valid, false);
  assert.ok(report.failures.includes("LEGACY_V1_AUTHORIZATION_UNTRUSTED"));
  assert.throws(
    () => service.getIntent(created.id),
    (error: unknown) => error instanceof ParimitError && error.code === "INTEGRITY_FAILURE",
  );
});

test("idempotency replays the same proposal and rejects key reuse with different content", (t) => {
  const service = new ParimitService({ receiptSecret: "test-secret" });
  t.after(() => service.close());
  const first = service.createIntent(proposal("stable-key", "250"));
  const replay = service.createIntent(proposal("stable-key", "250"));
  assert.equal(replay.id, first.id);
  assert.equal(replay.idempotent_replay, true);
  assert.throws(
    () => service.createIntent(proposal("stable-key", "251")),
    (error: unknown) => error instanceof ParimitError && error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("enforces per-transaction, daily exposure, blocklist and optional allowlist policies", (t) => {
  const service = new ParimitService({
    receiptSecret: "test-secret",
    policy: {
      perTransactionLimitMinor: 1_000,
      dailyAgentLimitMinor: 1_500,
      dualApprovalThresholdMinor: 500,
      blockedPayees: ["blocked_demo_001"],
      allowedPayees: ["merchant_demo_001", "blocked_demo_001"],
    },
  });
  t.after(() => service.close());

  const tooLarge = service.createIntent(proposal("limit-per-tx", "1001"));
  assert.equal(tooLarge.status, "POLICY_DENIED");
  assert.ok(tooLarge.policy.reasons.includes("PER_TRANSACTION_LIMIT_EXCEEDED"));

  const blocked = service.createIntent(
    proposal("limit-blocked", "10", { payee_reference: "blocked_demo_001" }),
  );
  assert.equal(blocked.status, "POLICY_DENIED");
  assert.ok(blocked.policy.reasons.includes("PAYEE_BLOCKED"));

  const unlisted = service.createIntent(
    proposal("limit-allowlist", "10", { payee_reference: "other_demo_001" }),
  );
  assert.equal(unlisted.status, "POLICY_DENIED");
  assert.ok(unlisted.policy.reasons.includes("PAYEE_NOT_ALLOWLISTED"));

  assert.equal(service.createIntent(proposal("limit-daily-1", "800")).status, "AWAITING_APPROVAL");
  const overDaily = service.createIntent(proposal("limit-daily-2", "701"));
  assert.equal(overDaily.status, "POLICY_DENIED");
  assert.ok(overDaily.policy.reasons.includes("DAILY_AGENT_LIMIT_EXCEEDED"));
});

test("agents cannot approve and high-value proposals require two distinct humans", (t) => {
  const service = new ParimitService({
    receiptSecret: "a-long-test-receipt-secret",
    policy: {
      perTransactionLimitMinor: 10_000,
      dailyAgentLimitMinor: 20_000,
      dualApprovalThresholdMinor: 500,
    },
  });
  t.after(() => service.close());
  const created = service.createIntent(proposal("dual-approval", "501"));
  assert.equal(created.required_approvals, 2);

  assert.throws(
    () => service.approveIntent(created.id, "agent-demo", "agent", "APPROVE"),
    (error: unknown) =>
      error instanceof ParimitError &&
      (error.code === "HUMAN_APPROVER_REQUIRED" || error.code === "AGENT_CANNOT_APPROVE"),
  );
  assert.throws(
    () => service.approveIntent(created.id, "agent-demo", "approver", "APPROVE"),
    (error: unknown) => error instanceof ParimitError && error.code === "AGENT_CANNOT_APPROVE",
  );

  const first = service.approveIntent(created.id, "human-a", "approver", "APPROVE");
  assert.equal(first.status, "AWAITING_APPROVAL");
  assert.equal(first.approval_count, 1);
  assert.throws(
    () => service.approveIntent(created.id, "human-a", "approver", "APPROVE"),
    (error: unknown) => error instanceof ParimitError && error.code === "DUPLICATE_APPROVER",
  );

  const second = service.approveIntent(created.id, "human-b", "admin", "APPROVE");
  assert.equal(second.status, "AUTHORIZED_NO_DISPATCH");
  assert.equal(second.approval_count, 2);
  assert.equal(second.receipt?.execution_authorized, false);
  assert.equal(second.receipt?.version, "parimit-approval-receipt-v1");
  assert.equal(second.receipt?.intent_hash, second.intent_hash);
  assert.equal(second.receipt?.approvals.length, 2);
  assert.equal(service.verifyIntegrity(created.id).valid, true);
});

test("clock rollback cannot commit approval, cancellation, observation, or audit evidence", (t) => {
  let now = new Date("2026-09-20T10:00:01.900Z");
  const approvalService = new ParimitService({
    receiptSecret: "approval-clock-rollback-secret",
    clock: () => now,
  });
  t.after(() => approvalService.close());
  const approvalIntent = approvalService.createIntent(proposal("approval-clock-rollback"));
  now = new Date("2026-09-20T10:00:01.100Z");
  assert.throws(
    () => approvalService.approveIntent(approvalIntent.id, "human-a", "approver", "APPROVE"),
    (error: unknown) =>
      error instanceof ParimitError && error.code === "CLOCK_ROLLBACK_DETECTED",
  );
  assert.equal(approvalService.getIntent(approvalIntent.id).approval_count, 0);
  assert.equal(approvalService.getIntent(approvalIntent.id).state_version, 1);
  assert.equal(approvalService.verifyIntegrity(approvalIntent.id).valid, true);

  now = new Date("2026-09-20T10:01:01.900Z");
  const cancellationService = new ParimitService({
    receiptSecret: "cancellation-clock-rollback-secret",
    clock: () => now,
  });
  t.after(() => cancellationService.close());
  const cancellationIntent = cancellationService.createIntent(
    proposal("cancellation-clock-rollback"),
  );
  now = new Date("2026-09-20T10:01:01.100Z");
  assert.throws(
    () => cancellationService.cancelIntent(cancellationIntent.id, "agent-demo", "agent"),
    (error: unknown) =>
      error instanceof ParimitError && error.code === "CLOCK_ROLLBACK_DETECTED",
  );
  assert.equal(cancellationService.getIntent(cancellationIntent.id).status, "AWAITING_APPROVAL");
  assert.equal(cancellationService.getIntent(cancellationIntent.id).state_version, 1);

  now = new Date("2026-09-20T10:02:01.000Z");
  const observationService = new ParimitService({
    receiptSecret: "observation-clock-rollback-secret",
    clock: () => now,
  });
  t.after(() => observationService.close());
  const observationIntent = observationService.createIntent(
    proposal("observation-clock-rollback"),
  );
  now = new Date("2026-09-20T10:02:02.900Z");
  observationService.approveIntent(
    observationIntent.id,
    "human-observer",
    "approver",
    "APPROVE",
  );
  now = new Date("2026-09-20T10:02:03.900Z");
  observationService.recordMockObservation(observationIntent.id, "PENDING");
  now = new Date("2026-09-20T10:02:03.100Z");
  assert.throws(
    () => observationService.recordMockObservation(observationIntent.id, "SUCCEEDED"),
    (error: unknown) =>
      error instanceof ParimitError && error.code === "CLOCK_ROLLBACK_DETECTED",
  );
  assert.equal(observationService.getIntent(observationIntent.id).observation?.status, "PENDING");
  assert.equal(observationService.verifyIntegrity(observationIntent.id).valid, true);

  appendForgedAuditEvent(
    observationService,
    observationIntent.id,
    "FORGED_NON_MONOTONIC_EVENT",
    "attacker",
    { note: "cryptographically rehashed but chronologically false" },
    "2026-09-20T10:02:03.200Z",
  );
  const chronologyReport = observationService.verifyIntegrity(observationIntent.id);
  assert.equal(chronologyReport.audit_chain_valid, false);
  assert.ok(
    chronologyReport.failures.some((failure) =>
      failure.startsWith("AUDIT_CHRONOLOGY_INVALID:"),
    ),
  );
});

test("rejection is terminal and mock observations require full authorization", (t) => {
  const service = new ParimitService({ receiptSecret: "test-secret" });
  t.after(() => service.close());
  const created = service.createIntent(proposal("rejection", "100"));
  assert.throws(
    () => service.recordMockObservation(created.id, "PENDING"),
    (error: unknown) => error instanceof ParimitError && error.code === "INVALID_STATE",
  );
  const rejected = service.approveIntent(created.id, "human-reviewer", "approver", "REJECT");
  assert.equal(rejected.status, "REJECTED");
  assert.throws(
    () => service.approveIntent(created.id, "human-other", "approver", "APPROVE"),
    (error: unknown) => error instanceof ParimitError && error.code === "INVALID_STATE",
  );

  const partiallyApproved = service.createIntent(proposal("partial-then-reject", "60000"));
  service.approveIntent(partiallyApproved.id, "partial-human-a", "approver", "APPROVE");
  const rejectedAfterOne = service.approveIntent(
    partiallyApproved.id,
    "partial-human-b",
    "approver",
    "REJECT",
  );
  assert.equal(rejectedAfterOne.status, "REJECTED");
  assert.equal(service.verifyIntegrity(partiallyApproved.id).valid, true);
});

test("intent expiry is enforced before a late approval", (t) => {
  let now = new Date("2026-09-19T10:00:00.000Z");
  const service = new ParimitService({
    receiptSecret: "test-secret",
    clock: () => new Date(now),
  });
  t.after(() => service.close());
  const created = service.createIntent(proposal("expires", "100", { expires_in_seconds: 1 }));
  now = new Date("2026-09-19T10:00:02.000Z");
  assert.equal(service.getIntent(created.id).status, "EXPIRED");
  assert.throws(
    () => service.approveIntent(created.id, "human-a", "approver", "APPROVE"),
    (error: unknown) => error instanceof ParimitError && error.code === "INVALID_STATE",
  );
  assert.ok(service.getAudit(created.id).some((event) => event.event_type === "PROPOSAL_EXPIRED"));
});

test("cancellation rechecks expiry inside the state transition", (t) => {
  const createdAt = new Date("2026-09-19T11:00:00.000Z");
  let cancellationClock = false;
  let cancellationClockReads = 0;
  const service = new ParimitService({
    receiptSecret: "cancellation-expiry-test-secret",
    clock: () => {
      if (!cancellationClock) return new Date(createdAt);
      cancellationClockReads += 1;
      return new Date(
        cancellationClockReads === 1
          ? "2026-09-19T11:00:00.999Z"
          : "2026-09-19T11:00:01.000Z",
      );
    },
  });
  t.after(() => service.close());
  const created = service.createIntent(
    proposal("cancel-at-expiry", "100", { expires_in_seconds: 1 }),
  );
  cancellationClock = true;
  assert.throws(
    () => service.cancelIntent(created.id, "agent-demo", "agent"),
    (error: unknown) => error instanceof ParimitError && error.code === "PROPOSAL_EXPIRED",
  );
  assert.equal(service.getIntent(created.id).status, "EXPIRED");
  const eventTypes = service.getAudit(created.id).map((event) => event.event_type);
  assert.equal(eventTypes.filter((event) => event === "PROPOSAL_EXPIRED").length, 1);
  assert.equal(eventTypes.includes("PROPOSAL_CANCELLED"), false);
});

test("tampering with intent fields, approval receipts, or audit events is detected", (t) => {
  const intentService = new ParimitService({ receiptSecret: "receipt-secret" });
  t.after(() => intentService.close());
  const intent = intentService.createIntent(proposal("tamper-intent", "100"));
  intentService.database.prepare("UPDATE intents SET amount_minor = 101 WHERE id = ?").run(intent.id);
  const intentReport = intentService.verifyIntegrity(intent.id);
  assert.equal(intentReport.intent_hash_valid, false);
  assert.equal(intentReport.valid, false);
  assert.throws(
    () => intentService.getIntent(intent.id),
    (error: unknown) => error instanceof ParimitError && error.code === "INTEGRITY_FAILURE",
  );

  const receiptService = new ParimitService({ receiptSecret: "receipt-secret" });
  t.after(() => receiptService.close());
  const receiptIntent = receiptService.createIntent(proposal("tamper-receipt", "100"));
  receiptService.approveIntent(receiptIntent.id, "human-a", "approver", "APPROVE");
  receiptService.database
    .prepare("UPDATE approvals SET receipt_hmac = 'tampered' WHERE intent_id = ?")
    .run(receiptIntent.id);
  const receiptReport = receiptService.verifyIntegrity(receiptIntent.id);
  assert.equal(receiptReport.approval_receipts_valid, false);
  assert.equal(receiptReport.valid, false);

  const auditService = new ParimitService({ receiptSecret: "receipt-secret" });
  t.after(() => auditService.close());
  const auditIntent = auditService.createIntent(proposal("tamper-audit", "100"));
  auditService.database
    .prepare("UPDATE audit_events SET payload = '{\"tampered\":true}' WHERE intent_id = ?")
    .run(auditIntent.id);
  const auditReport = auditService.verifyIntegrity(auditIntent.id);
  assert.equal(auditReport.audit_chain_valid, false);
  assert.equal(auditReport.valid, false);
});

test("mock observation rows are reconciled exactly with their hash-linked audit events", (t) => {
  const createAuthorized = (
    key: string,
  ): { service: ParimitService; id: string; createdAt: string } => {
    const service = new ParimitService({ receiptSecret: `observation-integrity-${key}` });
    t.after(() => service.close());
    const intent = service.createIntent(proposal(key, "100"));
    service.approveIntent(intent.id, "human-a", "approver", "APPROVE");
    return { service, id: intent.id, createdAt: intent.created_at };
  };
  const createObserved = (
    key: string,
    status: "PENDING" | "SUCCEEDED" | "FAILED" | "IN_DOUBT" = "SUCCEEDED",
    providerReference = "mock-ref-original",
  ): { service: ParimitService; id: string; createdAt: string } => {
    const fixture = createAuthorized(key);
    fixture.service.recordMockObservation(fixture.id, status, providerReference);
    return fixture;
  };
  const assertFailsClosed = (
    service: ParimitService,
    id: string,
    expectedFailure: string,
  ): void => {
    const report = service.verifyIntegrity(id);
    assert.equal(report.intent_hash_valid, true);
    assert.equal(report.approval_receipts_valid, true);
    assert.equal(report.audit_chain_valid, true);
    assert.equal(report.state_consistency_valid, false);
    assert.equal(report.valid, false);
    assert.ok(
      report.failures.some((failure) => failure.startsWith(expectedFailure)),
      `${expectedFailure}: ${report.failures.join(", ")}`,
    );
    for (const read of [() => service.getIntent(id), () => service.getAudit(id)]) {
      assert.throws(
        read,
        (error: unknown) => error instanceof ParimitError && error.code === "INTEGRITY_FAILURE",
      );
    }
  };

  const statusTamper = createObserved("observation-status-tamper");
  statusTamper.service.database
    .prepare("UPDATE observations SET status = 'FAILED' WHERE intent_id = ?")
    .run(statusTamper.id);
  assertFailsClosed(statusTamper.service, statusTamper.id, "OBSERVATION_AUDIT_MISMATCH:");
  assert.throws(
    () => statusTamper.service.listIntents({ agentId: "agent-demo" }),
    (error: unknown) => error instanceof ParimitError && error.code === "INTEGRITY_FAILURE",
  );

  const referenceTamper = createObserved("observation-reference-tamper");
  referenceTamper.service.database
    .prepare("UPDATE observations SET provider_reference = 'mock-ref-tampered' WHERE intent_id = ?")
    .run(referenceTamper.id);
  assertFailsClosed(referenceTamper.service, referenceTamper.id, "OBSERVATION_AUDIT_MISMATCH:");

  const timestampTamper = createObserved("observation-timestamp-tamper");
  timestampTamper.service.database
    .prepare("UPDATE observations SET observed_at = '2099-01-01T00:00:00.000Z' WHERE intent_id = ?")
    .run(timestampTamper.id);
  assertFailsClosed(timestampTamper.service, timestampTamper.id, "OBSERVATION_AUDIT_MISMATCH:");

  const sourceTamper = createObserved("observation-source-tamper");
  sourceTamper.service.database.exec("PRAGMA ignore_check_constraints = ON");
  sourceTamper.service.database
    .prepare("UPDATE observations SET source = 'FORGED_SOURCE' WHERE intent_id = ?")
    .run(sourceTamper.id);
  assertFailsClosed(sourceTamper.service, sourceTamper.id, "OBSERVATION_SEMANTICS_INVALID:");

  const deletion = createObserved("observation-deletion");
  deletion.service.database.prepare("DELETE FROM observations WHERE intent_id = ?").run(deletion.id);
  assertFailsClosed(deletion.service, deletion.id, "OBSERVATION_AUDIT_COUNT_MISMATCH");

  const insertion = createAuthorized("observation-insertion");
  const insertedAt = new Date(Date.parse(insertion.createdAt) + 1_000).toISOString();
  insertion.service.database
    .prepare(
      `INSERT INTO observations (id, intent_id, status, provider_reference, observed_at, source)
       VALUES ('forged-observation', ?, 'SUCCEEDED', 'mock-ref-forged', ?, 'DEMO_MOCK')`,
    )
    .run(insertion.id, insertedAt);
  assertFailsClosed(insertion.service, insertion.id, "OBSERVATION_AUDIT_COUNT_MISMATCH");

  const reordered = createAuthorized("observation-reordering");
  reordered.service.recordMockObservation(reordered.id, "PENDING", "mock-ref-first");
  reordered.service.recordMockObservation(reordered.id, "SUCCEEDED", "mock-ref-second");
  const stored = reordered.service.database
    .prepare("SELECT rowid, id FROM observations WHERE intent_id = ? ORDER BY rowid")
    .all(reordered.id) as Array<Record<string, string | number | bigint | null>>;
  reordered.service.database
    .prepare("UPDATE observations SET rowid = ? WHERE id = ?")
    .run(Number(stored[1].rowid) + 1_000, stored[0].id);
  assertFailsClosed(reordered.service, reordered.id, "OBSERVATION_AUDIT_MISMATCH:");
});

test("v2 intent digest binds the policy snapshot, initial state, and digest version", (t) => {
  const cases: Array<{ column: string; value: string | number }> = [
    { column: "policy_allowed", value: 0 },
    {
      column: "policy_reasons",
      value: '["HUMAN_APPROVAL_REQUIRED","PAYEE_BLOCKED"]',
    },
    { column: "rules_version", value: "attacker-policy-v99" },
    { column: "required_approvals", value: 2 },
    { column: "initial_status", value: "POLICY_DENIED" },
    { column: "intent_version", value: "parimit-payment-intent-v1" },
  ];

  for (const [index, item] of cases.entries()) {
    const service = new ParimitService({ receiptSecret: `policy-binding-${index}` });
    t.after(() => service.close());
    const intent = service.createIntent(proposal(`policy-binding-${index}`, "100"));
    service.database
      .prepare(`UPDATE intents SET ${item.column} = ? WHERE id = ?`)
      .run(item.value, intent.id);
    const report = service.verifyIntegrity(intent.id);
    assert.equal(report.intent_hash_valid, false, item.column);
    assert.equal(report.valid, false, item.column);
    assert.throws(
      () => service.getIntent(intent.id),
      (error: unknown) => error instanceof ParimitError && error.code === "INTEGRITY_FAILURE",
      item.column,
    );
  }
});

test("authorization state requires the configured number of valid distinct approvals", (t) => {
  const forgedStateService = new ParimitService({
    receiptSecret: "forged-state-secret",
    policy: {
      perTransactionLimitMinor: 10_000,
      dailyAgentLimitMinor: 20_000,
      dualApprovalThresholdMinor: 500,
    },
  });
  t.after(() => forgedStateService.close());
  const forged = forgedStateService.createIntent(proposal("forged-authorization", "501"));
  forgedStateService.database
    .prepare("UPDATE intents SET status = 'AUTHORIZED_NO_DISPATCH' WHERE id = ?")
    .run(forged.id);
  const forgedReport = forgedStateService.verifyIntegrity(forged.id);
  assert.equal(forgedReport.intent_hash_valid, true);
  assert.equal(forgedReport.approval_receipts_valid, true);
  assert.equal(forgedReport.audit_chain_valid, true);
  assert.equal(forgedReport.state_consistency_valid, false);
  assert.ok(forgedReport.failures.includes("AUTHORIZED_APPROVAL_THRESHOLD_NOT_MET"));
  assert.ok(forgedReport.failures.includes("STATUS_AUDIT_MISMATCH"));

  const deletedApprovalService = new ParimitService({
    receiptSecret: "deleted-approval-secret",
    policy: {
      perTransactionLimitMinor: 10_000,
      dailyAgentLimitMinor: 20_000,
      dualApprovalThresholdMinor: 500,
    },
  });
  t.after(() => deletedApprovalService.close());
  const authorized = deletedApprovalService.createIntent(proposal("deleted-approval", "501"));
  deletedApprovalService.approveIntent(authorized.id, "human-a", "approver", "APPROVE");
  deletedApprovalService.approveIntent(authorized.id, "human-b", "admin", "APPROVE");
  deletedApprovalService.database
    .prepare("DELETE FROM approvals WHERE intent_id = ? AND actor_id = 'human-b'")
    .run(authorized.id);
  const deletedReport = deletedApprovalService.verifyIntegrity(authorized.id);
  assert.equal(deletedReport.intent_hash_valid, true);
  assert.equal(deletedReport.approval_receipts_valid, true);
  assert.equal(deletedReport.audit_chain_valid, true);
  assert.equal(deletedReport.state_consistency_valid, false);
  assert.ok(deletedReport.failures.includes("AUTHORIZED_APPROVAL_THRESHOLD_NOT_MET"));
  assert.ok(deletedReport.failures.includes("APPROVAL_AUDIT_COUNT_MISMATCH"));

  const rejectionSecret = "rejected-after-threshold-secret";
  const rejectedService = new ParimitService({
    receiptSecret: rejectionSecret,
    policy: {
      perTransactionLimitMinor: 10_000,
      dailyAgentLimitMinor: 20_000,
      dualApprovalThresholdMinor: 500,
    },
  });
  t.after(() => rejectedService.close());
  const rejected = rejectedService.createIntent(proposal("rejected-after-threshold", "501"));
  rejectedService.approveIntent(rejected.id, "threshold-human-a", "approver", "APPROVE");
  const authorizedAfterSecond = rejectedService.approveIntent(
    rejected.id,
    "threshold-human-b",
    "admin",
    "APPROVE",
  );
  const rejectedAt = new Date(
    Date.parse(authorizedAfterSecond.approvals.at(-1)!.created_at) + 1_000,
  ).toISOString();
  const rejectionReceipt = hmacSha256(rejectionSecret, {
    version: "parimit-approval-receipt-v1",
    intent_id: rejected.id,
    intent_hash: rejected.intent_hash,
    actor_id: "threshold-human-c",
    actor_role: "approver",
    decision: "REJECT",
    created_at: rejectedAt,
  });
  rejectedService.database
    .prepare(
      `INSERT INTO approvals
        (id, intent_id, actor_id, actor_role, decision, intent_hash, created_at, receipt_hmac)
       VALUES ('forged-late-rejection', ?, 'threshold-human-c', 'approver', 'REJECT', ?, ?, ?)`,
    )
    .run(rejected.id, rejected.intent_hash, rejectedAt, rejectionReceipt);
  rejectedService.database
    .prepare("UPDATE intents SET status = 'REJECTED' WHERE id = ?")
    .run(rejected.id);
  appendForgedAuditEvent(
    rejectedService,
    rejected.id,
    "HUMAN_REJECTION_RECORDED",
    "threshold-human-c",
    {
      actor_role: "approver",
      decision: "REJECT",
      intent_hash: rejected.intent_hash,
      receipt_hmac: rejectionReceipt,
      resulting_status: "REJECTED",
    },
    rejectedAt,
  );
  const rejectedReport = rejectedService.verifyIntegrity(rejected.id);
  assert.equal(rejectedReport.approval_receipts_valid, true);
  assert.equal(rejectedReport.audit_chain_valid, true);
  assert.equal(rejectedReport.state_consistency_valid, false);
  assert.ok(rejectedReport.failures.includes("REJECTED_STATE_MISMATCH"));
});

test("approval audit events bind the event type to the signed decision", (t) => {
  const service = new ParimitService({ receiptSecret: "review-event-type-secret" });
  t.after(() => service.close());

  const created = service.createIntent(proposal("review-event-type", "100"));
  service.approveIntent(created.id, "human-a", "approver", "APPROVE");
  const row = service.database
    .prepare(
      `SELECT sequence, actor_id, payload, occurred_at, previous_hash
         FROM audit_events
        WHERE intent_id = ? AND event_type = 'HUMAN_APPROVAL_RECORDED'`,
    )
    .get(created.id) as Record<string, string | number | bigint | null>;
  const relabeledEventType = "HUMAN_REJECTION_RECORDED";
  const payload = JSON.parse(String(row.payload)) as unknown;
  const eventHash = sha256(
    canonicalJson({
      intent_id: created.id,
      event_type: relabeledEventType,
      actor_id: String(row.actor_id),
      payload,
      occurred_at: String(row.occurred_at),
      previous_hash: String(row.previous_hash),
    }),
  );
  service.database
    .prepare("UPDATE audit_events SET event_type = ?, event_hash = ? WHERE sequence = ?")
    .run(relabeledEventType, eventHash, row.sequence);

  const report = service.verifyIntegrity(created.id);
  assert.equal(report.audit_chain_valid, true);
  assert.equal(report.approval_receipts_valid, true);
  assert.equal(report.state_consistency_valid, false);
  assert.ok(report.failures.includes("APPROVAL_AUDIT_MISMATCH:human-a"));
});

test("IN_DOUBT freezes every later mock observation because alpha has no reconciliation authority", (t) => {
  const service = new ParimitService({ receiptSecret: "receipt-secret" });
  t.after(() => service.close());
  const created = service.createIntent(proposal("in-doubt", "100"));
  service.approveIntent(created.id, "human-a", "approver", "APPROVE");
  const observed = service.recordMockObservation(created.id, "IN_DOUBT", "mock-ref-1");
  assert.equal(observed.status, "AUTHORIZED_NO_DISPATCH");
  assert.equal(observed.observation?.status, "IN_DOUBT");
  assert.equal(observed.observation?.retry_permitted, false);
  for (const laterStatus of ["SUCCEEDED", "FAILED", "IN_DOUBT"] as const) {
    assert.throws(
      () => service.recordMockObservation(created.id, laterStatus, "mock-ref-later"),
      (error: unknown) =>
        error instanceof ParimitError &&
        error.code === "IN_DOUBT_FROZEN" &&
        error.statusCode === 409,
    );
  }
  assert.equal(service.getIntent(created.id).observation?.status, "IN_DOUBT");
  assert.equal(
    service
      .getAudit(created.id)
      .filter((event) => event.event_type === "DEMO_MOCK_OBSERVATION_RECORDED").length,
    1,
  );
  assert.ok(
    service
      .getAudit(created.id)
      .some(
        (event) =>
          event.event_type === "DEMO_MOCK_OBSERVATION_RECORDED" &&
          (event.payload as Record<string, unknown>).retry_permitted === false,
      ),
  );

  const inDoubtAt = observed.observation!.observed_at;
  const forgedAt = new Date(Date.parse(inDoubtAt) + 1_000).toISOString();
  const forgedObservationId = "forged-after-in-doubt";
  service.database
    .prepare(
      `INSERT INTO observations (id, intent_id, status, provider_reference, observed_at, source)
       VALUES (?, ?, 'SUCCEEDED', 'mock-ref-forged-later', ?, 'DEMO_MOCK')`,
    )
    .run(forgedObservationId, created.id, forgedAt);
  appendForgedAuditEvent(
    service,
    created.id,
    "DEMO_MOCK_OBSERVATION_RECORDED",
    "forged-operator",
    {
      observation_id: forgedObservationId,
      status: "SUCCEEDED",
      provider_reference: "mock-ref-forged-later",
      source: "DEMO_MOCK",
      retry_permitted: false,
      moves_money: false,
    },
    forgedAt,
  );
  const forgedReport = service.verifyIntegrity(created.id);
  assert.equal(forgedReport.audit_chain_valid, true);
  assert.equal(forgedReport.state_consistency_valid, false);
  assert.ok(
    forgedReport.failures.includes(`OBSERVATION_AFTER_IN_DOUBT:${forgedObservationId}`),
  );
});
