import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, hmacSha256, safeEqualText, sha256 } from "./crypto.ts";
import { ParimitError } from "./errors.ts";
import {
  INTENT_STATUSES,
  OBSERVATION_STATUSES,
  type ActorRole,
  type ApprovalDecision,
  type ApprovalReceiptView,
  type ApprovalView,
  type AuditEventView,
  type ParimitServiceOptions,
  type IntegrityReport,
  type InitialIntentStatus,
  type IntentStatus,
  type IntentView,
  type NormalizedPaymentProposal,
  type ObservationStatus,
  type ObservationView,
  type PaymentProposalInput,
  type PaymentIntentVersion,
  type PolicyConfig,
  type PolicyDecision,
} from "./types.ts";

type SqlRow = Record<string, string | number | bigint | null>;

const DEFAULT_POLICY: PolicyConfig = {
  rulesVersion: "parimit-policy-v1",
  perTransactionLimitMinor: 100_000,
  dailyAgentLimitMinor: 500_000,
  dualApprovalThresholdMinor: 50_000,
  defaultExpirySeconds: 1_800,
  maxExpirySeconds: 86_400,
  blockedPayees: new Set<string>(),
  allowedPayees: null,
};

const APPROVAL_NOTICE =
  "This receipt proves human approval of the exact proposal. It is not an instruction to move funds.";

const LEGACY_INTENT_VERSION: PaymentIntentVersion = "parimit-payment-intent-v1";
const CURRENT_INTENT_VERSION: PaymentIntentVersion = "parimit-payment-intent-v2";
const APPROVAL_POLICY_REASONS = new Set([
  "HUMAN_APPROVAL_REQUIRED",
  "DISTINCT_DUAL_APPROVAL_REQUIRED",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  field: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new ParimitError(
      "VALIDATION_ERROR",
      `${field} contains unsupported field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`,
      400,
    );
  }
}

function requireString(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.trim() !== value) {
    throw new ParimitError(
      "VALIDATION_ERROR",
      `${field} must be a non-empty string of at most ${maximum} characters without surrounding whitespace`,
      400,
    );
  }
  if (/\p{Cc}/u.test(value)) {
    throw new ParimitError("VALIDATION_ERROR", `${field} cannot contain control characters`, 400);
  }
  return value;
}

function requireIdentifier(value: unknown, field: string): string {
  const identifier = requireString(value, field, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$/.test(identifier)) {
    throw new ParimitError(
      "VALIDATION_ERROR",
      `${field} contains unsupported characters`,
      400,
    );
  }
  return identifier;
}

function requireOpaquePayeeReference(value: unknown): string {
  const reference = requireString(value, "payee_reference", 64);
  if (!/^[A-Za-z][A-Za-z0-9:_-]{5,63}$/.test(reference)) {
    throw new ParimitError(
      "VALIDATION_ERROR",
      "payee_reference must be an opaque 6-64 character alias; payment addresses and account identifiers are forbidden",
      400,
    );
  }
  return reference;
}

function requireSafePositiveInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ParimitError("INVALID_CONFIGURATION", `${field} must be a positive safe integer`, 500);
  }
  return value;
}

function normalizePayeeSet(values: Iterable<string>): ReadonlySet<string> {
  return new Set(Array.from(values, (value) => value.trim().toLocaleLowerCase("en-US")).filter(Boolean));
}

function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

function requiredRow(row: SqlRow | undefined, message = "Payment proposal not found"): SqlRow {
  if (!row) throw new ParimitError("NOT_FOUND", message, 404);
  return row;
}

function stringCell(row: SqlRow, key: string): string {
  return String(row[key]);
}

function numberCell(row: SqlRow, key: string): number {
  return Number(row[key]);
}

export function normalizePaymentProposal(
  value: unknown,
  defaultExpirySeconds = DEFAULT_POLICY.defaultExpirySeconds,
  maxExpirySeconds = DEFAULT_POLICY.maxExpirySeconds,
): NormalizedPaymentProposal {
  if (!isRecord(value)) {
    throw new ParimitError("VALIDATION_ERROR", "Request body must be a JSON object", 400);
  }
  rejectUnknownKeys(
    value,
    new Set([
      "idempotency_key",
      "requested_by",
      "on_behalf_of",
      "amount",
      "payee_reference",
      "purpose",
      "expires_in_seconds",
    ]),
    "Request body",
  );
  if (!isRecord(value.requested_by) || value.requested_by.type !== "agent") {
    throw new ParimitError("VALIDATION_ERROR", "requested_by.type must be 'agent'", 400);
  }
  rejectUnknownKeys(value.requested_by, new Set(["type", "id"]), "requested_by");
  if (!isRecord(value.amount) || value.amount.currency !== "INR") {
    throw new ParimitError("VALIDATION_ERROR", "amount.currency must be 'INR'", 400);
  }
  rejectUnknownKeys(value.amount, new Set(["currency", "minor"]), "amount");
  if (typeof value.amount.minor !== "string" || !/^[1-9][0-9]*$/.test(value.amount.minor)) {
    throw new ParimitError(
      "VALIDATION_ERROR",
      "amount.minor must be a positive decimal string containing INR minor units (paise)",
      400,
    );
  }
  const amountMinor = Number(value.amount.minor);
  if (!Number.isSafeInteger(amountMinor)) {
    throw new ParimitError("VALIDATION_ERROR", "amount.minor exceeds the safe supported range", 400);
  }
  const expiry = value.expires_in_seconds ?? defaultExpirySeconds;
  if (!Number.isInteger(expiry) || (expiry as number) < 1 || (expiry as number) > maxExpirySeconds) {
    throw new ParimitError(
      "VALIDATION_ERROR",
      `expires_in_seconds must be an integer between 1 and ${maxExpirySeconds}`,
      400,
    );
  }
  let onBehalfOf: string | null = null;
  if (value.on_behalf_of !== undefined) {
    onBehalfOf = requireIdentifier(value.on_behalf_of, "on_behalf_of");
  }
  return {
    idempotencyKey: requireIdentifier(value.idempotency_key, "idempotency_key"),
    agentId: requireIdentifier(value.requested_by.id, "requested_by.id"),
    onBehalfOf,
    amountMinor,
    currency: "INR",
    payeeReference: requireOpaquePayeeReference(value.payee_reference),
    purpose: requireString(value.purpose, "purpose", 500),
    expiresInSeconds: expiry as number,
  };
}

function originalRequestShape(input: NormalizedPaymentProposal): PaymentProposalInput {
  return {
    idempotency_key: input.idempotencyKey,
    requested_by: { type: "agent", id: input.agentId },
    ...(input.onBehalfOf === null ? {} : { on_behalf_of: input.onBehalfOf }),
    amount: { currency: "INR", minor: String(input.amountMinor) },
    payee_reference: input.payeeReference,
    purpose: input.purpose,
    expires_in_seconds: input.expiresInSeconds,
  };
}

export class ParimitService {
  readonly database: DatabaseSync;
  readonly policy: PolicyConfig;
  private readonly receiptSecret: string;
  private readonly clock: () => Date;

  constructor(options: ParimitServiceOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.receiptSecret = options.receiptSecret ?? "development-only-change-me";
    const requestedPolicy = options.policy ?? {};
    this.policy = {
      rulesVersion: requestedPolicy.rulesVersion ?? DEFAULT_POLICY.rulesVersion,
      perTransactionLimitMinor: requireSafePositiveInteger(
        requestedPolicy.perTransactionLimitMinor ?? DEFAULT_POLICY.perTransactionLimitMinor,
        "perTransactionLimitMinor",
      ),
      dailyAgentLimitMinor: requireSafePositiveInteger(
        requestedPolicy.dailyAgentLimitMinor ?? DEFAULT_POLICY.dailyAgentLimitMinor,
        "dailyAgentLimitMinor",
      ),
      dualApprovalThresholdMinor: requireSafePositiveInteger(
        requestedPolicy.dualApprovalThresholdMinor ?? DEFAULT_POLICY.dualApprovalThresholdMinor,
        "dualApprovalThresholdMinor",
      ),
      defaultExpirySeconds: requireSafePositiveInteger(
        requestedPolicy.defaultExpirySeconds ?? DEFAULT_POLICY.defaultExpirySeconds,
        "defaultExpirySeconds",
      ),
      maxExpirySeconds: requireSafePositiveInteger(
        requestedPolicy.maxExpirySeconds ?? DEFAULT_POLICY.maxExpirySeconds,
        "maxExpirySeconds",
      ),
      blockedPayees: normalizePayeeSet(requestedPolicy.blockedPayees ?? DEFAULT_POLICY.blockedPayees),
      allowedPayees:
        requestedPolicy.allowedPayees === undefined
          ? DEFAULT_POLICY.allowedPayees
          : requestedPolicy.allowedPayees === null
            ? null
            : normalizePayeeSet(requestedPolicy.allowedPayees),
    };
    if (this.policy.defaultExpirySeconds > this.policy.maxExpirySeconds) {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        "defaultExpirySeconds cannot exceed maxExpirySeconds",
        500,
      );
    }
    this.database = new DatabaseSync(options.databasePath ?? ":memory:");
    this.database.exec("PRAGMA foreign_keys = ON");
    this.initializeSchema();
  }

  close(): void {
    this.database.close();
  }

  private initializeSchema(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS intents (
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

      CREATE TABLE IF NOT EXISTS approvals (
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

      CREATE TABLE IF NOT EXISTS observations (
        id TEXT PRIMARY KEY,
        intent_id TEXT NOT NULL REFERENCES intents(id),
        status TEXT NOT NULL,
        provider_reference TEXT,
        observed_at TEXT NOT NULL,
        source TEXT NOT NULL CHECK (source = 'DEMO_MOCK')
      );

      CREATE TABLE IF NOT EXISTS audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        intent_id TEXT NOT NULL REFERENCES intents(id),
        event_type TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_intents_agent_created ON intents(agent_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_intent_sequence ON audit_events(intent_id, sequence);
      CREATE INDEX IF NOT EXISTS idx_observations_intent_time ON observations(intent_id, observed_at);
    `);

    // Databases created before v0.1 bound only proposal fields into a v1 digest.
    // Add provenance columns without rewriting those hashes; new rows always use v2.
    const intentColumns = new Set(
      (this.database.prepare("PRAGMA table_info(intents)").all() as SqlRow[]).map((row) =>
        stringCell(row, "name"),
      ),
    );
    if (!intentColumns.has("intent_version")) {
      this.database.exec(
        "ALTER TABLE intents ADD COLUMN intent_version TEXT NOT NULL DEFAULT 'parimit-payment-intent-v1'",
      );
    }
    if (!intentColumns.has("initial_status")) {
      this.database.exec(
        "ALTER TABLE intents ADD COLUMN initial_status TEXT NOT NULL DEFAULT 'AWAITING_APPROVAL'",
      );
      this.database.exec(`
        UPDATE intents
           SET initial_status = CASE
             WHEN policy_allowed = 1 THEN 'AWAITING_APPROVAL'
             ELSE 'POLICY_DENIED'
           END
      `);
    }
  }

  private now(): string {
    return this.clock().toISOString();
  }

  private transaction<T>(work: () => T): T {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private intentPayload(
    id: string,
    input: NormalizedPaymentProposal,
    createdAt: string,
    expiresAt: string,
    policy: PolicyDecision,
    initialStatus: InitialIntentStatus,
  ): Record<string, unknown> {
    return {
      version: CURRENT_INTENT_VERSION,
      id,
      idempotency_key: input.idempotencyKey,
      requested_by: { type: "agent", id: input.agentId },
      on_behalf_of: input.onBehalfOf,
      amount: { currency: input.currency, minor: String(input.amountMinor) },
      payee_reference: input.payeeReference,
      purpose: input.purpose,
      initial_status: initialStatus,
      policy: {
        allowed: policy.allowed,
        reasons: policy.reasons,
        rules_version: policy.rules_version,
        required_approvals: policy.required_approvals,
      },
      created_at: createdAt,
      expires_at: expiresAt,
    };
  }

  private intentPayloadFromRow(row: SqlRow): Record<string, unknown> {
    const version = stringCell(row, "intent_version") as PaymentIntentVersion;
    const common = {
      id: stringCell(row, "id"),
      idempotency_key: stringCell(row, "idempotency_key"),
      requested_by: { type: "agent", id: stringCell(row, "agent_id") },
      on_behalf_of: row.on_behalf_of === null ? null : stringCell(row, "on_behalf_of"),
      payee_reference: stringCell(row, "payee_reference"),
      purpose: stringCell(row, "purpose"),
      created_at: stringCell(row, "created_at"),
      expires_at: stringCell(row, "expires_at"),
    };
    if (version === LEGACY_INTENT_VERSION) {
      return {
        version,
        ...common,
        // Preserve the exact v1 representation so pre-migration rows remain readable.
        amount: { currency: "INR", minor: String(numberCell(row, "amount_minor")) },
      };
    }
    if (version !== CURRENT_INTENT_VERSION) {
      throw new TypeError(`Unsupported payment intent digest version: ${version}`);
    }
    return {
      version,
      ...common,
      amount: {
        currency: stringCell(row, "currency"),
        minor: String(numberCell(row, "amount_minor")),
      },
      initial_status: stringCell(row, "initial_status"),
      policy: {
        allowed: numberCell(row, "policy_allowed") === 1,
        reasons: parseJson<unknown>(stringCell(row, "policy_reasons")),
        rules_version: stringCell(row, "rules_version"),
        required_approvals: numberCell(row, "required_approvals"),
      },
    };
  }

  private requestFingerprint(input: NormalizedPaymentProposal): string {
    return sha256(canonicalJson(originalRequestShape(input)));
  }

  private approvalReceiptPayload(
    intentId: string,
    intentHash: string,
    actorId: string,
    actorRole: "approver" | "admin",
    decision: ApprovalDecision,
    createdAt: string,
  ): Record<string, unknown> {
    return {
      version: "parimit-approval-receipt-v1",
      intent_id: intentId,
      intent_hash: intentHash,
      actor_id: actorId,
      actor_role: actorRole,
      decision,
      created_at: createdAt,
    };
  }

  private appendAudit(
    intentId: string,
    eventType: string,
    actorId: string,
    payload: unknown,
    occurredAt = this.now(),
  ): void {
    const previous = this.database
      .prepare("SELECT event_hash FROM audit_events WHERE intent_id = ? ORDER BY sequence DESC LIMIT 1")
      .get(intentId) as SqlRow | undefined;
    const previousHash = previous ? stringCell(previous, "event_hash") : "GENESIS";
    const normalizedPayload = canonicalJson(payload);
    const eventHash = sha256(
      canonicalJson({
        intent_id: intentId,
        event_type: eventType,
        actor_id: actorId,
        payload: parseJson<unknown>(normalizedPayload),
        occurred_at: occurredAt,
        previous_hash: previousHash,
      }),
    );
    this.database
      .prepare(
        `INSERT INTO audit_events
          (intent_id, event_type, actor_id, payload, occurred_at, previous_hash, event_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(intentId, eventType, actorId, normalizedPayload, occurredAt, previousHash, eventHash);
  }

  private expireDueIntents(): void {
    const now = this.now();
    const rows = this.database
      .prepare("SELECT id FROM intents WHERE status = 'AWAITING_APPROVAL' AND expires_at <= ?")
      .all(now) as SqlRow[];
    if (rows.length === 0) return;
    this.transaction(() => {
      for (const row of rows) {
        const id = stringCell(row, "id");
        const result = this.database
          .prepare("UPDATE intents SET status = 'EXPIRED' WHERE id = ? AND status = 'AWAITING_APPROVAL'")
          .run(id);
        if (Number(result.changes) === 1) {
          this.appendAudit(id, "PROPOSAL_EXPIRED", "parimit-clock", { status: "EXPIRED" }, now);
        }
      }
    });
  }

  private dailyExposure(agentId: string, at: Date): number {
    const start = new Date(at);
    start.setUTCHours(0, 0, 0, 0);
    const row = this.database
      .prepare(
        `SELECT COALESCE(SUM(amount_minor), 0) AS exposure
           FROM intents
          WHERE agent_id = ?
            AND created_at >= ?
            AND policy_allowed = 1
            AND status IN ('AWAITING_APPROVAL', 'AUTHORIZED_NO_DISPATCH')`,
      )
      .get(agentId, start.toISOString()) as SqlRow;
    return numberCell(row, "exposure");
  }

  private decidePolicy(input: NormalizedPaymentProposal): PolicyDecision {
    const exposure = this.dailyExposure(input.agentId, this.clock());
    const projected = exposure + input.amountMinor;
    const denialReasons: string[] = [];
    const normalizedPayee = input.payeeReference.toLocaleLowerCase("en-US");
    if (input.amountMinor > this.policy.perTransactionLimitMinor) {
      denialReasons.push("PER_TRANSACTION_LIMIT_EXCEEDED");
    }
    if (projected > this.policy.dailyAgentLimitMinor) {
      denialReasons.push("DAILY_AGENT_LIMIT_EXCEEDED");
    }
    if (this.policy.blockedPayees.has(normalizedPayee)) {
      denialReasons.push("PAYEE_BLOCKED");
    }
    if (this.policy.allowedPayees !== null && !this.policy.allowedPayees.has(normalizedPayee)) {
      denialReasons.push("PAYEE_NOT_ALLOWLISTED");
    }
    const requiredApprovals: 1 | 2 =
      input.amountMinor > this.policy.dualApprovalThresholdMinor ? 2 : 1;
    const approvalReason =
      requiredApprovals === 2 ? "DISTINCT_DUAL_APPROVAL_REQUIRED" : "HUMAN_APPROVAL_REQUIRED";
    return {
      allowed: denialReasons.length === 0,
      reasons: [...denialReasons, approvalReason],
      rules_version: this.policy.rulesVersion,
      required_approvals: requiredApprovals,
      current_daily_exposure_minor: String(exposure),
      projected_daily_exposure_minor: String(projected),
    };
  }

  evaluatePolicy(value: unknown): PolicyDecision {
    this.expireDueIntents();
    const input = normalizePaymentProposal(
      value,
      this.policy.defaultExpirySeconds,
      this.policy.maxExpirySeconds,
    );
    return this.decidePolicy(input);
  }

  createIntent(value: unknown): IntentView {
    this.expireDueIntents();
    const input = normalizePaymentProposal(
      value,
      this.policy.defaultExpirySeconds,
      this.policy.maxExpirySeconds,
    );
    const requestFingerprint = this.requestFingerprint(input);
    const existing = this.database
      .prepare("SELECT id, request_fingerprint FROM intents WHERE agent_id = ? AND idempotency_key = ?")
      .get(input.agentId, input.idempotencyKey) as SqlRow | undefined;
    if (existing) {
      if (!safeEqualText(stringCell(existing, "request_fingerprint"), requestFingerprint)) {
        throw new ParimitError(
          "IDEMPOTENCY_CONFLICT",
          "This agent already used the idempotency key for a different proposal",
          409,
        );
      }
      return { ...this.getIntent(stringCell(existing, "id")), idempotent_replay: true };
    }

    const policy = this.decidePolicy(input);
    const id = randomUUID();
    const createdAt = this.now();
    const expiresAt = new Date(new Date(createdAt).getTime() + input.expiresInSeconds * 1_000).toISOString();
    const status: InitialIntentStatus = policy.allowed ? "AWAITING_APPROVAL" : "POLICY_DENIED";
    const intentHash = sha256(
      canonicalJson(this.intentPayload(id, input, createdAt, expiresAt, policy, status)),
    );

    this.transaction(() => {
      this.database
        .prepare(
          `INSERT INTO intents
            (id, idempotency_key, request_fingerprint, agent_id, on_behalf_of, amount_minor,
             currency, payee_reference, purpose, status, required_approvals, policy_allowed,
             policy_reasons, rules_version, intent_version, initial_status, intent_hash,
             created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, 'INR', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          input.idempotencyKey,
          requestFingerprint,
          input.agentId,
          input.onBehalfOf,
          input.amountMinor,
          input.payeeReference,
          input.purpose,
          status,
          policy.required_approvals,
          policy.allowed ? 1 : 0,
          canonicalJson(policy.reasons),
          policy.rules_version,
          CURRENT_INTENT_VERSION,
          status,
          intentHash,
          createdAt,
          expiresAt,
        );
      this.appendAudit(
        id,
        policy.allowed ? "PROPOSAL_CREATED" : "PROPOSAL_POLICY_DENIED",
        input.agentId,
        {
          intent_hash: intentHash,
          status,
          policy,
          boundary: "PROPOSAL_ONLY_NO_VALUE_MOVEMENT",
        },
        createdAt,
      );
    });
    return this.getIntent(id);
  }

  private getRawIntent(id: string): SqlRow {
    return requiredRow(
      this.database.prepare("SELECT * FROM intents WHERE id = ?").get(id) as SqlRow | undefined,
    );
  }

  private approvalsFor(id: string): ApprovalView[] {
    const rows = this.database
      .prepare(
        `SELECT actor_id, actor_role, decision, intent_hash, created_at, receipt_hmac
           FROM approvals WHERE intent_id = ? ORDER BY created_at, id`,
      )
      .all(id) as SqlRow[];
    return rows.map((row) => ({
      actor_id: stringCell(row, "actor_id"),
      actor_role: stringCell(row, "actor_role") as "approver" | "admin",
      decision: stringCell(row, "decision") as ApprovalDecision,
      intent_hash: stringCell(row, "intent_hash"),
      created_at: stringCell(row, "created_at"),
      receipt_hmac: stringCell(row, "receipt_hmac"),
    }));
  }

  private latestObservation(id: string): ObservationView | undefined {
    const row = this.database
      .prepare(
        `SELECT status, provider_reference, observed_at, source
           FROM observations WHERE intent_id = ? ORDER BY observed_at DESC, rowid DESC LIMIT 1`,
      )
      .get(id) as SqlRow | undefined;
    if (!row) return undefined;
    return {
      status: stringCell(row, "status") as ObservationStatus,
      ...(row.provider_reference === null
        ? {}
        : { provider_reference: stringCell(row, "provider_reference") }),
      observed_at: stringCell(row, "observed_at"),
      source: "DEMO_MOCK",
      retry_permitted: false,
    };
  }

  private rowToIntent(row: SqlRow, idempotentReplay = false): IntentView {
    const id = stringCell(row, "id");
    const approvals = this.approvalsFor(id);
    const approvalCount = approvals.filter((approval) => approval.decision === "APPROVE").length;
    const status = stringCell(row, "status") as IntentStatus;
    let receipt: ApprovalReceiptView | undefined;
    if (status === "AUTHORIZED_NO_DISPATCH") {
      const approved = approvals.filter((approval) => approval.decision === "APPROVE");
      receipt = {
        version: "parimit-approval-receipt-v1",
        intent_id: id,
        intent_hash: stringCell(row, "intent_hash"),
        fully_approved_at: approved.at(-1)?.created_at ?? stringCell(row, "created_at"),
        approvals: approved,
        execution_authorized: false,
        notice: APPROVAL_NOTICE,
      };
    }
    return {
      id,
      intent_version: stringCell(row, "intent_version") as PaymentIntentVersion,
      initial_status: stringCell(row, "initial_status") as InitialIntentStatus,
      idempotency_key: stringCell(row, "idempotency_key"),
      requested_by: { type: "agent", id: stringCell(row, "agent_id") },
      ...(row.on_behalf_of === null ? {} : { on_behalf_of: stringCell(row, "on_behalf_of") }),
      amount: { currency: "INR", minor: String(numberCell(row, "amount_minor")) },
      payee_reference: stringCell(row, "payee_reference"),
      purpose: stringCell(row, "purpose"),
      status,
      required_approvals: numberCell(row, "required_approvals") as 1 | 2,
      approval_count: approvalCount,
      policy: {
        allowed: numberCell(row, "policy_allowed") === 1,
        reasons: parseJson<string[]>(stringCell(row, "policy_reasons")),
        rules_version: stringCell(row, "rules_version"),
      },
      intent_hash: stringCell(row, "intent_hash"),
      created_at: stringCell(row, "created_at"),
      expires_at: stringCell(row, "expires_at"),
      ...(this.latestObservation(id) ? { observation: this.latestObservation(id) } : {}),
      approvals,
      ...(receipt ? { receipt } : {}),
      ...(idempotentReplay ? { idempotent_replay: true } : {}),
    };
  }

  getIntent(id: string): IntentView {
    this.expireDueIntents();
    const row = this.getRawIntent(id);
    const report = this.verifyIntegrity(id);
    if (!report.valid) {
      throw new ParimitError("INTEGRITY_FAILURE", "Stored proposal integrity verification failed", 500, report);
    }
    return this.rowToIntent(row);
  }

  listIntents(filters: { agentId?: string; status?: IntentStatus; limit?: number } = {}): IntentView[] {
    this.expireDueIntents();
    const clauses: string[] = [];
    const parameters: Array<string | number> = [];
    if (filters.agentId) {
      clauses.push("agent_id = ?");
      parameters.push(filters.agentId);
    }
    if (filters.status) {
      clauses.push("status = ?");
      parameters.push(filters.status);
    }
    const limit = filters.limit ?? 100;
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw new ParimitError("VALIDATION_ERROR", "limit must be an integer from 1 to 200", 400);
    }
    parameters.push(limit);
    const sql = `SELECT * FROM intents${clauses.length ? ` WHERE ${clauses.join(" AND ")}` : ""}
                  ORDER BY created_at DESC LIMIT ?`;
    const rows = this.database.prepare(sql).all(...parameters) as SqlRow[];
    return rows.map((row) => {
      const id = stringCell(row, "id");
      const report = this.verifyIntegrity(id);
      if (!report.valid) {
        throw new ParimitError("INTEGRITY_FAILURE", `Integrity verification failed for proposal ${id}`, 500, report);
      }
      return this.rowToIntent(row);
    });
  }

  approveIntent(
    id: string,
    actorIdValue: unknown,
    actorRoleValue: unknown,
    decisionValue: unknown,
  ): IntentView {
    this.expireDueIntents();
    const actorId = requireIdentifier(actorIdValue, "x-parimit-actor");
    const actorRole = String(actorRoleValue).toLocaleLowerCase("en-US") as ActorRole;
    if (actorRole !== "approver" && actorRole !== "admin") {
      throw new ParimitError(
        "HUMAN_APPROVER_REQUIRED",
        "Only demo roles 'approver' or 'admin' may approve or reject; agents cannot approve",
        403,
      );
    }
    if (decisionValue !== "APPROVE" && decisionValue !== "REJECT") {
      throw new ParimitError("VALIDATION_ERROR", "decision must be 'APPROVE' or 'REJECT'", 400);
    }
    const decision = decisionValue;
    const row = this.getRawIntent(id);
    this.assertStoredIntegrity(row);
    if (stringCell(row, "agent_id") === actorId) {
      throw new ParimitError("AGENT_CANNOT_APPROVE", "The requesting agent cannot approve its own proposal", 403);
    }
    if (stringCell(row, "status") !== "AWAITING_APPROVAL") {
      throw new ParimitError(
        "INVALID_STATE",
        `Proposal cannot be reviewed while in ${stringCell(row, "status")} state`,
        409,
      );
    }
    const createdAt = this.now();
    const intentHash = stringCell(row, "intent_hash");
    const receiptPayload = this.approvalReceiptPayload(
      id,
      intentHash,
      actorId,
      actorRole,
      decision,
      createdAt,
    );
    const receipt = hmacSha256(this.receiptSecret, receiptPayload);
    this.transaction(() => {
      const previous = this.database
        .prepare("SELECT decision FROM approvals WHERE intent_id = ? AND actor_id = ?")
        .get(id, actorId) as SqlRow | undefined;
      if (previous) {
        throw new ParimitError(
          "DUPLICATE_APPROVER",
          "Each human may review a proposal only once; dual approval requires distinct humans",
          409,
        );
      }
      this.database
        .prepare(
          `INSERT INTO approvals
            (id, intent_id, actor_id, actor_role, decision, intent_hash, created_at, receipt_hmac)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(randomUUID(), id, actorId, actorRole, decision, intentHash, createdAt, receipt);

      let nextStatus: IntentStatus = "AWAITING_APPROVAL";
      if (decision === "REJECT") {
        nextStatus = "REJECTED";
      } else {
        const countRow = this.database
          .prepare("SELECT COUNT(*) AS total FROM approvals WHERE intent_id = ? AND decision = 'APPROVE'")
          .get(id) as SqlRow;
        if (numberCell(countRow, "total") >= numberCell(row, "required_approvals")) {
          nextStatus = "AUTHORIZED_NO_DISPATCH";
        }
      }
      this.database.prepare("UPDATE intents SET status = ? WHERE id = ?").run(nextStatus, id);
      this.appendAudit(
        id,
        decision === "APPROVE" ? "HUMAN_APPROVAL_RECORDED" : "HUMAN_REJECTION_RECORDED",
        actorId,
        {
          actor_role: actorRole,
          decision,
          intent_hash: intentHash,
          receipt_hmac: receipt,
          resulting_status: nextStatus,
        },
        createdAt,
      );
    });
    return this.getIntent(id);
  }

  cancelIntent(id: string, actorIdValue: unknown, actorRoleValue: unknown = "agent"): IntentView {
    this.expireDueIntents();
    const actorId = requireIdentifier(actorIdValue, "actor_id");
    const actorRole = String(actorRoleValue).toLocaleLowerCase("en-US") as ActorRole;
    if (actorRole !== "agent" && actorRole !== "admin") {
      throw new ParimitError("FORBIDDEN", "Only the requesting agent or a demo admin may cancel", 403);
    }
    const row = this.getRawIntent(id);
    this.assertStoredIntegrity(row);
    if (actorRole === "agent" && stringCell(row, "agent_id") !== actorId) {
      throw new ParimitError("FORBIDDEN", "An agent may cancel only its own proposal", 403);
    }
    if (stringCell(row, "status") !== "AWAITING_APPROVAL") {
      throw new ParimitError(
        "INVALID_STATE",
        `Proposal cannot be cancelled while in ${stringCell(row, "status")} state`,
        409,
      );
    }
    const occurredAt = this.now();
    this.transaction(() => {
      this.database.prepare("UPDATE intents SET status = 'CANCELLED' WHERE id = ?").run(id);
      this.appendAudit(id, "PROPOSAL_CANCELLED", actorId, { status: "CANCELLED" }, occurredAt);
    });
    return this.getIntent(id);
  }

  recordMockObservation(
    id: string,
    statusValue: unknown,
    providerReferenceValue?: unknown,
    actorId = "demo-mock-rail",
  ): IntentView {
    if (typeof statusValue !== "string" || !OBSERVATION_STATUSES.includes(statusValue as ObservationStatus)) {
      throw new ParimitError(
        "VALIDATION_ERROR",
        `status must be one of ${OBSERVATION_STATUSES.join(", ")}`,
        400,
      );
    }
    let providerReference: string | null = null;
    if (providerReferenceValue !== undefined) {
      providerReference = requireString(providerReferenceValue, "provider_reference", 200);
    }
    const row = this.getRawIntent(id);
    this.assertStoredIntegrity(row);
    if (stringCell(row, "status") !== "AUTHORIZED_NO_DISPATCH") {
      throw new ParimitError(
        "INVALID_STATE",
        "Mock observations may be attached only after all required human approvals",
        409,
      );
    }
    const observedAt = this.now();
    const status = statusValue as ObservationStatus;
    this.transaction(() => {
      const latestObservation = this.latestObservation(id);
      if (latestObservation?.status === "IN_DOUBT") {
        throw new ParimitError(
          "IN_DOUBT_FROZEN",
          "No later mock observation is allowed after IN_DOUBT; this alpha has no authorized reconciliation mechanism",
          409,
        );
      }
      this.database
        .prepare(
          `INSERT INTO observations (id, intent_id, status, provider_reference, observed_at, source)
           VALUES (?, ?, ?, ?, ?, 'DEMO_MOCK')`,
        )
        .run(randomUUID(), id, status, providerReference, observedAt);
      this.appendAudit(
        id,
        "DEMO_MOCK_OBSERVATION_RECORDED",
        actorId,
        {
          status,
          provider_reference: providerReference,
          source: "DEMO_MOCK",
          retry_permitted: false,
          moves_money: false,
        },
        observedAt,
      );
    });
    return this.getIntent(id);
  }

  getAudit(id: string): AuditEventView[] {
    this.getRawIntent(id);
    const rows = this.database
      .prepare("SELECT * FROM audit_events WHERE intent_id = ? ORDER BY sequence")
      .all(id) as SqlRow[];
    return rows.map((row) => ({
      sequence: numberCell(row, "sequence"),
      intent_id: stringCell(row, "intent_id"),
      event_type: stringCell(row, "event_type"),
      actor_id: stringCell(row, "actor_id"),
      payload: parseJson<unknown>(stringCell(row, "payload")),
      occurred_at: stringCell(row, "occurred_at"),
      previous_hash: stringCell(row, "previous_hash"),
      event_hash: stringCell(row, "event_hash"),
    }));
  }

  private assertStoredIntegrity(row: SqlRow): void {
    const report = this.verifyIntegrity(stringCell(row, "id"));
    if (!report.valid) {
      const hashOnly = !report.intent_hash_valid;
      throw new ParimitError(
        hashOnly ? "INTENT_HASH_MISMATCH" : "INTEGRITY_FAILURE",
        hashOnly
          ? "The immutable payment intent has been tampered with"
          : "Stored proposal integrity verification failed",
        500,
        report,
      );
    }
    if (stringCell(row, "intent_version") === LEGACY_INTENT_VERSION) {
      throw new ParimitError(
        "LEGACY_INTENT_READ_ONLY",
        "Legacy v1 intents are archival and cannot be reviewed, cancelled, or observed; create a new v2 proposal",
        409,
      );
    }
  }

  verifyIntegrity(id: string): IntegrityReport {
    const row = this.getRawIntent(id);
    const failures: string[] = [];
    const addFailure = (failure: string): void => {
      if (!failures.includes(failure)) failures.push(failure);
    };
    const storedIntentHash = stringCell(row, "intent_hash");

    let intentHashValid = true;
    try {
      const expectedIntentHash = sha256(canonicalJson(this.intentPayloadFromRow(row)));
      intentHashValid = safeEqualText(expectedIntentHash, storedIntentHash);
    } catch {
      intentHashValid = false;
      addFailure("INTENT_PAYLOAD_INVALID");
    }
    if (!intentHashValid) addFailure("INTENT_HASH_MISMATCH");

    let stateConsistencyValid = true;
    const addStateFailure = (failure: string): void => {
      stateConsistencyValid = false;
      addFailure(failure);
    };

    const version = stringCell(row, "intent_version");
    if (version !== LEGACY_INTENT_VERSION && version !== CURRENT_INTENT_VERSION) {
      addStateFailure("INTENT_VERSION_UNSUPPORTED");
    }
    const status = stringCell(row, "status") as IntentStatus;
    if (!INTENT_STATUSES.includes(status)) addStateFailure("INTENT_STATUS_INVALID");
    const initialStatus = stringCell(row, "initial_status") as InitialIntentStatus;
    const policyAllowedValue = numberCell(row, "policy_allowed");
    if (policyAllowedValue !== 0 && policyAllowedValue !== 1) {
      addStateFailure("POLICY_ALLOWED_INVALID");
    }
    const policyAllowed = policyAllowedValue === 1;
    const expectedInitialStatus: InitialIntentStatus = policyAllowed
      ? "AWAITING_APPROVAL"
      : "POLICY_DENIED";
    if (initialStatus !== expectedInitialStatus) {
      addStateFailure("INITIAL_STATUS_POLICY_MISMATCH");
    }

    const requiredApprovals = numberCell(row, "required_approvals");
    if (requiredApprovals !== 1 && requiredApprovals !== 2) {
      addStateFailure("REQUIRED_APPROVALS_INVALID");
    }
    const rulesVersion = stringCell(row, "rules_version");
    if (rulesVersion.length === 0) addStateFailure("RULES_VERSION_INVALID");

    let policyReasons: string[] | null = null;
    try {
      const parsed = parseJson<unknown>(stringCell(row, "policy_reasons"));
      if (!Array.isArray(parsed) || !parsed.every((reason) => typeof reason === "string")) {
        throw new TypeError("policy_reasons is not a string array");
      }
      policyReasons = parsed;
    } catch {
      addStateFailure("POLICY_REASONS_INVALID");
    }
    if (policyReasons) {
      if (new Set(policyReasons).size !== policyReasons.length) {
        addStateFailure("POLICY_REASONS_DUPLICATED");
      }
      const expectedApprovalReason =
        requiredApprovals === 2
          ? "DISTINCT_DUAL_APPROVAL_REQUIRED"
          : "HUMAN_APPROVAL_REQUIRED";
      const approvalReasons = policyReasons.filter((reason) => APPROVAL_POLICY_REASONS.has(reason));
      if (approvalReasons.length !== 1 || approvalReasons[0] !== expectedApprovalReason) {
        addStateFailure("POLICY_APPROVAL_REASON_MISMATCH");
      }
      const denialReasons = policyReasons.filter((reason) => !APPROVAL_POLICY_REASONS.has(reason));
      if ((policyAllowed && denialReasons.length !== 0) || (!policyAllowed && denialReasons.length === 0)) {
        addStateFailure("POLICY_ALLOWED_REASONS_MISMATCH");
      }
    }

    let approvalReceiptsValid = true;
    const approvals = this.approvalsFor(id);
    const seenApprovalActors = new Set<string>();
    let validApproveCount = 0;
    let validRejectCount = 0;
    const proposalCreatedAt = Date.parse(stringCell(row, "created_at"));
    const proposalExpiresAt = Date.parse(stringCell(row, "expires_at"));
    if (!Number.isFinite(proposalCreatedAt) || !Number.isFinite(proposalExpiresAt)) {
      addStateFailure("INTENT_TIMESTAMPS_INVALID");
    }
    for (const approval of approvals) {
      const actorIsDistinct = !seenApprovalActors.has(approval.actor_id);
      seenApprovalActors.add(approval.actor_id);
      const expected = hmacSha256(
        this.receiptSecret,
        this.approvalReceiptPayload(
          id,
          approval.intent_hash,
          approval.actor_id,
          approval.actor_role,
          approval.decision,
          approval.created_at,
        ),
      );
      const receiptValid =
        safeEqualText(expected, approval.receipt_hmac) &&
        safeEqualText(approval.intent_hash, storedIntentHash);
      if (!receiptValid) {
        approvalReceiptsValid = false;
        addFailure(`APPROVAL_RECEIPT_INVALID:${approval.actor_id}`);
      }

      const approvalTime = Date.parse(approval.created_at);
      const semanticValid =
        approval.actor_id.length > 0 &&
        approval.actor_id !== stringCell(row, "agent_id") &&
        (approval.actor_role === "approver" || approval.actor_role === "admin") &&
        (approval.decision === "APPROVE" || approval.decision === "REJECT") &&
        Number.isFinite(approvalTime) &&
        approvalTime >= proposalCreatedAt &&
        approvalTime < proposalExpiresAt &&
        actorIsDistinct;
      if (!semanticValid) addStateFailure(`APPROVAL_SEMANTICS_INVALID:${approval.actor_id}`);
      if (receiptValid && semanticValid) {
        if (approval.decision === "APPROVE") validApproveCount += 1;
        else validRejectCount += 1;
      }
    }

    let auditChainValid = true;
    let previousHash = "GENESIS";
    const auditEvents: AuditEventView[] = [];
    const auditRows = this.database
      .prepare("SELECT * FROM audit_events WHERE intent_id = ? ORDER BY sequence")
      .all(id) as SqlRow[];
    for (const auditRow of auditRows) {
      const sequence = numberCell(auditRow, "sequence");
      let payload: unknown;
      try {
        payload = parseJson<unknown>(stringCell(auditRow, "payload"));
      } catch {
        auditChainValid = false;
        addFailure(`AUDIT_PAYLOAD_INVALID:${sequence}`);
        payload = null;
      }
      const event: AuditEventView = {
        sequence,
        intent_id: stringCell(auditRow, "intent_id"),
        event_type: stringCell(auditRow, "event_type"),
        actor_id: stringCell(auditRow, "actor_id"),
        payload,
        occurred_at: stringCell(auditRow, "occurred_at"),
        previous_hash: stringCell(auditRow, "previous_hash"),
        event_hash: stringCell(auditRow, "event_hash"),
      };
      const expected = sha256(
        canonicalJson({
          intent_id: event.intent_id,
          event_type: event.event_type,
          actor_id: event.actor_id,
          payload: event.payload,
          occurred_at: event.occurred_at,
          previous_hash: event.previous_hash,
        }),
      );
      if (
        event.intent_id !== id ||
        !safeEqualText(event.previous_hash, previousHash) ||
        !safeEqualText(event.event_hash, expected)
      ) {
        auditChainValid = false;
        addFailure(`AUDIT_CHAIN_INVALID:${event.sequence}`);
      }
      previousHash = event.event_hash;
      auditEvents.push(event);
    }

    const initialEvent = auditEvents[0];
    const expectedInitialEvent =
      initialStatus === "POLICY_DENIED" ? "PROPOSAL_POLICY_DENIED" : "PROPOSAL_CREATED";
    const initialPayload = initialEvent && isRecord(initialEvent.payload) ? initialEvent.payload : null;
    const initialPolicy =
      initialPayload && isRecord(initialPayload.policy) ? initialPayload.policy : null;
    if (
      !initialEvent ||
      initialEvent.event_type !== expectedInitialEvent ||
      !initialPayload ||
      initialPayload.status !== initialStatus ||
      initialPayload.intent_hash !== storedIntentHash ||
      !initialPolicy ||
      initialPolicy.allowed !== policyAllowed ||
      initialPolicy.rules_version !== rulesVersion ||
      initialPolicy.required_approvals !== requiredApprovals ||
      !policyReasons ||
      canonicalJson(initialPolicy.reasons) !== canonicalJson(policyReasons)
    ) {
      addStateFailure("INITIAL_AUDIT_POLICY_MISMATCH");
    }

    const reviewEvents = auditEvents.filter(
      (event) =>
        event.event_type === "HUMAN_APPROVAL_RECORDED" ||
        event.event_type === "HUMAN_REJECTION_RECORDED",
    );
    if (reviewEvents.length !== approvals.length) {
      addStateFailure("APPROVAL_AUDIT_COUNT_MISMATCH");
    }
    for (const approval of approvals) {
      const matches = reviewEvents.filter((event) => {
        if (!isRecord(event.payload)) return false;
        return (
          event.actor_id === approval.actor_id &&
          event.occurred_at === approval.created_at &&
          event.payload.actor_role === approval.actor_role &&
          event.payload.decision === approval.decision &&
          event.payload.intent_hash === approval.intent_hash &&
          event.payload.receipt_hmac === approval.receipt_hmac
        );
      });
      if (matches.length !== 1) {
        addStateFailure(`APPROVAL_AUDIT_MISMATCH:${approval.actor_id}`);
      }
    }

    let auditedStatus: IntentStatus | null = null;
    for (const event of auditEvents) {
      if (event.event_type === "PROPOSAL_CREATED") auditedStatus = "AWAITING_APPROVAL";
      else if (event.event_type === "PROPOSAL_POLICY_DENIED") auditedStatus = "POLICY_DENIED";
      else if (event.event_type === "PROPOSAL_CANCELLED") auditedStatus = "CANCELLED";
      else if (event.event_type === "PROPOSAL_EXPIRED") auditedStatus = "EXPIRED";
      else if (
        event.event_type === "HUMAN_APPROVAL_RECORDED" ||
        event.event_type === "HUMAN_REJECTION_RECORDED"
      ) {
        const resultingStatus = isRecord(event.payload) ? event.payload.resulting_status : undefined;
        if (
          resultingStatus === "AWAITING_APPROVAL" ||
          resultingStatus === "AUTHORIZED_NO_DISPATCH" ||
          resultingStatus === "REJECTED"
        ) {
          auditedStatus = resultingStatus;
        } else {
          addStateFailure(`AUDIT_RESULTING_STATUS_INVALID:${event.sequence}`);
        }
      }
    }
    if (auditedStatus !== status) addStateFailure("STATUS_AUDIT_MISMATCH");

    if (!policyAllowed && status !== "POLICY_DENIED") {
      addStateFailure("DENIED_POLICY_STATUS_MISMATCH");
    }
    if (policyAllowed && status === "POLICY_DENIED") {
      addStateFailure("ALLOWED_POLICY_STATUS_MISMATCH");
    }
    if (status === "POLICY_DENIED" && approvals.length !== 0) {
      addStateFailure("DENIED_INTENT_HAS_APPROVALS");
    }
    if (status === "AWAITING_APPROVAL") {
      if (validRejectCount !== 0 || validApproveCount >= requiredApprovals) {
        addStateFailure("AWAITING_APPROVAL_STATE_MISMATCH");
      }
    } else if (status === "AUTHORIZED_NO_DISPATCH") {
      if (!policyAllowed || validRejectCount !== 0 || validApproveCount < requiredApprovals) {
        addStateFailure("AUTHORIZED_APPROVAL_THRESHOLD_NOT_MET");
      }
    } else if (status === "REJECTED") {
      if (!policyAllowed || validRejectCount < 1) addStateFailure("REJECTED_WITHOUT_VALID_REJECTION");
    } else if (status === "CANCELLED" || status === "EXPIRED") {
      if (!policyAllowed || validRejectCount !== 0 || validApproveCount >= requiredApprovals) {
        addStateFailure("TERMINAL_STATE_APPROVAL_MISMATCH");
      }
    }
    if (version === LEGACY_INTENT_VERSION && status === "AUTHORIZED_NO_DISPATCH") {
      // v1 did not bind policy metadata or the approval threshold. Its unkeyed
      // audit chain cannot safely recover that missing authorization context.
      addStateFailure("LEGACY_V1_AUTHORIZATION_UNTRUSTED");
    }

    const observationCountRow = this.database
      .prepare("SELECT COUNT(*) AS total FROM observations WHERE intent_id = ?")
      .get(id) as SqlRow;
    if (numberCell(observationCountRow, "total") > 0 && status !== "AUTHORIZED_NO_DISPATCH") {
      addStateFailure("OBSERVATION_WITHOUT_AUTHORIZED_STATE");
    }

    return {
      valid:
        intentHashValid && approvalReceiptsValid && auditChainValid && stateConsistencyValid,
      intent_hash_valid: intentHashValid,
      approval_receipts_valid: approvalReceiptsValid,
      audit_chain_valid: auditChainValid,
      state_consistency_valid: stateConsistencyValid,
      failures,
    };
  }

  safetyMetadata(): Record<string, unknown> {
    return {
      name: "Parimit",
      version: "0.1.0-alpha.0",
      mode: "PROPOSAL_ONLY",
      moves_money: false,
      connects_to_upi: false,
      live_payment_credentials_accepted: false,
      execution_routes: [],
      agent_capabilities: [
        "create_payment_proposal",
        "get_payment_status",
        "cancel_payment_proposal",
        "get_policy_decision",
        "simulate_payment",
        "get_payment_audit",
      ],
      human_only_capabilities: ["approve_exact_proposal", "reject_exact_proposal"],
      mock_observations: [...OBSERVATION_STATUSES],
      mock_observation_retry_permitted: false,
      currency: "INR",
      amount_unit: "minor (paise), represented as a decimal string",
      demo_auth_warning:
        "x-parimit-actor and x-parimit-role are spoofable demo headers. Replace them with verified OIDC/WebAuthn identities before any real deployment.",
      rules: {
        version: this.policy.rulesVersion,
        per_transaction_limit_minor: String(this.policy.perTransactionLimitMinor),
        daily_agent_limit_minor: String(this.policy.dailyAgentLimitMinor),
        dual_approval_above_minor: String(this.policy.dualApprovalThresholdMinor),
        human_approval_always_required: true,
        distinct_dual_approval: true,
      },
    };
  }
}

function parsePositiveEnvironmentInteger(value: string | undefined, fallback: number): number {
  if (value === undefined || value === "") return fallback;
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new ParimitError("INVALID_CONFIGURATION", `Invalid positive integer environment value: ${value}`, 500);
  }
  return Number(value);
}

function parseEnvironmentSet(value: string | undefined): string[] | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function environmentValue(
  environment: Record<string, string | undefined>,
  primary: string,
  alias?: string,
): string | undefined {
  return environment[primary] ?? (alias ? environment[alias] : undefined);
}

export function createServiceFromEnvironment(
  environment: Record<string, string | undefined> = process.env,
): ParimitService {
  const demoModeValue = (environment.PARIMIT_DEMO_MODE ?? "true").toLocaleLowerCase("en-US");
  if (demoModeValue !== "true" && demoModeValue !== "1") {
    throw new ParimitError(
      "DEMO_ONLY_BUILD",
      "This alpha uses spoofable demo identity headers and refuses to start outside demo mode",
      500,
    );
  }
  const allowed = parseEnvironmentSet(environment.PARIMIT_ALLOWED_PAYEES);
  return new ParimitService({
    databasePath: environment.PARIMIT_DB_PATH ?? "./data/parimit.db",
    receiptSecret:
      environmentValue(environment, "PARIMIT_RECEIPT_KEY", "PARIMIT_RECEIPT_SECRET") ??
      "development-only-change-me",
    policy: {
      perTransactionLimitMinor: parsePositiveEnvironmentInteger(
        environmentValue(environment, "PARIMIT_PER_TX_LIMIT", "PARIMIT_PER_TRANSACTION_LIMIT_MINOR"),
        DEFAULT_POLICY.perTransactionLimitMinor,
      ),
      dailyAgentLimitMinor: parsePositiveEnvironmentInteger(
        environmentValue(environment, "PARIMIT_DAILY_AGENT_LIMIT", "PARIMIT_DAILY_AGENT_LIMIT_MINOR"),
        DEFAULT_POLICY.dailyAgentLimitMinor,
      ),
      dualApprovalThresholdMinor: parsePositiveEnvironmentInteger(
        environmentValue(
          environment,
          "PARIMIT_DUAL_APPROVAL_THRESHOLD",
          "PARIMIT_DUAL_APPROVAL_THRESHOLD_MINOR",
        ),
        DEFAULT_POLICY.dualApprovalThresholdMinor,
      ),
      defaultExpirySeconds: parsePositiveEnvironmentInteger(
        environmentValue(environment, "PARIMIT_INTENT_TTL_SECONDS", "PARIMIT_DEFAULT_EXPIRY_SECONDS"),
        DEFAULT_POLICY.defaultExpirySeconds,
      ),
      maxExpirySeconds: parsePositiveEnvironmentInteger(
        environment.PARIMIT_MAX_EXPIRY_SECONDS,
        DEFAULT_POLICY.maxExpirySeconds,
      ),
      blockedPayees: parseEnvironmentSet(environment.PARIMIT_BLOCKED_PAYEES) ?? [],
      allowedPayees: allowed === undefined ? null : allowed,
    },
  });
}
