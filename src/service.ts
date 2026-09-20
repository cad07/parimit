import { randomBytes, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson, hmacSha256, safeEqualText, sha256 } from "./crypto.ts";
import {
  createEnvelopeSigningKey,
  parseAuthorizationEnvelope,
  signAuthorizationEnvelope,
  verifyAuthorizationEnvelopeSignature,
  type EnvelopeSigningKey,
} from "./envelope.ts";
import { ParimitError } from "./errors.ts";
import {
  LOCAL_DEMO_IDENTITY_TRUST_DOMAIN,
} from "./identity-trust.ts";
import {
  INTENT_STATUSES,
  OBSERVATION_STATUSES,
  type ActorRole,
  type ApprovalDecision,
  type ApprovalReceiptView,
  type ApprovalView,
  type AuthorizationEnvelopeClaims,
  type AuthorizationEnvelopeConsumption,
  type AuthorizationEnvelopeIssueInput,
  type AuthorizationEnvelopeVerification,
  type AuthorizationEnvelopeView,
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
const AUTHORIZATION_ENVELOPE_NOTICE =
  "This signed envelope proves Parimit recorded the required human approvals. It is evidence-only, non-dispatchable, and never authorizes a payment rail to move funds.";

const LEGACY_INTENT_VERSION: PaymentIntentVersion = "parimit-payment-intent-v1";
const POLICY_BOUND_INTENT_VERSION: PaymentIntentVersion = "parimit-payment-intent-v2";
const CURRENT_INTENT_VERSION: PaymentIntentVersion = "parimit-payment-intent-v3";
const DEFAULT_TENANT_ID = "local-demo";
const DEFAULT_ENVELOPE_ISSUER = "https://parimit.local";
const DEFAULT_ENVELOPE_TTL_SECONDS = 300;
const MAX_PROPOSAL_EXPIRY_SECONDS = 86_400;
const RECEIPT_INTEGRITY_ROOT_NAME = "receipt_integrity_root_v1";
const ENVELOPE_KEY_REGISTRY_STATE_NAME = "envelope_signing_key_registry_state_v1";
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

function requireTrustUri(value: unknown, field: string): string {
  const identifier = requireString(value, field, 512);
  let url: URL;
  try {
    url = new URL(identifier);
  } catch {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      `${field} must be an absolute HTTPS URL or URN`,
      500,
    );
  }
  if (
    (url.protocol !== "https:" && url.protocol !== "urn:") ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      `${field} must be an absolute HTTPS URL or URN without credentials, a query, or a fragment`,
      500,
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

function requireConfigurationString(value: unknown, field: string, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    value.trim() !== value ||
    /\p{Cc}/u.test(value)
  ) {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      `${field} must be a non-empty string of at most ${maximum} characters without surrounding whitespace or control characters`,
      500,
    );
  }
  return value;
}

class ImmutableSet<T> implements ReadonlySet<T> {
  readonly #values: Set<T>;

  constructor(values: Iterable<T>) {
    this.#values = new Set(values);
    Object.freeze(this);
  }

  get size(): number {
    return this.#values.size;
  }

  has(value: T): boolean {
    return this.#values.has(value);
  }

  entries(): SetIterator<[T, T]> {
    return this.#values.entries();
  }

  keys(): SetIterator<T> {
    return this.#values.keys();
  }

  values(): SetIterator<T> {
    return this.#values.values();
  }

  [Symbol.iterator](): SetIterator<T> {
    return this.#values[Symbol.iterator]();
  }

  forEach(callbackfn: (value: T, value2: T, set: ReadonlySet<T>) => void, thisArg?: unknown): void {
    for (const value of this.#values) callbackfn.call(thisArg, value, value, this);
  }
}

function normalizePayeeSet(values: Iterable<string>): ReadonlySet<string> {
  return new ImmutableSet(
    Array.from(values, (value) => value.trim().toLocaleLowerCase("en-US")).filter(Boolean),
  );
}

function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isSha256Hex(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
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
  readonly authenticationMode: "demo_headers" | "oidc";
  readonly identityTrustDomainId: string;
  readonly tenantId: string;
  readonly policyConfigurationDigest: string;
  private readonly receiptSecret: string;
  private readonly clock: () => Date;
  private readonly envelopeIssuer: string;
  private readonly envelopeTtlSeconds: number;
  private readonly envelopeAudiences: ReadonlySet<string>;
  private readonly envelopeSigningKey: EnvelopeSigningKey;

  constructor(options: ParimitServiceOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.authenticationMode = options.authenticationMode ?? "demo_headers";
    if (this.authenticationMode !== "demo_headers" && this.authenticationMode !== "oidc") {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        "authenticationMode must be 'demo_headers' or 'oidc'",
        500,
      );
    }
    if (this.authenticationMode === "demo_headers") {
      if (
        options.identityTrustDomainId !== undefined &&
        options.identityTrustDomainId !== LOCAL_DEMO_IDENTITY_TRUST_DOMAIN
      ) {
        throw new ParimitError(
          "INVALID_CONFIGURATION",
          "demo_headers mode requires the fixed local-demo identity trust domain",
          500,
        );
      }
      this.identityTrustDomainId = LOCAL_DEMO_IDENTITY_TRUST_DOMAIN;
    } else {
      if (!/^sha256:[0-9a-f]{64}$/.test(options.identityTrustDomainId ?? "")) {
        throw new ParimitError(
          "INVALID_CONFIGURATION",
          "OIDC mode requires a sha256 identityTrustDomainId derived from the complete verifier configuration",
          500,
        );
      }
      this.identityTrustDomainId = options.identityTrustDomainId!;
    }
    this.receiptSecret = options.receiptSecret ?? "development-only-change-me";
    this.tenantId = requireIdentifier(options.tenantId ?? DEFAULT_TENANT_ID, "tenantId");
    this.envelopeIssuer = requireTrustUri(
      options.envelopeIssuer ?? DEFAULT_ENVELOPE_ISSUER,
      "envelopeIssuer",
    );
    const audienceValues = Array.from(
      options.envelopeAudiences ?? ["urn:parimit:consumer:local-demo"],
      (value) => requireTrustUri(value, "envelopeAudience"),
    );
    if (audienceValues.length !== 1) {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        "alpha.3 requires exactly one envelope audience per deployment",
        500,
      );
    }
    this.envelopeAudiences = new ImmutableSet(audienceValues);
    this.envelopeTtlSeconds = requireSafePositiveInteger(
      options.envelopeTtlSeconds ?? DEFAULT_ENVELOPE_TTL_SECONDS,
      "envelopeTtlSeconds",
    );
    if (this.envelopeTtlSeconds > 3_600) {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        "envelopeTtlSeconds cannot exceed 3600",
        500,
      );
    }
    try {
      this.envelopeSigningKey = createEnvelopeSigningKey(
        options.envelopeSigningPrivateKeyPem,
        options.envelopeSigningKeyId,
      );
    } catch (error) {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        error instanceof Error ? error.message : "Invalid authorization-envelope signing key",
        500,
      );
    }
    if (
      this.authenticationMode === "oidc" &&
      (this.receiptSecret === "development-only-change-me" ||
        Buffer.byteLength(this.receiptSecret, "utf8") < 32)
    ) {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        "OIDC mode requires a receiptSecret with at least 32 UTF-8 bytes",
        500,
      );
    }
    const requestedPolicy = options.policy ?? {};
    this.policy = Object.freeze({
      rulesVersion: requireConfigurationString(
        requestedPolicy.rulesVersion ?? DEFAULT_POLICY.rulesVersion,
        "policy.rulesVersion",
        128,
      ),
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
    });
    if (this.policy.defaultExpirySeconds > this.policy.maxExpirySeconds) {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        "defaultExpirySeconds cannot exceed maxExpirySeconds",
        500,
      );
    }
    if (this.policy.maxExpirySeconds > MAX_PROPOSAL_EXPIRY_SECONDS) {
      throw new ParimitError(
        "INVALID_CONFIGURATION",
        `maxExpirySeconds cannot exceed ${MAX_PROPOSAL_EXPIRY_SECONDS}`,
        500,
      );
    }
    this.policyConfigurationDigest = sha256(
      canonicalJson({
        version: "parimit-policy-configuration-v1",
        rules_version: this.policy.rulesVersion,
        per_transaction_limit_minor: String(this.policy.perTransactionLimitMinor),
        daily_agent_limit_minor: String(this.policy.dailyAgentLimitMinor),
        dual_approval_threshold_minor: String(this.policy.dualApprovalThresholdMinor),
        default_expiry_seconds: this.policy.defaultExpirySeconds,
        maximum_expiry_seconds: this.policy.maxExpirySeconds,
        blocked_payees: [...this.policy.blockedPayees].sort(),
        allowed_payees:
          this.policy.allowedPayees === null ? null : [...this.policy.allowedPayees].sort(),
      }),
    );
    this.database = new DatabaseSync(options.databasePath ?? ":memory:");
    try {
      this.database.exec("PRAGMA foreign_keys = ON");
      this.preflightReceiptIntegrity();
      this.initializeSchema();
      this.registerEnvelopeSigningKey();
      Object.freeze(this);
    } catch (error) {
      try {
        this.database.close();
      } catch {
        // Preserve the startup failure that explains why the service cannot run.
      }
      throw error;
    }
  }

  close(): void {
    this.database.close();
  }

  private initializeSchema(): void {
    this.database.exec("PRAGMA foreign_keys = OFF");
    try {
      this.database.exec("BEGIN IMMEDIATE");
      this.database.exec(`
      CREATE TABLE IF NOT EXISTS intents (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
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
          intent_version IN (
            'parimit-payment-intent-v1',
            'parimit-payment-intent-v2',
            'parimit-payment-intent-v3'
          )
        ),
        initial_status TEXT NOT NULL CHECK (initial_status IN ('POLICY_DENIED', 'AWAITING_APPROVAL')),
        state_version INTEGER NOT NULL CHECK (state_version >= 1),
        intent_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        UNIQUE (tenant_id, agent_id, idempotency_key)
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

      CREATE TABLE IF NOT EXISTS service_metadata (
        name TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS envelope_signing_keys (
        key_id TEXT PRIMARY KEY,
        public_jwk TEXT NOT NULL,
        created_at TEXT NOT NULL,
        attestation_hmac TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS authorization_envelopes (
        id TEXT PRIMARY KEY,
        intent_id TEXT NOT NULL REFERENCES intents(id),
        tenant_id TEXT NOT NULL,
        state_version INTEGER NOT NULL CHECK (state_version >= 1),
        audience TEXT NOT NULL,
        issuance_idempotency_key TEXT NOT NULL,
        key_id TEXT NOT NULL REFERENCES envelope_signing_keys(key_id),
        compact_jws TEXT NOT NULL UNIQUE,
        claims_hash TEXT NOT NULL,
        nonce_hash TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT,
        consumed_by TEXT,
        consumption_idempotency_key TEXT,
        UNIQUE (tenant_id, intent_id, state_version, audience),
        UNIQUE (tenant_id, nonce_hash)
      );

      CREATE INDEX IF NOT EXISTS idx_intents_agent_created ON intents(agent_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_intent_sequence ON audit_events(intent_id, sequence);
      CREATE INDEX IF NOT EXISTS idx_observations_intent_time ON observations(intent_id, observed_at);
      CREATE INDEX IF NOT EXISTS idx_envelopes_intent_state
        ON authorization_envelopes(intent_id, state_version);
      CREATE INDEX IF NOT EXISTS idx_envelopes_expiry
        ON authorization_envelopes(expires_at);
      `);

    // Databases created before alpha.3 used v1/v2 digests and no tenant/state
    // columns. Detect first, then migrate every column and backfill in one
    // transaction so an interrupted startup cannot strand partial defaults.
    const intentColumns = new Set(
      (this.database.prepare("PRAGMA table_info(intents)").all() as SqlRow[]).map((row) =>
        stringCell(row, "name"),
      ),
    );
    const intentSchemaRow = this.database
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'intents'")
      .get() as SqlRow | undefined;
    const hasV3Schema =
      intentSchemaRow !== undefined &&
      stringCell(intentSchemaRow, "sql").includes("parimit-payment-intent-v3");
      if (!hasV3Schema) {
        this.migrateIntentTableForV3(intentColumns);
      } else {
        for (const requiredColumn of [
          "intent_version",
          "initial_status",
          "tenant_id",
          "state_version",
        ]) {
          if (!intentColumns.has(requiredColumn)) {
            throw new ParimitError(
              "DATABASE_MIGRATION_FAILED",
              `v3 intent schema is missing required column ${requiredColumn}`,
              500,
            );
          }
        }
      }
      this.registerReceiptIntegrityRoot();
      this.registerEnvelopeSigningKeyRegistryState();
      const violations = this.database.prepare("PRAGMA foreign_key_check").all() as SqlRow[];
      if (violations.length > 0) {
        throw new ParimitError(
          "DATABASE_MIGRATION_FAILED",
          "Schema initialization produced a foreign-key violation",
          500,
        );
      }
      this.database.exec("COMMIT");
    } catch (error) {
      try {
        this.database.exec("ROLLBACK");
      } catch {
        // The original initialization error is the actionable failure.
      }
      throw error;
    } finally {
      this.database.exec("PRAGMA foreign_keys = ON");
    }
  }

  private migrateIntentTableForV3(intentColumns: ReadonlySet<string>): void {
      if (!intentColumns.has("intent_version")) {
        this.database.exec(
          "ALTER TABLE intents ADD COLUMN intent_version TEXT NOT NULL DEFAULT 'parimit-payment-intent-v1'",
        );
      }
      if (!intentColumns.has("initial_status")) {
        this.database.exec(
          "ALTER TABLE intents ADD COLUMN initial_status TEXT NOT NULL DEFAULT 'AWAITING_APPROVAL'",
        );
      }
      if (!intentColumns.has("tenant_id")) {
        this.database.exec(
          "ALTER TABLE intents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'local-demo'",
        );
      }
      if (!intentColumns.has("state_version")) {
        this.database.exec(
          "ALTER TABLE intents ADD COLUMN state_version INTEGER NOT NULL DEFAULT 1",
        );
      }
      if (!intentColumns.has("initial_status")) {
        this.database.exec(`
          UPDATE intents
             SET initial_status = CASE
               WHEN policy_allowed = 1 THEN 'AWAITING_APPROVAL'
               ELSE 'POLICY_DENIED'
             END
        `);
      }
      this.database.prepare("UPDATE intents SET tenant_id = ?").run(this.tenantId);
      this.database.exec(`
        UPDATE intents
           SET state_version = 1
             + (SELECT COUNT(*) FROM approvals WHERE approvals.intent_id = intents.id)
             + (SELECT COUNT(*)
                  FROM audit_events
                 WHERE audit_events.intent_id = intents.id
                   AND audit_events.event_type IN ('PROPOSAL_CANCELLED', 'PROPOSAL_EXPIRED'))
      `);
      this.database.exec(`
        CREATE TABLE intents_v3_migration (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
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
            intent_version IN (
              'parimit-payment-intent-v1',
              'parimit-payment-intent-v2',
              'parimit-payment-intent-v3'
            )
          ),
          initial_status TEXT NOT NULL CHECK (initial_status IN ('POLICY_DENIED', 'AWAITING_APPROVAL')),
          state_version INTEGER NOT NULL CHECK (state_version >= 1),
          intent_hash TEXT NOT NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          UNIQUE (tenant_id, agent_id, idempotency_key)
        );
        INSERT INTO intents_v3_migration
          (id, tenant_id, idempotency_key, request_fingerprint, agent_id, on_behalf_of,
           amount_minor, currency, payee_reference, purpose, status, required_approvals,
           policy_allowed, policy_reasons, rules_version, intent_version, initial_status,
           state_version, intent_hash, created_at, expires_at)
        SELECT id, tenant_id, idempotency_key, request_fingerprint, agent_id, on_behalf_of,
               amount_minor, currency, payee_reference, purpose, status, required_approvals,
               policy_allowed, policy_reasons, rules_version, intent_version, initial_status,
               state_version, intent_hash, created_at, expires_at
          FROM intents;
        DROP TABLE intents;
        ALTER TABLE intents_v3_migration RENAME TO intents;
        CREATE INDEX idx_intents_agent_created ON intents(agent_id, created_at);
      `);
  }

  private signingKeyAttestationPayload(
    keyId: string,
    publicJwk: Record<string, unknown>,
    createdAt: string,
  ): Record<string, unknown> {
    return {
      version: "parimit-envelope-signing-key-v1",
      key_id: keyId,
      public_jwk: publicJwk,
      created_at: createdAt,
    };
  }

  private receiptIntegrityRootPayload(): Record<string, unknown> {
    return {
      version: "parimit-receipt-integrity-root-v1",
      tenant_id: this.tenantId,
      envelope_issuer: this.envelopeIssuer,
      envelope_audience: [...this.envelopeAudiences][0],
      envelope_maximum_lifetime_seconds: this.envelopeTtlSeconds,
      authentication_mode: this.authenticationMode,
      identity_trust_domain_id: this.identityTrustDomainId,
      policy_configuration_digest: this.policyConfigurationDigest,
    };
  }

  private envelopeSigningKeyRows(): SqlRow[] {
    if (!this.tableExists("envelope_signing_keys")) return [];
    return this.database
      .prepare("SELECT * FROM envelope_signing_keys ORDER BY key_id")
      .all() as SqlRow[];
  }

  private envelopeSigningKeyRegistryStatePayload(
    signingKeyRows: readonly SqlRow[],
  ): Record<string, unknown> {
    return {
      version: "parimit-envelope-signing-key-registry-state-v1",
      keys: signingKeyRows.map((row) => ({
        key_id: stringCell(row, "key_id"),
        public_jwk: parseJson<Record<string, unknown>>(stringCell(row, "public_jwk")),
        created_at: stringCell(row, "created_at"),
        attestation_hmac: stringCell(row, "attestation_hmac"),
      })),
    };
  }

  private envelopeSigningKeyRegistryState(signingKeyRows: readonly SqlRow[]): string {
    return hmacSha256(
      this.receiptSecret,
      this.envelopeSigningKeyRegistryStatePayload(signingKeyRows),
    );
  }

  private validateEnvelopeSigningKeyRows(
    signingKeyRows: readonly SqlRow[],
    errorCode: string,
  ): void {
    for (const row of signingKeyRows) {
      let publicJwk: Record<string, unknown>;
      try {
        publicJwk = parseJson<Record<string, unknown>>(stringCell(row, "public_jwk"));
      } catch {
        throw new ParimitError(
          errorCode,
          "Existing envelope verification-key evidence is malformed",
          500,
        );
      }
      const attestation = hmacSha256(
        this.receiptSecret,
        this.signingKeyAttestationPayload(
          stringCell(row, "key_id"),
          publicJwk,
          stringCell(row, "created_at"),
        ),
      );
      if (!safeEqualText(attestation, stringCell(row, "attestation_hmac"))) {
        throw new ParimitError(
          errorCode,
          "The receipt key cannot verify the existing envelope key registry",
          500,
        );
      }
    }
  }

  private assertEnvelopeSigningKeyRegistryState(
    signingKeyRows: readonly SqlRow[],
    errorCode: string,
  ): void {
    const existing = this.tableExists("service_metadata")
      ? (this.database
          .prepare("SELECT value FROM service_metadata WHERE name = ?")
          .get(ENVELOPE_KEY_REGISTRY_STATE_NAME) as SqlRow | undefined)
      : undefined;
    if (!existing) {
      throw new ParimitError(
        errorCode,
        "The envelope signing-key registry checkpoint is missing",
        500,
      );
    }
    let expected: string;
    try {
      expected = this.envelopeSigningKeyRegistryState(signingKeyRows);
    } catch {
      throw new ParimitError(
        errorCode,
        "The envelope signing-key registry is malformed",
        500,
      );
    }
    if (!safeEqualText(stringCell(existing, "value"), expected)) {
      throw new ParimitError(
        errorCode,
        "The envelope signing-key registry does not match its protected checkpoint",
        500,
      );
    }
  }

  private validatedEnvelopeSigningKeyRows(): SqlRow[] {
    const rows = this.envelopeSigningKeyRows();
    this.validateEnvelopeSigningKeyRows(rows, "SIGNING_KEY_INTEGRITY_FAILURE");
    this.assertEnvelopeSigningKeyRegistryState(rows, "SIGNING_KEY_INTEGRITY_FAILURE");
    return rows;
  }

  private tableExists(name: string): boolean {
    return (
      this.database
        .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?")
        .get(name) !== undefined
    );
  }

  private assertReceiptIntegrityRootMatches(value: string): void {
    const expected = hmacSha256(this.receiptSecret, this.receiptIntegrityRootPayload());
    if (!safeEqualText(value, expected)) {
      throw new ParimitError(
        "RECEIPT_KEY_MISMATCH",
        "The receipt key or deployment trust configuration does not match this database's integrity root",
        500,
      );
    }
  }

  private validateReceiptBoundEvidence(
    approvalRows: readonly SqlRow[],
    signingKeyRows: readonly SqlRow[],
  ): void {
    if (this.authenticationMode === "oidc" && approvalRows.length > 0) {
      throw new ParimitError(
        "UNATTESTED_IDENTITY_HISTORY",
        "OIDC mode cannot adopt approval evidence created before authentication mode was database-bound",
        500,
      );
    }
    for (const row of approvalRows) {
      const receipt = hmacSha256(
        this.receiptSecret,
        this.approvalReceiptPayload(
          stringCell(row, "intent_id"),
          stringCell(row, "intent_hash"),
          stringCell(row, "actor_id"),
          stringCell(row, "actor_role") as "approver" | "admin",
          stringCell(row, "decision") as ApprovalDecision,
          stringCell(row, "created_at"),
        ),
      );
      if (!safeEqualText(receipt, stringCell(row, "receipt_hmac"))) {
        throw new ParimitError(
          "RECEIPT_KEY_MISMATCH",
          "The receipt key cannot verify existing approval evidence",
          500,
        );
      }
    }

    this.validateEnvelopeSigningKeyRows(signingKeyRows, "RECEIPT_KEY_MISMATCH");
  }

  private preflightReceiptIntegrity(): void {
    if (this.tableExists("service_metadata")) {
      const existing = this.database
        .prepare("SELECT value FROM service_metadata WHERE name = ?")
        .get(RECEIPT_INTEGRITY_ROOT_NAME) as SqlRow | undefined;
      if (existing) {
        this.assertReceiptIntegrityRootMatches(stringCell(existing, "value"));
        const signingKeyRows = this.envelopeSigningKeyRows();
        this.validateEnvelopeSigningKeyRows(
          signingKeyRows,
          "SIGNING_KEY_INTEGRITY_FAILURE",
        );
        this.assertEnvelopeSigningKeyRegistryState(
          signingKeyRows,
          "SIGNING_KEY_INTEGRITY_FAILURE",
        );
        return;
      }
    }

    if (this.tableExists("intents")) {
      const schema = this.database
        .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'intents'")
        .get() as SqlRow | undefined;
      if (schema && stringCell(schema, "sql").includes("parimit-payment-intent-v3")) {
        const materialTables = [
          "intents",
          "approvals",
          "observations",
          "audit_events",
          "envelope_signing_keys",
          "authorization_envelopes",
          "service_metadata",
        ];
        const hasMaterialHistory = materialTables.some(
          (table) =>
            this.tableExists(table) &&
            this.database.prepare(`SELECT 1 AS present FROM ${table} LIMIT 1`).get() !== undefined,
        );
        if (hasMaterialHistory) {
          throw new ParimitError(
            "TRUST_ROOT_MISSING",
            "A v3 database with material history is missing its receipt integrity root and cannot be rebound in place",
            500,
          );
        }
      }
    }

    const approvalRows = this.tableExists("approvals")
      ? (this.database
          .prepare("SELECT * FROM approvals ORDER BY intent_id, created_at, id")
          .all() as SqlRow[])
      : [];
    const signingKeyRows = this.envelopeSigningKeyRows();
    this.validateReceiptBoundEvidence(approvalRows, signingKeyRows);
  }

  private registerReceiptIntegrityRoot(): void {
    const expected = hmacSha256(this.receiptSecret, this.receiptIntegrityRootPayload());
    const existing = this.database
      .prepare("SELECT value FROM service_metadata WHERE name = ?")
      .get(RECEIPT_INTEGRITY_ROOT_NAME) as SqlRow | undefined;
    if (existing) {
      this.assertReceiptIntegrityRootMatches(stringCell(existing, "value"));
      return;
    }

    const approvalRows = this.database
      .prepare("SELECT * FROM approvals ORDER BY intent_id, created_at, id")
      .all() as SqlRow[];
    const signingKeyRows = this.database
      .prepare("SELECT * FROM envelope_signing_keys ORDER BY created_at, key_id")
      .all() as SqlRow[];
    this.validateReceiptBoundEvidence(approvalRows, signingKeyRows);

    this.database
      .prepare("INSERT INTO service_metadata (name, value) VALUES (?, ?)")
      .run(RECEIPT_INTEGRITY_ROOT_NAME, expected);
  }

  private registerEnvelopeSigningKeyRegistryState(): void {
    const signingKeyRows = this.envelopeSigningKeyRows();
    this.validateEnvelopeSigningKeyRows(signingKeyRows, "SIGNING_KEY_INTEGRITY_FAILURE");
    const existing = this.database
      .prepare("SELECT value FROM service_metadata WHERE name = ?")
      .get(ENVELOPE_KEY_REGISTRY_STATE_NAME) as SqlRow | undefined;
    if (existing) {
      this.assertEnvelopeSigningKeyRegistryState(
        signingKeyRows,
        "SIGNING_KEY_INTEGRITY_FAILURE",
      );
      return;
    }
    if (signingKeyRows.length > 0) {
      throw new ParimitError(
        "TRUST_ROOT_MISSING",
        "An existing envelope signing-key registry is missing its protected checkpoint",
        500,
      );
    }
    this.database
      .prepare("INSERT INTO service_metadata (name, value) VALUES (?, ?)")
      .run(
        ENVELOPE_KEY_REGISTRY_STATE_NAME,
        this.envelopeSigningKeyRegistryState(signingKeyRows),
      );
  }

  private registerEnvelopeSigningKey(): void {
    this.transaction(() => {
      const keyId = this.envelopeSigningKey.keyId;
      const publicJwk = canonicalJson(this.envelopeSigningKey.publicJwk);
      const signingKeyRows = this.validatedEnvelopeSigningKeyRows();
      const existing = signingKeyRows.find((row) => stringCell(row, "key_id") === keyId);
      if (existing) {
        const createdAt = stringCell(existing, "created_at");
        const storedJwk = parseJson<Record<string, unknown>>(stringCell(existing, "public_jwk"));
        const expectedAttestation = hmacSha256(
          this.receiptSecret,
          this.signingKeyAttestationPayload(keyId, storedJwk, createdAt),
        );
        if (
          !safeEqualText(stringCell(existing, "public_jwk"), publicJwk) ||
          !safeEqualText(stringCell(existing, "attestation_hmac"), expectedAttestation)
        ) {
          throw new ParimitError(
            "SIGNING_KEY_CONFLICT",
            "The configured envelope key id conflicts with the protected verification-key registry",
            500,
          );
        }
        return;
      }
      const createdAt = this.now();
      const attestation = hmacSha256(
        this.receiptSecret,
        this.signingKeyAttestationPayload(
          keyId,
          this.envelopeSigningKey.publicJwk,
          createdAt,
        ),
      );
      this.database
        .prepare(
          `INSERT INTO envelope_signing_keys
            (key_id, public_jwk, created_at, attestation_hmac)
           VALUES (?, ?, ?, ?)`,
        )
        .run(keyId, publicJwk, createdAt, attestation);
      const updatedRows = this.envelopeSigningKeyRows();
      this.validateEnvelopeSigningKeyRows(
        updatedRows,
        "SIGNING_KEY_INTEGRITY_FAILURE",
      );
      const update = this.database
        .prepare("UPDATE service_metadata SET value = ? WHERE name = ?")
        .run(
          this.envelopeSigningKeyRegistryState(updatedRows),
          ENVELOPE_KEY_REGISTRY_STATE_NAME,
        );
      if (Number(update.changes) !== 1) {
        throw new ParimitError(
          "SIGNING_KEY_INTEGRITY_FAILURE",
          "The envelope signing-key registry checkpoint could not be updated",
          500,
        );
      }
    });
  }

  private trustedEnvelopePublicJwk(keyId: string): Record<string, unknown> {
    const row = requiredRow(
      this.validatedEnvelopeSigningKeyRows().find(
        (candidate) => stringCell(candidate, "key_id") === keyId,
      ),
      "Envelope signing key not found",
    );
    return parseJson<Record<string, unknown>>(stringCell(row, "public_jwk"));
  }

  envelopeJwks(): { keys: Record<string, unknown>[] } {
    const rows = this.validatedEnvelopeSigningKeyRows();
    return {
      keys: rows.map((row) =>
        parseJson<Record<string, unknown>>(stringCell(row, "public_jwk")),
      ),
    };
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
      tenant_id: this.tenantId,
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
        config_digest: policy.config_digest,
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
    if (version !== POLICY_BOUND_INTENT_VERSION && version !== CURRENT_INTENT_VERSION) {
      throw new TypeError(`Unsupported payment intent digest version: ${version}`);
    }
    const storedPolicy = {
      allowed: numberCell(row, "policy_allowed") === 1,
      reasons: parseJson<unknown>(stringCell(row, "policy_reasons")),
      rules_version: stringCell(row, "rules_version"),
      required_approvals: numberCell(row, "required_approvals"),
    };
    const policyBound = {
      version,
      ...common,
      amount: {
        currency: stringCell(row, "currency"),
        minor: String(numberCell(row, "amount_minor")),
      },
      initial_status: stringCell(row, "initial_status"),
      policy: storedPolicy,
    };
    return version === CURRENT_INTENT_VERSION
      ? {
          ...policyBound,
          tenant_id: stringCell(row, "tenant_id"),
          policy: { ...storedPolicy, config_digest: this.policyConfigurationDigest },
        }
      : policyBound;
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
      .prepare(
        "SELECT event_hash, occurred_at FROM audit_events WHERE intent_id = ? ORDER BY sequence DESC LIMIT 1",
      )
      .get(intentId) as SqlRow | undefined;
    const intent = this.database
      .prepare("SELECT created_at FROM intents WHERE id = ? AND tenant_id = ?")
      .get(intentId, this.tenantId) as SqlRow | undefined;
    if (
      !intent ||
      !isCanonicalTimestamp(occurredAt) ||
      occurredAt < stringCell(intent, "created_at") ||
      (previous !== undefined && occurredAt < stringCell(previous, "occurred_at"))
    ) {
      throw new ParimitError(
        "CLOCK_ROLLBACK_DETECTED",
        "Audit evidence cannot be recorded before the proposal or its latest event",
        409,
      );
    }
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
      .prepare(
        "SELECT id FROM intents WHERE tenant_id = ? AND status = 'AWAITING_APPROVAL' AND expires_at <= ?",
      )
      .all(this.tenantId, now) as SqlRow[];
    if (rows.length === 0) return;
    this.transaction(() => {
      for (const row of rows) {
        const id = stringCell(row, "id");
        const result = this.database
          .prepare(
            `UPDATE intents
                SET status = 'EXPIRED', state_version = state_version + 1
              WHERE id = ? AND tenant_id = ? AND status = 'AWAITING_APPROVAL'`,
          )
          .run(id, this.tenantId);
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
            AND tenant_id = ?
            AND created_at >= ?
            AND policy_allowed = 1
            AND status IN ('AWAITING_APPROVAL', 'AUTHORIZED_NO_DISPATCH')`,
      )
      .get(agentId, this.tenantId, start.toISOString()) as SqlRow;
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
      config_digest: this.policyConfigurationDigest,
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
    const result = this.transaction(() => {
      const existing = this.database
        .prepare(
          `SELECT id, request_fingerprint
             FROM intents
            WHERE tenant_id = ? AND agent_id = ? AND idempotency_key = ?`,
        )
        .get(this.tenantId, input.agentId, input.idempotencyKey) as SqlRow | undefined;
      if (existing) {
        if (!safeEqualText(stringCell(existing, "request_fingerprint"), requestFingerprint)) {
          throw new ParimitError(
            "IDEMPOTENCY_CONFLICT",
            "This agent already used the idempotency key for a different proposal",
            409,
          );
        }
        return { id: stringCell(existing, "id"), idempotentReplay: true };
      }

      const policy = this.decidePolicy(input);
      const id = randomUUID();
      const createdAt = this.now();
      const expiresAt = new Date(
        new Date(createdAt).getTime() + input.expiresInSeconds * 1_000,
      ).toISOString();
      const status: InitialIntentStatus = policy.allowed
        ? "AWAITING_APPROVAL"
        : "POLICY_DENIED";
      const intentHash = sha256(
        canonicalJson(this.intentPayload(id, input, createdAt, expiresAt, policy, status)),
      );
      this.database
        .prepare(
          `INSERT INTO intents
            (id, tenant_id, idempotency_key, request_fingerprint, agent_id, on_behalf_of, amount_minor,
             currency, payee_reference, purpose, status, required_approvals, policy_allowed,
             policy_reasons, rules_version, intent_version, initial_status, state_version, intent_hash,
             created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'INR', ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
        )
        .run(
          id,
          this.tenantId,
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
          tenant_id: this.tenantId,
          state_version: 1,
          status,
          policy,
          boundary: "PROPOSAL_ONLY_NO_VALUE_MOVEMENT",
        },
        createdAt,
      );
      return { id, idempotentReplay: false };
    });
    return {
      ...this.getIntent(result.id),
      ...(result.idempotentReplay ? { idempotent_replay: true } : {}),
    };
  }

  private getRawIntent(id: string): SqlRow {
    return requiredRow(
      this.database
        .prepare("SELECT * FROM intents WHERE id = ? AND tenant_id = ?")
        .get(id, this.tenantId) as SqlRow | undefined,
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
      tenant_id: stringCell(row, "tenant_id"),
      state_version: numberCell(row, "state_version"),
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
        ...(stringCell(row, "intent_version") === CURRENT_INTENT_VERSION
          ? { config_digest: this.policyConfigurationDigest }
          : {}),
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

  assertIntentOwnedByAgent(id: string, actorIdValue: unknown): void {
    this.expireDueIntents();
    const actorId = requireIdentifier(actorIdValue, "actor_id");
    requiredRow(
      this.database
        .prepare("SELECT id FROM intents WHERE id = ? AND tenant_id = ? AND agent_id = ?")
        .get(id, this.tenantId, actorId) as SqlRow | undefined,
    );
  }

  listIntents(filters: { agentId?: string; status?: IntentStatus; limit?: number } = {}): IntentView[] {
    this.expireDueIntents();
    const clauses: string[] = ["tenant_id = ?"];
    const parameters: Array<string | number> = [this.tenantId];
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
    const expiredBeforeDecision = this.transaction(() => {
      const row = this.getRawIntent(id);
      this.assertStoredIntegrity(row);
      if (stringCell(row, "agent_id") === actorId) {
        throw new ParimitError(
          "AGENT_CANNOT_APPROVE",
          "The requesting agent cannot approve its own proposal",
          403,
        );
      }
      if (stringCell(row, "status") !== "AWAITING_APPROVAL") {
        throw new ParimitError(
          "INVALID_STATE",
          `Proposal cannot be reviewed while in ${stringCell(row, "status")} state`,
          409,
        );
      }
      const decisionTime = this.now();
      if (decisionTime >= stringCell(row, "expires_at")) {
        const expired = this.database
          .prepare(
            `UPDATE intents
                SET status = 'EXPIRED', state_version = state_version + 1
              WHERE id = ? AND tenant_id = ? AND status = 'AWAITING_APPROVAL'`,
          )
          .run(id, this.tenantId);
        if (Number(expired.changes) !== 1) {
          throw new ParimitError(
            "STATE_CONFLICT",
            "Proposal state changed while enforcing its approval deadline",
            409,
          );
        }
        this.appendAudit(id, "PROPOSAL_EXPIRED", "parimit-clock", { status: "EXPIRED" }, decisionTime);
        return true;
      }
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
      const createdAt = decisionTime;
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
      const update = this.database
        .prepare(
          `UPDATE intents
              SET status = ?, state_version = state_version + 1
            WHERE id = ? AND tenant_id = ? AND status = 'AWAITING_APPROVAL'`,
        )
        .run(nextStatus, id, this.tenantId);
      if (Number(update.changes) !== 1) {
        throw new ParimitError(
          "STATE_CONFLICT",
          "Proposal state changed before the decision could be recorded",
          409,
        );
      }
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
      return false;
    });
    if (expiredBeforeDecision) {
      throw new ParimitError(
        "PROPOSAL_EXPIRED",
        "Proposal expired before the human decision could be recorded",
        409,
      );
    }
    return this.getIntent(id);
  }

  cancelIntent(id: string, actorIdValue: unknown, actorRoleValue: unknown = "agent"): IntentView {
    this.expireDueIntents();
    const actorId = requireIdentifier(actorIdValue, "actor_id");
    const actorRole = String(actorRoleValue).toLocaleLowerCase("en-US") as ActorRole;
    if (actorRole !== "agent" && actorRole !== "admin") {
      throw new ParimitError("FORBIDDEN", "Only the requesting agent or a demo admin may cancel", 403);
    }
    const expiredBeforeCancellation = this.transaction(() => {
      const row =
        actorRole === "agent"
          ? requiredRow(
              this.database
                .prepare("SELECT * FROM intents WHERE id = ? AND tenant_id = ? AND agent_id = ?")
                .get(id, this.tenantId, actorId) as SqlRow | undefined,
            )
          : this.getRawIntent(id);
      this.assertStoredIntegrity(row);
      if (stringCell(row, "status") !== "AWAITING_APPROVAL") {
        throw new ParimitError(
          "INVALID_STATE",
          `Proposal cannot be cancelled while in ${stringCell(row, "status")} state`,
          409,
        );
      }
      const occurredAt = this.now();
      if (occurredAt >= stringCell(row, "expires_at")) {
        const expired = this.database
          .prepare(
            `UPDATE intents
                SET status = 'EXPIRED', state_version = state_version + 1
              WHERE id = ? AND tenant_id = ? AND status = 'AWAITING_APPROVAL'`,
          )
          .run(id, this.tenantId);
        if (Number(expired.changes) !== 1) {
          throw new ParimitError(
            "STATE_CONFLICT",
            "Proposal state changed while enforcing its cancellation deadline",
            409,
          );
        }
        this.appendAudit(id, "PROPOSAL_EXPIRED", "parimit-clock", { status: "EXPIRED" }, occurredAt);
        return true;
      }
      const update = this.database
        .prepare(
          `UPDATE intents
              SET status = 'CANCELLED', state_version = state_version + 1
            WHERE id = ? AND tenant_id = ? AND status = 'AWAITING_APPROVAL'`,
        )
        .run(id, this.tenantId);
      if (Number(update.changes) !== 1) {
        throw new ParimitError(
          "STATE_CONFLICT",
          "Proposal state changed before cancellation could be recorded",
          409,
        );
      }
      this.appendAudit(id, "PROPOSAL_CANCELLED", actorId, { status: "CANCELLED" }, occurredAt);
      return false;
    });
    if (expiredBeforeCancellation) {
      throw new ParimitError(
        "PROPOSAL_EXPIRED",
        "Proposal expired before cancellation could be recorded",
        409,
      );
    }
    return this.getIntent(id);
  }

  private normalizeEnvelopeIssueInput(value: unknown): Required<AuthorizationEnvelopeIssueInput> {
    if (!isRecord(value)) {
      throw new ParimitError("VALIDATION_ERROR", "Request body must be a JSON object", 400);
    }
    rejectUnknownKeys(
      value,
      new Set(["audience", "idempotency_key", "expires_in_seconds"]),
      "Request body",
    );
    const audience = requireString(value.audience, "audience", 512);
    if (!this.envelopeAudiences.has(audience)) {
      throw new ParimitError(
        "ENVELOPE_AUDIENCE_NOT_ALLOWED",
        "audience is not configured as a trusted envelope recipient",
        403,
      );
    }
    const requestedTtl = value.expires_in_seconds ?? this.envelopeTtlSeconds;
    if (
      !Number.isInteger(requestedTtl) ||
      (requestedTtl as number) < 1 ||
      (requestedTtl as number) > this.envelopeTtlSeconds
    ) {
      throw new ParimitError(
        "VALIDATION_ERROR",
        `expires_in_seconds must be an integer between 1 and ${this.envelopeTtlSeconds}`,
        400,
      );
    }
    return {
      audience,
      idempotency_key: requireIdentifier(value.idempotency_key, "idempotency_key"),
      expires_in_seconds: requestedTtl as number,
    };
  }

  private envelopeApprovals(id: string): AuthorizationEnvelopeClaims["decision"]["approvals"] {
    return this.approvalsFor(id)
      .filter((approval) => approval.decision === "APPROVE")
      .map((approval) => ({
        subject: approval.actor_id,
        role: approval.actor_role,
        decision: "APPROVE" as const,
        intent_hash: approval.intent_hash,
        decided_at: approval.created_at,
        record_digest: sha256(
          canonicalJson({
            actor_id: approval.actor_id,
            actor_role: approval.actor_role,
            decision: approval.decision,
            intent_hash: approval.intent_hash,
            created_at: approval.created_at,
            receipt_hmac: approval.receipt_hmac,
          }),
        ),
      }))
      .sort((left, right) =>
        compareCodeUnits(left.decided_at, right.decided_at) ||
        compareCodeUnits(left.subject, right.subject),
      );
  }

  private strictEnvelopeClaims(value: Record<string, unknown>): AuthorizationEnvelopeClaims {
    if (
      !hasExactKeys(value, [
        "version",
        "iss",
        "sub",
        "aud",
        "jti",
        "iat",
        "nbf",
        "exp",
        "issued_at",
        "tenant_id",
        "identity_assurance",
        "intent",
        "policy_digest",
        "decision",
        "replay",
        "source_audit",
        "capability",
        "notice",
      ]) ||
      value.version !== "parimit-authorization-envelope-v1" ||
      typeof value.iss !== "string" ||
      typeof value.sub !== "string" ||
      typeof value.aud !== "string" ||
      typeof value.jti !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        value.jti,
      ) ||
      !Number.isSafeInteger(value.iat) ||
      !Number.isSafeInteger(value.nbf) ||
      !Number.isSafeInteger(value.exp) ||
      value.iat !== value.nbf ||
      (value.exp as number) <= (value.iat as number) ||
      !isCanonicalTimestamp(value.issued_at) ||
      Math.floor(Date.parse(String(value.issued_at)) / 1_000) !== value.iat ||
      typeof value.tenant_id !== "string" ||
      !isRecord(value.identity_assurance) ||
      value.notice !== AUTHORIZATION_ENVELOPE_NOTICE ||
      !isRecord(value.intent) ||
      !isRecord(value.policy_digest) ||
      !isRecord(value.decision) ||
      !isRecord(value.replay) ||
      !isRecord(value.source_audit) ||
      !isRecord(value.capability)
    ) {
      throw new TypeError("Authorization envelope claims have an invalid top-level schema");
    }

    if (
      !hasExactKeys(value.identity_assurance, [
        "authentication_method",
        "cryptographically_verified",
        "trust_domain_id",
      ]) ||
      (value.identity_assurance.authentication_method !== "oidc" &&
        value.identity_assurance.authentication_method !== "local_demo_headers") ||
      value.identity_assurance.cryptographically_verified !==
        (value.identity_assurance.authentication_method === "oidc") ||
      typeof value.identity_assurance.trust_domain_id !== "string" ||
      (value.identity_assurance.authentication_method === "oidc"
        ? !/^sha256:[0-9a-f]{64}$/.test(value.identity_assurance.trust_domain_id)
        : value.identity_assurance.trust_domain_id !== LOCAL_DEMO_IDENTITY_TRUST_DOMAIN)
    ) {
      throw new TypeError("Authorization envelope identity assurance is invalid");
    }

    const intent = value.intent;
    if (
      !hasExactKeys(intent, ["snapshot", "digest"]) ||
      !isRecord(intent.snapshot) ||
      !isRecord(intent.digest)
    ) {
      throw new TypeError("Authorization envelope intent binding is invalid");
    }
    const snapshot = intent.snapshot;
    if (
      !hasExactKeys(snapshot, [
        "version",
        "id",
        "tenant_id",
        "idempotency_key",
        "requested_by",
        "on_behalf_of",
        "amount",
        "payee_reference",
        "purpose",
        "initial_status",
        "policy",
        "created_at",
        "expires_at",
      ]) ||
      snapshot.version !== CURRENT_INTENT_VERSION ||
      typeof snapshot.id !== "string" ||
      typeof snapshot.tenant_id !== "string" ||
      typeof snapshot.idempotency_key !== "string" ||
      !isRecord(snapshot.requested_by) ||
      !hasExactKeys(snapshot.requested_by, ["type", "id"]) ||
      snapshot.requested_by.type !== "agent" ||
      typeof snapshot.requested_by.id !== "string" ||
      (snapshot.on_behalf_of !== null && typeof snapshot.on_behalf_of !== "string") ||
      !isRecord(snapshot.amount) ||
      !hasExactKeys(snapshot.amount, ["currency", "minor"]) ||
      snapshot.amount.currency !== "INR" ||
      typeof snapshot.amount.minor !== "string" ||
      typeof snapshot.payee_reference !== "string" ||
      typeof snapshot.purpose !== "string" ||
      snapshot.initial_status !== "AWAITING_APPROVAL" ||
      !isCanonicalTimestamp(snapshot.created_at) ||
      !isCanonicalTimestamp(snapshot.expires_at) ||
      !isRecord(snapshot.policy)
    ) {
      throw new TypeError("Authorization envelope intent snapshot is invalid");
    }
    const policy = snapshot.policy;
    if (
      !hasExactKeys(policy, [
        "allowed",
        "reasons",
        "rules_version",
        "config_digest",
        "required_approvals",
      ]) ||
      policy.allowed !== true ||
      !Array.isArray(policy.reasons) ||
      !policy.reasons.every((reason) => typeof reason === "string") ||
      typeof policy.rules_version !== "string" ||
      !isSha256Hex(policy.config_digest) ||
      (policy.required_approvals !== 1 && policy.required_approvals !== 2) ||
      !hasExactKeys(intent.digest, ["alg", "value"]) ||
      intent.digest.alg !== "sha-256" ||
      !isSha256Hex(intent.digest.value) ||
      !hasExactKeys(value.policy_digest, ["alg", "value"]) ||
      value.policy_digest.alg !== "sha-256" ||
      !isSha256Hex(value.policy_digest.value)
    ) {
      throw new TypeError("Authorization envelope policy or digest is invalid");
    }

    const decision = value.decision;
    if (
      !hasExactKeys(decision, [
        "state",
        "authorization_state_version",
        "required_approvals",
        "fully_approved_at",
        "approval_set_digest",
        "approvals",
      ]) ||
      decision.state !== "AUTHORIZED_NO_DISPATCH" ||
      !Number.isSafeInteger(decision.authorization_state_version) ||
      (decision.authorization_state_version as number) < 2 ||
      (decision.required_approvals !== 1 && decision.required_approvals !== 2) ||
      !isCanonicalTimestamp(decision.fully_approved_at) ||
      !isRecord(decision.approval_set_digest) ||
      !hasExactKeys(decision.approval_set_digest, ["alg", "value"]) ||
      decision.approval_set_digest.alg !== "sha-256" ||
      !isSha256Hex(decision.approval_set_digest.value) ||
      !Array.isArray(decision.approvals) ||
      decision.approvals.length !== decision.required_approvals
    ) {
      throw new TypeError("Authorization envelope decision is invalid");
    }
    for (const approval of decision.approvals) {
      if (
        !isRecord(approval) ||
        !hasExactKeys(approval, [
          "subject",
          "role",
          "decision",
          "intent_hash",
          "decided_at",
          "record_digest",
        ]) ||
        typeof approval.subject !== "string" ||
        (approval.role !== "approver" && approval.role !== "admin") ||
        approval.decision !== "APPROVE" ||
        !isSha256Hex(approval.intent_hash) ||
        !isCanonicalTimestamp(approval.decided_at) ||
        !isSha256Hex(approval.record_digest)
      ) {
        throw new TypeError("Authorization envelope approval set is invalid");
      }
    }
    const approvals = decision.approvals as Array<Record<string, unknown>>;
    const approvalSubjects = approvals.map((approval) => String(approval.subject));
    const orderedApprovals = [...approvals].sort((left, right) =>
      compareCodeUnits(String(left.decided_at), String(right.decided_at)) ||
      compareCodeUnits(String(left.subject), String(right.subject)),
    );
    if (
      snapshot.tenant_id !== value.tenant_id ||
      value.sub !== `urn:parimit:intent:${snapshot.id}` ||
      decision.required_approvals !== policy.required_approvals ||
      decision.authorization_state_version !== approvals.length + 1 ||
      new Set(approvalSubjects).size !== approvals.length ||
      canonicalJson(approvals) !== canonicalJson(orderedApprovals) ||
      decision.fully_approved_at !== approvals.at(-1)?.decided_at ||
      Date.parse(String(decision.fully_approved_at)) > Date.parse(String(value.issued_at)) ||
      Date.parse(String(snapshot.created_at)) > Date.parse(String(value.issued_at)) ||
      Date.parse(String(value.issued_at)) >= (value.exp as number) * 1_000 ||
      approvals.some(
        (approval) =>
          Date.parse(String(approval.decided_at)) < Date.parse(String(snapshot.created_at)) ||
          Date.parse(String(approval.decided_at)) >= Date.parse(String(snapshot.expires_at)) ||
          Date.parse(String(approval.decided_at)) > Date.parse(String(value.issued_at)),
      ) ||
      approvals.some((approval) => approval.intent_hash !== intent.digest.value) ||
      Date.parse(String(snapshot.created_at)) >= Date.parse(String(snapshot.expires_at)) ||
      (value.exp as number) * 1_000 > Date.parse(String(snapshot.expires_at))
    ) {
      throw new TypeError("Authorization envelope claims are internally inconsistent");
    }

    const replay = value.replay;
    let nonceBytes: Buffer;
    try {
      nonceBytes = Buffer.from(String(replay.nonce), "base64url");
    } catch {
      nonceBytes = Buffer.alloc(0);
    }
    if (
      !hasExactKeys(replay, ["nonce", "use_limit"]) ||
      typeof replay.nonce !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(replay.nonce) ||
      nonceBytes.length !== 32 ||
      nonceBytes.toString("base64url") !== replay.nonce ||
      replay.use_limit !== 1
    ) {
      throw new TypeError("Authorization envelope replay protection is invalid");
    }

    const sourceAudit = value.source_audit;
    const capability = value.capability;
    if (
      !hasExactKeys(sourceAudit, ["event_count", "chain_tip"]) ||
      !Number.isSafeInteger(sourceAudit.event_count) ||
      (sourceAudit.event_count as number) < 1 ||
      !isSha256Hex(sourceAudit.chain_tip) ||
      !hasExactKeys(capability, [
        "kind",
        "payment_dispatch_authorized",
        "execution_authorized",
        "provider_instruction",
        "moves_money",
      ]) ||
      capability.kind !== "EVIDENCE_ONLY" ||
      capability.payment_dispatch_authorized !== false ||
      capability.execution_authorized !== false ||
      capability.provider_instruction !== false ||
      capability.moves_money !== false
    ) {
      throw new TypeError("Authorization envelope audit or capability boundary is invalid");
    }
    return value as unknown as AuthorizationEnvelopeClaims;
  }

  private envelopeViewFromRow(row: SqlRow, idempotentReplay = false): AuthorizationEnvelopeView {
    const compactJws = stringCell(row, "compact_jws");
    const parsed = verifyAuthorizationEnvelopeSignature(
      compactJws,
      this.trustedEnvelopePublicJwk(stringCell(row, "key_id")),
    );
    const claims = this.strictEnvelopeClaims(parsed.payload);
    if (
      !safeEqualText(stringCell(row, "claims_hash"), sha256(canonicalJson(claims))) ||
      !safeEqualText(stringCell(row, "nonce_hash"), sha256(claims.replay.nonce)) ||
      !this.verifyIntegrity(stringCell(row, "intent_id")).valid
    ) {
      throw new ParimitError(
        "INTEGRITY_FAILURE",
        "Stored evidence-envelope integrity verification failed",
        500,
      );
    }
    const consumption: AuthorizationEnvelopeConsumption =
      row.consumed_at === null
        ? { state: "UNCONSUMED" }
        : {
            state: "CONSUMED",
            consumed_at: stringCell(row, "consumed_at"),
            consumed_by: stringCell(row, "consumed_by"),
          };
    return {
      compact_jws: compactJws,
      claims,
      signature: {
        algorithm: "EdDSA",
        key_id: stringCell(row, "key_id"),
        jwks_uri: "/.well-known/jwks.json",
      },
      consumption,
      execution_authorized: false,
      moves_money: false,
      notice: AUTHORIZATION_ENVELOPE_NOTICE,
      ...(idempotentReplay ? { idempotent_replay: true } : {}),
    };
  }

  issueAuthorizationEnvelope(
    id: string,
    value: unknown,
    actorIdValue: unknown,
    actorRoleValue: unknown,
  ): AuthorizationEnvelopeView {
    const input = this.normalizeEnvelopeIssueInput(value);
    const actorId = requireIdentifier(actorIdValue, "actor_id");
    const actorRole = String(actorRoleValue).toLocaleLowerCase("en-US") as ActorRole;
    if (actorRole !== "approver" && actorRole !== "admin") {
      throw new ParimitError(
        "FORBIDDEN",
        "Only a verified approver or admin may issue evidence envelopes",
        403,
      );
    }
    const result = this.transaction(() => {
      const row = this.getRawIntent(id);
      this.assertStoredIntegrity(row);
      if (stringCell(row, "intent_version") !== CURRENT_INTENT_VERSION) {
        throw new ParimitError(
          "ENVELOPE_REQUIRES_V3_INTENT",
          "Evidence envelopes require a tenant-bound v3 proposal",
          409,
        );
      }
      if (stringCell(row, "status") !== "AUTHORIZED_NO_DISPATCH") {
        throw new ParimitError(
          "INVALID_STATE",
          "Evidence envelopes may be issued only after all required human approvals",
          409,
        );
      }
      const stateVersion = numberCell(row, "state_version");
      const existing = this.database
        .prepare(
          `SELECT *
             FROM authorization_envelopes
            WHERE tenant_id = ? AND intent_id = ? AND state_version = ? AND audience = ?`,
        )
        .get(this.tenantId, id, stateVersion, input.audience) as SqlRow | undefined;
      if (existing) {
        if (
          !safeEqualText(
            stringCell(existing, "issuance_idempotency_key"),
            input.idempotency_key,
          )
        ) {
          throw new ParimitError(
            "IDEMPOTENCY_CONFLICT",
            "An envelope already exists for this intent state and audience under a different idempotency key",
            409,
          );
        }
        const existingClaims = this.strictEnvelopeClaims(
          parseAuthorizationEnvelope(stringCell(existing, "compact_jws")).payload,
        );
        if (existingClaims.exp - existingClaims.iat !== input.expires_in_seconds) {
          throw new ParimitError(
            "IDEMPOTENCY_CONFLICT",
            "An envelope already exists for this intent state and audience with a different lifetime",
            409,
          );
        }
        return { row: existing, idempotentReplay: true };
      }

      const clockAt = this.now();
      const issuedAtMilliseconds = Date.parse(clockAt);
      const requestedExpiryMilliseconds =
        issuedAtMilliseconds + input.expires_in_seconds * 1_000;
      const intentExpiryMilliseconds = Date.parse(stringCell(row, "expires_at"));
      if (
        !Number.isFinite(issuedAtMilliseconds) ||
        !Number.isFinite(intentExpiryMilliseconds) ||
        issuedAtMilliseconds >= intentExpiryMilliseconds ||
        requestedExpiryMilliseconds > intentExpiryMilliseconds
      ) {
        throw new ParimitError(
          "ENVELOPE_EXPIRY_EXCEEDS_INTENT",
          "Envelope lifetime must end before the proposal's bound review deadline",
          409,
        );
      }
      const approvals = this.envelopeApprovals(id);
      const requiredApprovals = numberCell(row, "required_approvals") as 1 | 2;
      if (approvals.length !== requiredApprovals) {
        throw new ParimitError(
          "INTEGRITY_FAILURE",
          "Stored approval set does not exactly match the required threshold",
          500,
        );
      }
      if (issuedAtMilliseconds < Date.parse(approvals.at(-1)!.decided_at)) {
        throw new ParimitError(
          "ENVELOPE_INVALID",
          "Evidence envelope cannot be issued before the recorded final approval time",
          409,
        );
      }
      const auditSummary = this.database
        .prepare(
          `SELECT COUNT(*) AS event_count,
                  (SELECT event_hash
                     FROM audit_events
                    WHERE intent_id = ?
                    ORDER BY sequence DESC LIMIT 1) AS chain_tip
             FROM audit_events
            WHERE intent_id = ?`,
        )
        .get(id, id) as SqlRow;
      const intentSnapshot = this.intentPayloadFromRow(row) as AuthorizationEnvelopeClaims["intent"]["snapshot"];
      const policySnapshot = intentSnapshot.policy;
      const envelopeId = randomUUID();
      const nowSeconds = Math.floor(issuedAtMilliseconds / 1_000);
      const issuedAt = clockAt;
      const claims: AuthorizationEnvelopeClaims = {
        version: "parimit-authorization-envelope-v1",
        iss: this.envelopeIssuer,
        sub: `urn:parimit:intent:${id}`,
        aud: input.audience,
        jti: envelopeId,
        iat: nowSeconds,
        nbf: nowSeconds,
        exp: Math.floor(requestedExpiryMilliseconds / 1_000),
        issued_at: issuedAt,
        tenant_id: this.tenantId,
        identity_assurance: {
          authentication_method:
            this.authenticationMode === "oidc" ? "oidc" : "local_demo_headers",
          cryptographically_verified: this.authenticationMode === "oidc",
          trust_domain_id: this.identityTrustDomainId,
        },
        intent: {
          snapshot: intentSnapshot,
          digest: { alg: "sha-256", value: stringCell(row, "intent_hash") },
        },
        policy_digest: { alg: "sha-256", value: sha256(canonicalJson(policySnapshot)) },
        decision: {
          state: "AUTHORIZED_NO_DISPATCH",
          authorization_state_version: stateVersion,
          required_approvals: requiredApprovals,
          fully_approved_at: approvals.at(-1)!.decided_at,
          approval_set_digest: { alg: "sha-256", value: sha256(canonicalJson(approvals)) },
          approvals,
        },
        replay: {
          nonce: randomBytes(32).toString("base64url"),
          use_limit: 1,
        },
        source_audit: {
          event_count: numberCell(auditSummary, "event_count"),
          chain_tip: stringCell(auditSummary, "chain_tip"),
        },
        capability: {
          kind: "EVIDENCE_ONLY",
          payment_dispatch_authorized: false,
          execution_authorized: false,
          provider_instruction: false,
          moves_money: false,
        },
        notice: AUTHORIZATION_ENVELOPE_NOTICE,
      };
      try {
        this.strictEnvelopeClaims(claims as unknown as Record<string, unknown>);
      } catch {
        throw new ParimitError(
          "INTEGRITY_FAILURE",
          "Constructed evidence-envelope claims failed internal validation",
          500,
        );
      }
      const compactJws = signAuthorizationEnvelope(
        claims as unknown as Record<string, unknown>,
        this.envelopeSigningKey,
      );
      const expiresAt = new Date(claims.exp * 1_000).toISOString();
      this.database
        .prepare(
          `INSERT INTO authorization_envelopes
            (id, intent_id, tenant_id, state_version, audience, issuance_idempotency_key,
             key_id, compact_jws, claims_hash, nonce_hash, issued_at, expires_at,
             consumed_at, consumed_by, consumption_idempotency_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)`,
        )
        .run(
          envelopeId,
          id,
          this.tenantId,
          stateVersion,
          input.audience,
          input.idempotency_key,
          this.envelopeSigningKey.keyId,
          compactJws,
          sha256(canonicalJson(claims)),
          sha256(claims.replay.nonce),
          issuedAt,
          expiresAt,
        );
      this.appendAudit(
        id,
        "EVIDENCE_ENVELOPE_ISSUED",
        actorId,
        {
          envelope_id: envelopeId,
          audience: input.audience,
          state_version: stateVersion,
          key_id: this.envelopeSigningKey.keyId,
          claims_hash: sha256(canonicalJson(claims)),
          jws_digest: sha256(compactJws),
          issuance_idempotency_hash: sha256(input.idempotency_key),
          expires_at: expiresAt,
          execution_authorized: false,
          moves_money: false,
        },
        issuedAt,
      );
      return {
        row: this.database
          .prepare("SELECT * FROM authorization_envelopes WHERE id = ?")
          .get(envelopeId) as SqlRow,
        idempotentReplay: false,
      };
    });
    return this.envelopeViewFromRow(result.row, result.idempotentReplay);
  }

  verifyAuthorizationEnvelope(
    compactJws: unknown,
    expectedAudience: unknown,
  ): AuthorizationEnvelopeVerification {
    const failures: string[] = [];
    const result: AuthorizationEnvelopeVerification = {
      valid: false,
      signature_valid: false,
      claims_valid: false,
      time_valid: false,
      locally_issued: false,
      intent_binding_valid: false,
      consumption: null,
      failures,
    };
    if (typeof compactJws !== "string") {
      failures.push("ENVELOPE_NOT_STRING");
      return result;
    }
    let claims: AuthorizationEnvelopeClaims;
    let keyId: string;
    try {
      keyId = parseAuthorizationEnvelope(compactJws).header.kid;
      const parsed = verifyAuthorizationEnvelopeSignature(
        compactJws,
        this.trustedEnvelopePublicJwk(keyId),
      );
      result.signature_valid = true;
      claims = this.strictEnvelopeClaims(parsed.payload);
      result.claims_valid = true;
      result.claims = claims;
    } catch {
      failures.push("SIGNATURE_OR_SCHEMA_INVALID");
      return result;
    }

    const nowSeconds = Math.floor(this.clock().getTime() / 1_000);
    const audienceMatches =
      typeof expectedAudience === "string" &&
      expectedAudience === claims.aud &&
      this.envelopeAudiences.has(expectedAudience);
    result.time_valid =
      claims.iat <= claims.nbf &&
      claims.nbf <= nowSeconds &&
      nowSeconds < claims.exp &&
      claims.exp - claims.iat >= 1 &&
      claims.exp - claims.iat <= this.envelopeTtlSeconds;
    if (!result.time_valid) failures.push("ENVELOPE_TIME_INVALID");
    if (claims.iss !== this.envelopeIssuer) failures.push("ISSUER_MISMATCH");
    if (!audienceMatches) failures.push("AUDIENCE_MISMATCH");
    if (claims.tenant_id !== this.tenantId) failures.push("TENANT_MISMATCH");

    const envelopeRow = this.database
      .prepare("SELECT * FROM authorization_envelopes WHERE id = ? AND tenant_id = ?")
      .get(claims.jti, this.tenantId) as SqlRow | undefined;
    if (envelopeRow) {
      const exactArtifact = safeEqualText(stringCell(envelopeRow, "compact_jws"), compactJws);
      const exactClaims = safeEqualText(
        stringCell(envelopeRow, "claims_hash"),
        sha256(canonicalJson(claims)),
      );
      const exactNonce = safeEqualText(
        stringCell(envelopeRow, "nonce_hash"),
        sha256(claims.replay.nonce),
      );
      result.locally_issued = exactArtifact && exactClaims && exactNonce;
      result.consumption =
        envelopeRow.consumed_at === null
          ? { state: "UNCONSUMED" }
          : {
              state: "CONSUMED",
              consumed_at: stringCell(envelopeRow, "consumed_at"),
              consumed_by: stringCell(envelopeRow, "consumed_by"),
            };
    }
    if (!result.locally_issued) failures.push("LOCAL_ISSUANCE_NOT_PROVEN");

    try {
      const intentRow = this.getRawIntent(claims.intent.snapshot.id);
      const integrity = this.verifyIntegrity(claims.intent.snapshot.id);
      const expectedApprovals = this.envelopeApprovals(claims.intent.snapshot.id);
      const expectedSnapshot = this.intentPayloadFromRow(intentRow);
      const auditRows = this.database
        .prepare("SELECT event_type, payload FROM audit_events WHERE intent_id = ? ORDER BY sequence")
        .all(claims.intent.snapshot.id) as SqlRow[];
      const issueEvents = auditRows.filter((event) => {
        if (stringCell(event, "event_type") !== "EVIDENCE_ENVELOPE_ISSUED") return false;
        try {
          const payload = parseJson<Record<string, unknown>>(stringCell(event, "payload"));
          return (
            payload.envelope_id === claims.jti &&
            payload.claims_hash === sha256(canonicalJson(claims)) &&
            payload.jws_digest === sha256(compactJws)
          );
        } catch {
          return false;
        }
      });
      result.intent_binding_valid =
        integrity.valid &&
        stringCell(intentRow, "intent_version") === CURRENT_INTENT_VERSION &&
        stringCell(intentRow, "status") === "AUTHORIZED_NO_DISPATCH" &&
        stringCell(intentRow, "tenant_id") === claims.tenant_id &&
        claims.identity_assurance.authentication_method ===
          (this.authenticationMode === "oidc" ? "oidc" : "local_demo_headers") &&
        claims.identity_assurance.cryptographically_verified ===
          (this.authenticationMode === "oidc") &&
        claims.identity_assurance.trust_domain_id === this.identityTrustDomainId &&
        stringCell(intentRow, "intent_hash") === claims.intent.digest.value &&
        numberCell(intentRow, "state_version") ===
          claims.decision.authorization_state_version &&
        canonicalJson(expectedSnapshot) === canonicalJson(claims.intent.snapshot) &&
        sha256(canonicalJson(expectedSnapshot)) === claims.intent.digest.value &&
        sha256(canonicalJson(claims.intent.snapshot.policy)) === claims.policy_digest.value &&
        canonicalJson(expectedApprovals) === canonicalJson(claims.decision.approvals) &&
        sha256(canonicalJson(expectedApprovals)) ===
          claims.decision.approval_set_digest.value &&
        claims.sub === `urn:parimit:intent:${claims.intent.snapshot.id}` &&
        issueEvents.length === 1;
    } catch {
      result.intent_binding_valid = false;
    }
    if (!result.intent_binding_valid) failures.push("INTENT_BINDING_INVALID");
    result.valid =
      result.signature_valid &&
      result.claims_valid &&
      result.time_valid &&
      result.locally_issued &&
      result.intent_binding_valid &&
      failures.length === 0;
    return result;
  }

  consumeAuthorizationEnvelope(
    compactJws: unknown,
    expectedAudience: unknown,
    actorIdValue: unknown,
    actorRoleValue: unknown,
    idempotencyKeyValue: unknown,
  ): AuthorizationEnvelopeView {
    const actorId = requireIdentifier(actorIdValue, "actor_id");
    const actorRole = String(actorRoleValue).toLocaleLowerCase("en-US") as ActorRole;
    if (actorRole !== "consumer" && actorRole !== "admin") {
      throw new ParimitError(
        "FORBIDDEN",
        "Only a verified consumer or admin may claim an evidence envelope",
        403,
      );
    }
    const audience = requireString(expectedAudience, "audience", 512);
    const idempotencyKey = requireIdentifier(idempotencyKeyValue, "idempotency_key");
    const verification = this.verifyAuthorizationEnvelope(compactJws, audience);
    const expiredButOtherwiseValid =
      verification.claims !== undefined &&
      verification.signature_valid &&
      verification.claims_valid &&
      verification.locally_issued &&
      verification.intent_binding_valid &&
      !verification.time_valid &&
      verification.failures.length === 1 &&
      verification.failures[0] === "ENVELOPE_TIME_INVALID" &&
      Math.floor(this.clock().getTime() / 1_000) >= verification.claims.exp;
    if (
      (!verification.valid && !expiredButOtherwiseValid) ||
      !verification.claims ||
      typeof compactJws !== "string"
    ) {
      throw new ParimitError(
        "ENVELOPE_INVALID",
        "Evidence envelope failed signature, time, audience, or intent-binding verification",
        409,
        verification,
      );
    }
    const envelopeId = verification.claims.jti;
    const result = this.transaction(() => {
      const row = requiredRow(
        this.database
          .prepare("SELECT * FROM authorization_envelopes WHERE id = ? AND tenant_id = ?")
          .get(envelopeId, this.tenantId) as SqlRow | undefined,
        "Evidence envelope not found",
      );
      if (row.consumed_at !== null) {
        if (
          safeEqualText(stringCell(row, "consumed_by"), actorId) &&
          safeEqualText(stringCell(row, "consumption_idempotency_key"), idempotencyKey)
        ) {
          return { row, idempotentReplay: true };
        }
        throw new ParimitError(
          "ENVELOPE_REPLAY_DETECTED",
          "Evidence envelope has already been consumed",
          409,
        );
      }
      if (expiredButOtherwiseValid) {
        throw new ParimitError("ENVELOPE_EXPIRED", "Evidence envelope has expired", 409);
      }
      const consumedAt = this.now();
      if (consumedAt < stringCell(row, "issued_at")) {
        throw new ParimitError(
          "ENVELOPE_INVALID",
          "Evidence envelope cannot be consumed before its recorded issuance time",
          409,
        );
      }
      if (consumedAt >= stringCell(row, "expires_at")) {
        throw new ParimitError("ENVELOPE_EXPIRED", "Evidence envelope has expired", 409);
      }
      const update = this.database
        .prepare(
          `UPDATE authorization_envelopes
              SET consumed_at = ?, consumed_by = ?, consumption_idempotency_key = ?
            WHERE id = ? AND tenant_id = ? AND consumed_at IS NULL`,
        )
        .run(consumedAt, actorId, idempotencyKey, envelopeId, this.tenantId);
      if (Number(update.changes) !== 1) {
        throw new ParimitError(
          "ENVELOPE_REPLAY_DETECTED",
          "Evidence envelope was consumed concurrently",
          409,
        );
      }
      this.appendAudit(
        stringCell(row, "intent_id"),
        "EVIDENCE_ENVELOPE_CONSUMED",
        actorId,
        {
          envelope_id: envelopeId,
          audience,
          consumer_id: actorId,
          consumption_idempotency_hash: sha256(idempotencyKey),
          state_version: numberCell(row, "state_version"),
          execution_authorized: false,
          moves_money: false,
        },
        consumedAt,
      );
      return {
        row: this.database
          .prepare("SELECT * FROM authorization_envelopes WHERE id = ?")
          .get(envelopeId) as SqlRow,
        idempotentReplay: false,
      };
    });
    return this.envelopeViewFromRow(result.row, result.idempotentReplay);
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
    const status = statusValue as ObservationStatus;
    this.transaction(() => {
      const row = this.getRawIntent(id);
      this.assertStoredIntegrity(row);
      if (stringCell(row, "status") !== "AUTHORIZED_NO_DISPATCH") {
        throw new ParimitError(
          "INVALID_STATE",
          "Mock observations may be attached only after all required human approvals",
          409,
        );
      }
      const latestObservation = this.latestObservation(id);
      if (latestObservation?.status === "IN_DOUBT") {
        throw new ParimitError(
          "IN_DOUBT_FROZEN",
          "No later mock observation is allowed after IN_DOUBT; this alpha has no authorized reconciliation mechanism",
          409,
        );
      }
      const observedAt = this.now();
      const observationId = randomUUID();
      this.database
        .prepare(
          `INSERT INTO observations (id, intent_id, status, provider_reference, observed_at, source)
           VALUES (?, ?, ?, ?, ?, 'DEMO_MOCK')`,
        )
        .run(observationId, id, status, providerReference, observedAt);
      this.appendAudit(
        id,
        "DEMO_MOCK_OBSERVATION_RECORDED",
        actorId,
        {
          observation_id: observationId,
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
    const report = this.verifyIntegrity(id);
    if (!report.valid) {
      throw new ParimitError(
        "INTEGRITY_FAILURE",
        "Stored proposal integrity verification failed",
        500,
        report,
      );
    }
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
        "Legacy v1 intents are archival and cannot be reviewed, cancelled, or observed; create a new v3 proposal",
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
    if (
      version !== LEGACY_INTENT_VERSION &&
      version !== POLICY_BOUND_INTENT_VERSION &&
      version !== CURRENT_INTENT_VERSION
    ) {
      addStateFailure("INTENT_VERSION_UNSUPPORTED");
    }
    if (stringCell(row, "tenant_id") !== this.tenantId) {
      addStateFailure("TENANT_CONTEXT_MISMATCH");
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
    let previousOccurredAt: string | null = null;
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
      if (
        !isCanonicalTimestamp(event.occurred_at) ||
        event.occurred_at < stringCell(row, "created_at") ||
        (previousOccurredAt !== null && event.occurred_at < previousOccurredAt)
      ) {
        auditChainValid = false;
        addFailure(`AUDIT_CHRONOLOGY_INVALID:${event.sequence}`);
      }
      previousHash = event.event_hash;
      previousOccurredAt = event.occurred_at;
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
      initialEvent.occurred_at !== stringCell(row, "created_at") ||
      !initialPolicy ||
      initialPolicy.allowed !== policyAllowed ||
      initialPolicy.rules_version !== rulesVersion ||
      initialPolicy.required_approvals !== requiredApprovals ||
      !policyReasons ||
      canonicalJson(initialPolicy.reasons) !== canonicalJson(policyReasons) ||
      (version === CURRENT_INTENT_VERSION &&
        initialPolicy.config_digest !== this.policyConfigurationDigest)
    ) {
      addStateFailure("INITIAL_AUDIT_POLICY_MISMATCH");
    }
    if (
      version === CURRENT_INTENT_VERSION &&
      (initialPayload?.tenant_id !== this.tenantId || initialPayload.state_version !== 1)
    ) {
      addStateFailure("INITIAL_AUDIT_TENANT_STATE_MISMATCH");
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
          event.event_type ===
            (approval.decision === "APPROVE"
              ? "HUMAN_APPROVAL_RECORDED"
              : "HUMAN_REJECTION_RECORDED") &&
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

    const observationRows = this.database
      .prepare(
        `SELECT rowid AS storage_order, id, status, provider_reference, observed_at, source
           FROM observations
          WHERE intent_id = ?
          ORDER BY rowid`,
      )
      .all(id) as SqlRow[];
    const observationEvents = auditEvents.filter(
      (event) => event.event_type === "DEMO_MOCK_OBSERVATION_RECORDED",
    );
    if (observationRows.length !== observationEvents.length) {
      addStateFailure("OBSERVATION_AUDIT_COUNT_MISMATCH");
    }
    let observationStreamFrozen = false;
    for (const [index, observationRow] of observationRows.entries()) {
      const observationId = stringCell(observationRow, "id");
      const observationStatus = stringCell(observationRow, "status");
      const providerReference =
        observationRow.provider_reference === null
          ? null
          : stringCell(observationRow, "provider_reference");
      const observedAt = stringCell(observationRow, "observed_at");
      const source = stringCell(observationRow, "source");
      const event = observationEvents[index];

      if (observationStreamFrozen) {
        addStateFailure(`OBSERVATION_AFTER_IN_DOUBT:${observationId || index + 1}`);
      }
      if (observationStatus === "IN_DOUBT") observationStreamFrozen = true;

      if (
        observationId.length === 0 ||
        !OBSERVATION_STATUSES.includes(observationStatus as ObservationStatus) ||
        source !== "DEMO_MOCK" ||
        !Number.isFinite(Date.parse(observedAt)) ||
        Date.parse(observedAt) < proposalCreatedAt ||
        (providerReference !== null &&
          (providerReference.length === 0 || providerReference.length > 200))
      ) {
        addStateFailure(`OBSERVATION_SEMANTICS_INVALID:${observationId || index + 1}`);
      }

      const payload = event && isRecord(event.payload) ? event.payload : null;
      const expectedPayloadWithoutId = {
        status: observationStatus,
        provider_reference: providerReference,
        source,
        retry_permitted: false,
        moves_money: false,
      };
      // Before observation IDs were audit-bound, alpha events contained the
      // same evidence fields but no observation_id. Keep those rows readable;
      // all newly recorded observations bind their stable row identity too.
      const expectedPayload =
        payload && Object.hasOwn(payload, "observation_id")
          ? { observation_id: observationId, ...expectedPayloadWithoutId }
          : expectedPayloadWithoutId;
      if (
        !event ||
        event.occurred_at !== observedAt ||
        !payload ||
        canonicalJson(payload) !== canonicalJson(expectedPayload)
      ) {
        addStateFailure(`OBSERVATION_AUDIT_MISMATCH:${observationId || index + 1}`);
      }
    }

    const envelopeRows = this.database
      .prepare("SELECT * FROM authorization_envelopes WHERE intent_id = ? ORDER BY issued_at, id")
      .all(id) as SqlRow[];
    const envelopeIssueEvents = auditEvents.filter(
      (event) => event.event_type === "EVIDENCE_ENVELOPE_ISSUED",
    );
    const envelopeConsumeEvents = auditEvents.filter(
      (event) => event.event_type === "EVIDENCE_ENVELOPE_CONSUMED",
    );
    if (envelopeIssueEvents.length !== envelopeRows.length) {
      addStateFailure("ENVELOPE_AUDIT_COUNT_MISMATCH");
    }
    let consumedEnvelopeCount = 0;
    for (const envelopeRow of envelopeRows) {
      const envelopeId = stringCell(envelopeRow, "id");
      try {
        const compactJws = stringCell(envelopeRow, "compact_jws");
        const keyId = stringCell(envelopeRow, "key_id");
        const parsed = verifyAuthorizationEnvelopeSignature(
          compactJws,
          this.trustedEnvelopePublicJwk(keyId),
        );
        const claims = this.strictEnvelopeClaims(parsed.payload);
        const issueMatches = envelopeIssueEvents.filter((event) => {
          const payload = isRecord(event.payload) ? event.payload : null;
          if (!payload) return false;
          const priorEventCount = auditEvents.findIndex(
            (candidate) => candidate.sequence === event.sequence,
          );
          return (
            payload.envelope_id === envelopeId &&
            payload.audience === stringCell(envelopeRow, "audience") &&
            payload.state_version === numberCell(envelopeRow, "state_version") &&
            payload.key_id === keyId &&
            payload.claims_hash === stringCell(envelopeRow, "claims_hash") &&
            payload.jws_digest === sha256(compactJws) &&
            payload.issuance_idempotency_hash ===
              sha256(stringCell(envelopeRow, "issuance_idempotency_key")) &&
            payload.expires_at === stringCell(envelopeRow, "expires_at") &&
            payload.execution_authorized === false &&
            payload.moves_money === false &&
            priorEventCount === claims.source_audit.event_count &&
            event.previous_hash === claims.source_audit.chain_tip &&
            event.occurred_at === stringCell(envelopeRow, "issued_at")
          );
        });
        const consumed = envelopeRow.consumed_at !== null;
        if (consumed) consumedEnvelopeCount += 1;
        const consumptionTimeValid = consumed
          ? isCanonicalTimestamp(envelopeRow.consumed_at) &&
            String(envelopeRow.consumed_at) >= stringCell(envelopeRow, "issued_at") &&
            String(envelopeRow.consumed_at) < stringCell(envelopeRow, "expires_at")
          : true;
        const consumeMatches = envelopeConsumeEvents.filter((event) => {
          const payload = isRecord(event.payload) ? event.payload : null;
          return (
            payload?.envelope_id === envelopeId &&
            payload.audience === stringCell(envelopeRow, "audience") &&
            payload.consumer_id === envelopeRow.consumed_by &&
            payload.consumption_idempotency_hash ===
              sha256(stringCell(envelopeRow, "consumption_idempotency_key")) &&
            event.actor_id === envelopeRow.consumed_by &&
            event.occurred_at === envelopeRow.consumed_at &&
            payload.state_version === numberCell(envelopeRow, "state_version") &&
            payload.execution_authorized === false &&
            payload.moves_money === false
          );
        });
        const envelopeValid =
          claims.jti === envelopeId &&
          claims.intent.snapshot.id === id &&
          claims.tenant_id === stringCell(envelopeRow, "tenant_id") &&
          claims.aud === stringCell(envelopeRow, "audience") &&
          claims.decision.authorization_state_version ===
            numberCell(envelopeRow, "state_version") &&
          parsed.header.kid === keyId &&
          safeEqualText(
            stringCell(envelopeRow, "claims_hash"),
            sha256(canonicalJson(claims)),
          ) &&
          safeEqualText(
            stringCell(envelopeRow, "nonce_hash"),
            sha256(claims.replay.nonce),
          ) &&
          claims.issued_at === stringCell(envelopeRow, "issued_at") &&
          Math.floor(Date.parse(stringCell(envelopeRow, "issued_at")) / 1_000) === claims.iat &&
          new Date(claims.exp * 1_000).toISOString() === stringCell(envelopeRow, "expires_at") &&
          consumptionTimeValid &&
          issueMatches.length === 1 &&
          (consumed ? consumeMatches.length === 1 : consumeMatches.length === 0) &&
          (consumed
            ? typeof envelopeRow.consumed_by === "string" &&
              typeof envelopeRow.consumption_idempotency_key === "string"
            : envelopeRow.consumed_by === null &&
              envelopeRow.consumption_idempotency_key === null);
        if (!envelopeValid) addStateFailure(`ENVELOPE_INTEGRITY_INVALID:${envelopeId}`);
      } catch {
        addStateFailure(`ENVELOPE_INTEGRITY_INVALID:${envelopeId}`);
      }
    }
    if (envelopeConsumeEvents.length !== consumedEnvelopeCount) {
      addStateFailure("ENVELOPE_CONSUMPTION_AUDIT_COUNT_MISMATCH");
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

    const terminalStateEvents = auditEvents.filter(
      (event) => event.event_type === "PROPOSAL_CANCELLED" || event.event_type === "PROPOSAL_EXPIRED",
    );
    if (terminalStateEvents.length > 1) addStateFailure("MULTIPLE_TERMINAL_STATE_EVENTS");
    const stateVersion = numberCell(row, "state_version");
    const expectedStateVersion = 1 + reviewEvents.length + terminalStateEvents.length;
    if (!Number.isSafeInteger(stateVersion) || stateVersion !== expectedStateVersion) {
      addStateFailure("AUTHORIZATION_STATE_VERSION_MISMATCH");
    }

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
      if (
        !policyAllowed ||
        validRejectCount !== 1 ||
        validApproveCount >= requiredApprovals
      ) {
        addStateFailure("REJECTED_STATE_MISMATCH");
      }
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

    if (observationRows.length > 0 && status !== "AUTHORIZED_NO_DISPATCH") {
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
      version: "0.1.0-alpha.3",
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
      human_only_capabilities: [
        "approve_exact_proposal",
        "reject_exact_proposal",
        "issue_evidence_envelope",
      ],
      consumer_capabilities: [
        "verify_evidence_envelope",
        "consume_evidence_envelope_once",
      ],
      evidence_envelopes: {
        version: "parimit-authorization-envelope-v1",
        algorithm: "EdDSA",
        key_id: this.envelopeSigningKey.keyId,
        ephemeral_demo_key: this.envelopeSigningKey.ephemeral,
        issuer: this.envelopeIssuer,
        tenant_id: this.tenantId,
        audiences: [...this.envelopeAudiences],
        identity_trust_domain_id: this.identityTrustDomainId,
        maximum_lifetime_seconds: this.envelopeTtlSeconds,
        execution_authorized: false,
        moves_money: false,
        replay_scope:
          "Atomic only within this SQLite service instance; offline recipients need their own durable replay ledger.",
      },
      receipt_integrity_root: {
        rotation_supported: false,
        recovery_rule:
          "The database, receipt key, tenant, issuer, audience, authentication mode, identity trust domain, policy configuration, envelope lifetime policy, and envelope key history must be restored as one matching set.",
      },
      mock_observations: [...OBSERVATION_STATUSES],
      mock_observation_retry_permitted: false,
      currency: "INR",
      amount_unit: "minor (paise), represented as a decimal string",
      identity: {
        mode: this.authenticationMode,
        cryptographically_verified: this.authenticationMode === "oidc",
        trust_domain_id: this.identityTrustDomainId,
      },
      ...(this.authenticationMode === "demo_headers"
        ? {
            demo_auth_warning:
              "x-parimit-actor and x-parimit-role are spoofable local-demo headers and are restricted to loopback.",
          }
        : {}),
      rules: {
        version: this.policy.rulesVersion,
        config_digest: this.policyConfigurationDigest,
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

function decodeEnvelopePrivateKey(value: string | undefined): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      "PARIMIT_ENVELOPE_PRIVATE_KEY_PEM_BASE64 must be canonical base64",
      500,
    );
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value || decoded.length === 0) {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      "PARIMIT_ENVELOPE_PRIVATE_KEY_PEM_BASE64 must be canonical base64",
      500,
    );
  }
  return decoded.toString("utf8");
}

export function createServiceFromEnvironment(
  environment: Record<string, string | undefined> = process.env,
  validatedIdentityProvider?: {
    readonly authenticationMethod: "oidc" | "local_demo_headers";
    readonly identityTrustDomainId: string;
  },
): ParimitService {
  const demoModeValue = (environment.PARIMIT_DEMO_MODE ?? "true").toLocaleLowerCase("en-US");
  const authenticationMode = environment.PARIMIT_AUTH_MODE ?? "demo_headers";
  const demoMode = demoModeValue === "true" || demoModeValue === "1";
  if (!demoMode && authenticationMode !== "oidc") {
    throw new ParimitError(
      "DEMO_ONLY_BUILD",
      "Non-demo startup requires PARIMIT_AUTH_MODE=oidc",
      500,
    );
  }
  if (authenticationMode !== "demo_headers" && authenticationMode !== "oidc") {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      "PARIMIT_AUTH_MODE must be 'demo_headers' or 'oidc'",
      500,
    );
  }
  const allowed = parseEnvironmentSet(environment.PARIMIT_ALLOWED_PAYEES);
  const envelopePrivateKeyPem = decodeEnvelopePrivateKey(
    environment.PARIMIT_ENVELOPE_PRIVATE_KEY_PEM_BASE64,
  );
  const envelopeAudiences = parseEnvironmentSet(environment.PARIMIT_ENVELOPE_AUDIENCES);
  const receiptSecret =
    environmentValue(environment, "PARIMIT_RECEIPT_KEY", "PARIMIT_RECEIPT_SECRET") ??
    "development-only-change-me";
  if (
    authenticationMode === "oidc" &&
    (receiptSecret === "development-only-change-me" ||
      Buffer.byteLength(receiptSecret, "utf8") < 32)
  ) {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      "OIDC mode requires PARIMIT_RECEIPT_KEY with at least 32 UTF-8 bytes",
      500,
    );
  }
  if (
    !demoMode &&
    (envelopePrivateKeyPem === undefined ||
      !environment.PARIMIT_TENANT_ID ||
      !environment.PARIMIT_ENVELOPE_ISSUER ||
      envelopeAudiences === undefined)
  ) {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      "Non-demo mode requires a stable envelope key, tenant id, issuer, and exactly one audience",
      500,
    );
  }
  let identityTrustDomainId: string;
  try {
    const expectedAuthenticationMethod =
      authenticationMode === "oidc" ? "oidc" : "local_demo_headers";
    if (authenticationMode === "oidc" && validatedIdentityProvider === undefined) {
      throw new TypeError("OIDC service startup requires a validated identity-provider trust context");
    }
    if (
      validatedIdentityProvider !== undefined &&
      validatedIdentityProvider.authenticationMethod !== expectedAuthenticationMethod
    ) {
      throw new TypeError("identity provider authentication mode does not match PARIMIT_AUTH_MODE");
    }
    identityTrustDomainId =
      validatedIdentityProvider?.identityTrustDomainId ?? LOCAL_DEMO_IDENTITY_TRUST_DOMAIN;
  } catch (error) {
    throw new ParimitError(
      "INVALID_CONFIGURATION",
      error instanceof Error
        ? `Invalid OIDC identity trust configuration: ${error.message}`
        : "Invalid OIDC identity trust configuration",
      500,
    );
  }
  return new ParimitService({
    databasePath: environment.PARIMIT_DB_PATH ?? "./data/parimit.db",
    receiptSecret,
    authenticationMode,
    identityTrustDomainId,
    tenantId: environment.PARIMIT_TENANT_ID ?? DEFAULT_TENANT_ID,
    envelopeIssuer: environment.PARIMIT_ENVELOPE_ISSUER ?? DEFAULT_ENVELOPE_ISSUER,
    envelopeSigningPrivateKeyPem: envelopePrivateKeyPem,
    envelopeSigningKeyId: environment.PARIMIT_ENVELOPE_SIGNING_KEY_ID || undefined,
    envelopeTtlSeconds: parsePositiveEnvironmentInteger(
      environment.PARIMIT_ENVELOPE_TTL_SECONDS,
      DEFAULT_ENVELOPE_TTL_SECONDS,
    ),
    envelopeAudiences: envelopeAudiences ?? ["urn:parimit:consumer:local-demo"],
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
