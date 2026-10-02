import type { InitialIntentStatus, IntentStatus, PaymentIntentVersion } from "../types.ts";

/**
 * Driver-neutral storage values for the first asynchronous repository slice.
 * PostgreSQL BIGINT identifiers stay decimal strings until the public API has
 * an explicit bigint migration.
 */
export interface StoredIntentRecord {
  id: string;
  tenantId: string;
  idempotencyKey: string;
  requestFingerprint: string;
  agentId: string;
  onBehalfOf: string | null;
  amountMinor: number;
  currency: "INR";
  payeeReference: string;
  purpose: string;
  status: IntentStatus;
  requiredApprovals: 1 | 2;
  policyAllowed: boolean;
  policyReasons: readonly string[];
  rulesVersion: string;
  intentVersion: PaymentIntentVersion;
  initialStatus: InitialIntentStatus;
  stateVersion: string;
  intentHash: string;
  createdAt: string;
  expiresAt: string;
}

export interface PreparedAuditEvent {
  eventType: "PROPOSAL_CREATED" | "PROPOSAL_POLICY_DENIED";
  actorId: string;
  payload: Readonly<Record<string, unknown>>;
  occurredAt: string;
}

export interface ProposalPreparationContext {
  /** Exposure after the per-agent transaction lock has been acquired. */
  currentDailyExposureMinor: number;
}

export interface PreparedProposal {
  intent: StoredIntentRecord;
  audit: PreparedAuditEvent;
}

export interface CreateProposalRequest {
  tenantId: string;
  agentId: string;
  idempotencyKey: string;
  requestFingerprint: string;
  /** Digest of the exact policy configuration used by the domain decision. */
  policyConfigurationDigest: string;
  /** Canonical UTC start of the policy day used by the domain decision. */
  policyDayStartsAt: string;
  /**
   * Pure preparation callback. A serializable retry may invoke it again with a
   * fresh snapshot, so it must not perform I/O or any non-database side effect.
   */
  prepare(
    context: ProposalPreparationContext,
  ): PreparedProposal | Promise<PreparedProposal>;
}

export interface CreateProposalResult {
  intent: StoredIntentRecord;
  idempotentReplay: boolean;
  /** Null on replay because no new event was appended. */
  auditSequence: string | null;
}

/**
 * Narrow first slice of the future repository. The production service remains
 * on SQLite until every operation and integrity check has behavioral parity.
 */
export interface ProposalRepository {
  createOrReplay(request: CreateProposalRequest): Promise<CreateProposalResult>;
  readIntent(tenantId: string, intentId: string): Promise<StoredIntentRecord | null>;
}
