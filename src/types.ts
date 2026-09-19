export const INTENT_STATUSES = [
  "POLICY_DENIED",
  "AWAITING_APPROVAL",
  "AUTHORIZED_NO_DISPATCH",
  "REJECTED",
  "CANCELLED",
  "EXPIRED",
] as const;

export type IntentStatus = (typeof INTENT_STATUSES)[number];

export const OBSERVATION_STATUSES = [
  "UNKNOWN",
  "PENDING",
  "SUCCEEDED",
  "FAILED",
  "REVERSED",
  "DISPUTED",
  "IN_DOUBT",
] as const;

export type ObservationStatus = (typeof OBSERVATION_STATUSES)[number];

export type ApprovalDecision = "APPROVE" | "REJECT";
export type ActorRole = "agent" | "approver" | "admin";

export const PAYMENT_INTENT_VERSIONS = [
  "parimit-payment-intent-v1",
  "parimit-payment-intent-v2",
] as const;

export type PaymentIntentVersion = (typeof PAYMENT_INTENT_VERSIONS)[number];
export type InitialIntentStatus = "POLICY_DENIED" | "AWAITING_APPROVAL";

export interface PaymentProposalInput {
  idempotency_key: string;
  requested_by: {
    type: "agent";
    id: string;
  };
  on_behalf_of?: string;
  amount: {
    currency: "INR";
    minor: string;
  };
  payee_reference: string;
  purpose: string;
  expires_in_seconds?: number;
}

export interface NormalizedPaymentProposal {
  idempotencyKey: string;
  agentId: string;
  onBehalfOf: string | null;
  amountMinor: number;
  currency: "INR";
  payeeReference: string;
  purpose: string;
  expiresInSeconds: number;
}

export interface PolicyDecision {
  allowed: boolean;
  reasons: string[];
  rules_version: string;
  required_approvals: 1 | 2;
  current_daily_exposure_minor: string;
  projected_daily_exposure_minor: string;
}

export interface ApprovalView {
  actor_id: string;
  actor_role: "approver" | "admin";
  decision: ApprovalDecision;
  intent_hash: string;
  created_at: string;
  receipt_hmac: string;
}

export interface ApprovalReceiptView {
  version: "parimit-approval-receipt-v1";
  intent_id: string;
  intent_hash: string;
  fully_approved_at: string;
  approvals: ApprovalView[];
  execution_authorized: false;
  notice: string;
}

export interface ObservationView {
  status: ObservationStatus;
  provider_reference?: string;
  observed_at: string;
  source: "DEMO_MOCK";
  retry_permitted: false;
}

export interface IntentView {
  id: string;
  intent_version: PaymentIntentVersion;
  initial_status: InitialIntentStatus;
  idempotency_key: string;
  requested_by: {
    type: "agent";
    id: string;
  };
  on_behalf_of?: string;
  amount: {
    currency: "INR";
    minor: string;
  };
  payee_reference: string;
  purpose: string;
  status: IntentStatus;
  required_approvals: 1 | 2;
  approval_count: number;
  policy: {
    allowed: boolean;
    reasons: string[];
    rules_version: string;
  };
  intent_hash: string;
  created_at: string;
  expires_at: string;
  observation?: ObservationView;
  approvals: ApprovalView[];
  receipt?: ApprovalReceiptView;
  idempotent_replay?: boolean;
}

export interface AuditEventView {
  sequence: number;
  intent_id: string;
  event_type: string;
  actor_id: string;
  payload: unknown;
  occurred_at: string;
  previous_hash: string;
  event_hash: string;
}

export interface IntegrityReport {
  valid: boolean;
  intent_hash_valid: boolean;
  approval_receipts_valid: boolean;
  audit_chain_valid: boolean;
  state_consistency_valid: boolean;
  failures: string[];
}

export interface PolicyConfig {
  rulesVersion: string;
  perTransactionLimitMinor: number;
  dailyAgentLimitMinor: number;
  dualApprovalThresholdMinor: number;
  defaultExpirySeconds: number;
  maxExpirySeconds: number;
  blockedPayees: ReadonlySet<string>;
  allowedPayees: ReadonlySet<string> | null;
}

export interface ParimitServiceOptions {
  databasePath?: string;
  receiptSecret?: string;
  clock?: () => Date;
  policy?: Partial<Omit<PolicyConfig, "blockedPayees" | "allowedPayees">> & {
    blockedPayees?: Iterable<string>;
    allowedPayees?: Iterable<string> | null;
  };
}
