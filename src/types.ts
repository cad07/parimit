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
export type ActorRole = "agent" | "approver" | "consumer" | "admin";

export const PAYMENT_INTENT_VERSIONS = [
  "parimit-payment-intent-v1",
  "parimit-payment-intent-v2",
  "parimit-payment-intent-v3",
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
  config_digest: string;
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
  tenant_id: string;
  state_version: number;
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
    config_digest?: string;
  };
  intent_hash: string;
  created_at: string;
  expires_at: string;
  observation?: ObservationView;
  approvals: ApprovalView[];
  receipt?: ApprovalReceiptView;
  idempotent_replay?: boolean;
}

export interface AuthorizationEnvelopeApproval {
  subject: string;
  role: "approver" | "admin";
  decision: "APPROVE";
  intent_hash: string;
  decided_at: string;
  record_digest: string;
}

export interface AuthorizationEnvelopeClaims {
  version: "parimit-authorization-envelope-v1";
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  issued_at: string;
  tenant_id: string;
  identity_assurance: {
    authentication_method: "oidc" | "local_demo_headers";
    cryptographically_verified: boolean;
    trust_domain_id: string;
  };
  intent: {
    snapshot: {
      version: "parimit-payment-intent-v3";
      id: string;
      tenant_id: string;
      idempotency_key: string;
      requested_by: { type: "agent"; id: string };
      on_behalf_of: string | null;
      amount: { currency: "INR"; minor: string };
      payee_reference: string;
      purpose: string;
      initial_status: "AWAITING_APPROVAL";
      policy: {
        allowed: true;
        reasons: string[];
        rules_version: string;
        config_digest: string;
        required_approvals: 1 | 2;
      };
      created_at: string;
      expires_at: string;
    };
    digest: { alg: "sha-256"; value: string };
  };
  policy_digest: { alg: "sha-256"; value: string };
  decision: {
    state: "AUTHORIZED_NO_DISPATCH";
    authorization_state_version: number;
    required_approvals: 1 | 2;
    fully_approved_at: string;
    approval_set_digest: { alg: "sha-256"; value: string };
    approvals: AuthorizationEnvelopeApproval[];
  };
  replay: {
    nonce: string;
    use_limit: 1;
  };
  source_audit: {
    event_count: number;
    chain_tip: string;
  };
  capability: {
    kind: "EVIDENCE_ONLY";
    payment_dispatch_authorized: false;
    execution_authorized: false;
    provider_instruction: false;
    moves_money: false;
  };
  notice: string;
}

export interface AuthorizationEnvelopeIssueInput {
  audience: string;
  idempotency_key: string;
  expires_in_seconds?: number;
}

export interface AuthorizationEnvelopeConsumption {
  state: "UNCONSUMED" | "CONSUMED";
  consumed_at?: string;
  consumed_by?: string;
}

export interface AuthorizationEnvelopeView {
  compact_jws: string;
  claims: AuthorizationEnvelopeClaims;
  signature: {
    algorithm: "EdDSA";
    key_id: string;
    jwks_uri: "/.well-known/jwks.json";
  };
  consumption: AuthorizationEnvelopeConsumption;
  execution_authorized: false;
  moves_money: false;
  notice: string;
  idempotent_replay?: boolean;
}

export interface AuthorizationEnvelopeVerification {
  valid: boolean;
  signature_valid: boolean;
  claims_valid: boolean;
  time_valid: boolean;
  locally_issued: boolean;
  intent_binding_valid: boolean;
  consumption: AuthorizationEnvelopeConsumption | null;
  failures: string[];
  claims?: AuthorizationEnvelopeClaims;
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
  readonly rulesVersion: string;
  readonly perTransactionLimitMinor: number;
  readonly dailyAgentLimitMinor: number;
  readonly dualApprovalThresholdMinor: number;
  readonly defaultExpirySeconds: number;
  readonly maxExpirySeconds: number;
  readonly blockedPayees: ReadonlySet<string>;
  readonly allowedPayees: ReadonlySet<string> | null;
}

export interface ParimitServiceOptions {
  databasePath?: string;
  receiptSecret?: string;
  authenticationMode?: "demo_headers" | "oidc";
  identityTrustDomainId?: string;
  tenantId?: string;
  envelopeIssuer?: string;
  envelopeSigningPrivateKeyPem?: string;
  envelopeSigningKeyId?: string;
  envelopeTtlSeconds?: number;
  envelopeAudiences?: Iterable<string>;
  clock?: () => Date;
  policy?: Partial<Omit<PolicyConfig, "blockedPayees" | "allowedPayees">> & {
    blockedPayees?: Iterable<string>;
    allowedPayees?: Iterable<string> | null;
  };
}
