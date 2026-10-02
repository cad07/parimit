import type {
  InitialIntentStatus,
  NormalizedPaymentProposal,
  PaymentIntentVersion,
  PolicyDecision,
} from "./types.ts";

export const CURRENT_PAYMENT_INTENT_VERSION: PaymentIntentVersion =
  "parimit-payment-intent-v3";

/**
 * One canonical constructor shared by SQLite and future storage adapters.
 * The returned shape is hashed byte-for-byte through canonicalJson.
 */
export function currentPaymentIntentPayload(input: {
  id: string;
  tenantId: string;
  proposal: NormalizedPaymentProposal;
  createdAt: string;
  expiresAt: string;
  policy: PolicyDecision;
  initialStatus: InitialIntentStatus;
}): Record<string, unknown> {
  return {
    version: CURRENT_PAYMENT_INTENT_VERSION,
    id: input.id,
    tenant_id: input.tenantId,
    idempotency_key: input.proposal.idempotencyKey,
    requested_by: { type: "agent", id: input.proposal.agentId },
    on_behalf_of: input.proposal.onBehalfOf,
    amount: { currency: input.proposal.currency, minor: String(input.proposal.amountMinor) },
    payee_reference: input.proposal.payeeReference,
    purpose: input.proposal.purpose,
    initial_status: input.initialStatus,
    policy: {
      allowed: input.policy.allowed,
      reasons: input.policy.reasons,
      rules_version: input.policy.rules_version,
      config_digest: input.policy.config_digest,
      required_approvals: input.policy.required_approvals,
    },
    created_at: input.createdAt,
    expires_at: input.expiresAt,
  };
}
