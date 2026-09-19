export type ActorRole = "agent" | "approver" | "admin";
export type ApprovalDecision = "APPROVE" | "REJECT";
export type IntentStatus =
  | "POLICY_DENIED"
  | "AWAITING_APPROVAL"
  | "AUTHORIZED_NO_DISPATCH"
  | "REJECTED"
  | "CANCELLED"
  | "EXPIRED";
export type ObservationStatus =
  | "UNKNOWN"
  | "PENDING"
  | "SUCCEEDED"
  | "FAILED"
  | "REVERSED"
  | "DISPUTED"
  | "IN_DOUBT";

export interface PaymentProposal {
  idempotency_key: string;
  requested_by: { type: "agent"; id: string };
  on_behalf_of?: string;
  amount: { currency: "INR"; minor: string };
  payee_reference: string;
  purpose: string;
  expires_in_seconds?: number;
}

export interface PolicyDecision {
  allowed: boolean;
  reasons: string[];
  rules_version: string;
  required_approvals: 1 | 2;
  current_daily_exposure_minor: string;
  projected_daily_exposure_minor: string;
}

export interface Approval {
  actor_id: string;
  actor_role: "approver" | "admin";
  decision: ApprovalDecision;
  intent_hash: string;
  created_at: string;
  receipt_hmac: string;
}

export interface Observation {
  status: ObservationStatus;
  provider_reference?: string;
  observed_at: string;
  source: "DEMO_MOCK";
  retry_permitted: false;
}

export interface ApprovalReceipt {
  version: "parimit-approval-receipt-v1";
  intent_id: string;
  intent_hash: string;
  fully_approved_at: string;
  approvals: Approval[];
  execution_authorized: false;
  notice: string;
}

export interface Intent {
  id: string;
  intent_version: string;
  initial_status: "POLICY_DENIED" | "AWAITING_APPROVAL";
  idempotency_key: string;
  requested_by: { type: "agent"; id: string };
  on_behalf_of?: string;
  amount: { currency: "INR"; minor: string };
  payee_reference: string;
  purpose: string;
  status: IntentStatus;
  required_approvals: 1 | 2;
  approval_count: number;
  policy: Pick<PolicyDecision, "allowed" | "reasons" | "rules_version">;
  intent_hash: string;
  created_at: string;
  expires_at: string;
  observation?: Observation;
  approvals: Approval[];
  receipt?: ApprovalReceipt;
  idempotent_replay?: boolean;
}

export interface IntegrityReport {
  valid: boolean;
  intent_hash_valid: boolean;
  approval_receipts_valid: boolean;
  audit_chain_valid: boolean;
  state_consistency_valid: boolean;
  failures: string[];
}

export interface IdentityInfo {
  actor_id: string;
  actor_role: ActorRole;
  authentication_method: "oidc" | "local_demo_headers";
  issuer?: string;
}

export interface AuditEvent {
  sequence: number;
  intent_id: string;
  event_type: string;
  actor_id: string;
  payload: unknown;
  occurred_at: string;
  previous_hash: string;
  event_hash: string;
}

export class ParimitApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ParimitApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

type FetchLike = typeof fetch;

export type ClientIdentity =
  | { accessToken: string; demoIdentity?: never }
  | { accessToken?: never; demoIdentity: { actorId: string; role: ActorRole } };

export interface ClientOptions {
  baseUrl: string;
  identity: ClientIdentity;
  timeoutMs?: number;
  fetch?: FetchLike;
}

interface Envelope<T> {
  data: T;
  warning?: string;
}

function normalizedBaseUrl(value: string): string {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new TypeError("Parimit requires HTTPS except on loopback addresses");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("Parimit baseUrl cannot contain credentials, a query, or a fragment");
  }
  return url.toString().replace(/\/+$/, "");
}

function createTransport(options: ClientOptions) {
  const baseUrl = normalizedBaseUrl(options.baseUrl);
  const requestFetch = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new TypeError("timeoutMs must be an integer from 1 to 120000");
  }

  return async function request<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    if (init.body !== undefined) headers.set("content-type", "application/json");
    if (options.identity.accessToken !== undefined) {
      headers.set("authorization", `Bearer ${options.identity.accessToken}`);
    } else {
      headers.set("x-parimit-actor", options.identity.demoIdentity.actorId);
      headers.set("x-parimit-role", options.identity.demoIdentity.role);
    }
    try {
      const response = await requestFetch(`${baseUrl}${path}`, {
        ...init,
        headers,
        signal: controller.signal,
      });
      const payload = (await response.json()) as {
        data?: T;
        error?: { code?: string; message?: string; details?: unknown };
      };
      if (!response.ok || payload.error) {
        throw new ParimitApiError(
          response.status,
          payload.error?.code ?? "HTTP_ERROR",
          payload.error?.message ?? `Parimit request failed with HTTP ${response.status}`,
          payload.error?.details,
        );
      }
      return (payload as Envelope<T>).data;
    } finally {
      clearTimeout(timeout);
    }
  };
}

function intentPath(id: string, suffix = ""): string {
  if (!id) throw new TypeError("intent id is required");
  return `/v1/intents/${encodeURIComponent(id)}${suffix}`;
}

function readMethods(request: ReturnType<typeof createTransport>) {
  return {
    safety: () => request<Record<string, unknown>>("/v1/safety"),
    identity: () => request<IdentityInfo>("/v1/identity"),
    getIntent: (id: string) => request<Intent>(intentPath(id)),
    listIntents: (filters: { status?: IntentStatus; agentId?: string; limit?: number } = {}) => {
      const query = new URLSearchParams();
      if (filters.status) query.set("status", filters.status);
      if (filters.agentId) query.set("agent_id", filters.agentId);
      if (filters.limit !== undefined) query.set("limit", String(filters.limit));
      const suffix = query.size === 0 ? "" : `?${query.toString()}`;
      return request<Intent[]>(`/v1/intents${suffix}`);
    },
    getAudit: (id: string) => request<AuditEvent[]>(intentPath(id, "/audit")),
    verifyAudit: (id: string) => request<IntegrityReport>(intentPath(id, "/audit/verify")),
  };
}

export function createAgentClient(options: ClientOptions) {
  const request = createTransport(options);
  return Object.freeze({
    ...readMethods(request),
    simulateProposal: (proposal: PaymentProposal) =>
      request<{ policy: PolicyDecision; persisted: false; moves_money: false }>(
        "/v1/intents/simulate",
        { method: "POST", body: JSON.stringify(proposal) },
      ),
    createProposal: (proposal: PaymentProposal) =>
      request<Intent>("/v1/intents", { method: "POST", body: JSON.stringify(proposal) }),
    cancelProposal: (id: string) =>
      request<Intent>(intentPath(id, "/cancel"), { method: "POST" }),
  });
}

export function createReviewerClient(options: ClientOptions) {
  const request = createTransport(options);
  const decide = (id: string, decision: ApprovalDecision) =>
    request<Intent>(intentPath(id, "/approvals"), {
      method: "POST",
      body: JSON.stringify({ decision }),
    });
  return Object.freeze({
    ...readMethods(request),
    approveProposal: (id: string) => decide(id, "APPROVE"),
    rejectProposal: (id: string) => decide(id, "REJECT"),
  });
}

export function createOperatorClient(options: ClientOptions) {
  const request = createTransport(options);
  return Object.freeze({
    ...readMethods(request),
    recordMockObservation: (
      id: string,
      status: ObservationStatus,
      providerReference?: string,
    ) =>
      request<Intent>(`/v1/demo/intents/${encodeURIComponent(id)}/observations`, {
        method: "POST",
        body: JSON.stringify({
          status,
          ...(providerReference === undefined
            ? {}
            : { provider_reference: providerReference }),
        }),
      }),
  });
}
