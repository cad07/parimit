const ROUTES = Object.freeze({
  safety: "/v1/safety",
  intents: "/v1/intents",
  simulate: "/v1/intents/simulate",
  intent: (id) => `/v1/intents/${encodeURIComponent(id)}`,
  cancel: (id) => `/v1/intents/${encodeURIComponent(id)}/cancel`,
  approvals: (id) => `/v1/intents/${encodeURIComponent(id)}/approvals`,
  audit: (id) => `/v1/intents/${encodeURIComponent(id)}/audit`,
  verifyAudit: (id) => `/v1/intents/${encodeURIComponent(id)}/audit/verify`,
  observations: (id) => `/v1/demo/intents/${encodeURIComponent(id)}/observations`,
});

const STATUS = Object.freeze({
  pending: new Set(["DRAFT", "PROPOSED", "PENDING", "PENDING_APPROVAL", "AWAITING_APPROVAL", "POLICY_ALLOWED"]),
  authorized: new Set(["AUTHORIZED_NO_DISPATCH", "AUTHORIZED"]),
  stopped: new Set(["POLICY_DENIED", "REJECTED", "CANCELLED", "CANCELED", "EXPIRED"]),
});

const TERMINAL_STATUSES = new Set([
  ...STATUS.authorized,
  ...STATUS.stopped,
]);

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const elements = {
  identityButton: $("#identity-button"),
  identityPopover: $("#identity-popover"),
  closeIdentity: $("#close-identity"),
  saveIdentity: $("#save-identity"),
  actorInput: $("#actor-input"),
  roleSelect: $("#role-select"),
  identitySummary: $("#identity-summary"),
  avatarInitials: $("#avatar-initials"),
  proposalForm: $("#proposal-form"),
  proposalError: $("#proposal-error"),
  createProposal: $("#create-proposal"),
  purpose: $("#purpose"),
  purposeCount: $("#purpose-count"),
  idempotencyKey: $("#idempotency-key"),
  generateKey: $("#generate-key"),
  refreshIntents: $("#refresh-intents"),
  retryConnection: $("#retry-connection"),
  connectionNotice: $("#connection-notice"),
  connectionMessage: $("#connection-message"),
  loading: $("#intents-loading"),
  list: $("#intent-list"),
  empty: $("#empty-state"),
  emptyMessage: $("#empty-message"),
  search: $("#intent-search"),
  statusTabs: $("#status-tabs"),
  dialog: $("#intent-dialog"),
  dialogTitle: $("#dialog-title"),
  dialogContent: $("#dialog-content"),
  toastRegion: $("#toast-region"),
  safetyStatus: $("#safety-api-status"),
  metrics: {
    total: $("#metric-total"),
    pending: $("#metric-pending"),
    approved: $("#metric-approved"),
    stopped: $("#metric-stopped"),
  },
};

const state = {
  intents: [],
  filter: "all",
  query: "",
  activeIntentId: null,
  activeIntent: null,
  audit: [],
  identity: loadIdentity(),
};

class ApiError extends Error {
  constructor(message, { status = 0, code = "REQUEST_FAILED", details = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function loadIdentity() {
  try {
    const saved = JSON.parse(localStorage.getItem("parimit.identity") || "null");
    if (saved?.actor && saved?.role) return saved;
  } catch {
    // Ignore malformed local demo preferences.
  }
  return { actor: "demo-approver", role: "approver" };
}

function saveIdentity(identity) {
  localStorage.setItem("parimit.identity", JSON.stringify(identity));
}

async function request(path, { method = "GET", body, role, signal } = {}) {
  const headers = {
    Accept: "application/json",
    "x-parimit-actor": state.identity.actor,
    "x-parimit-role": role || state.identity.role,
  };

  if (body !== undefined) headers["Content-Type"] = "application/json";

  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new ApiError("The local API is unavailable. Start the Parimit server and try again.", {
      code: "NETWORK_ERROR",
      details: error,
    });
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new ApiError(`The API returned an unreadable response (${response.status}).`, {
        status: response.status,
        code: "INVALID_RESPONSE",
      });
    }
  }

  if (!response.ok) {
    const apiError = payload?.error;
    throw new ApiError(apiError?.message || `Request failed with status ${response.status}.`, {
      status: response.status,
      code: apiError?.code || "REQUEST_FAILED",
      details: apiError?.details,
    });
  }

  return payload?.data ?? payload;
}

const api = Object.freeze({
  getSafety: () => request(ROUTES.safety),
  listIntents: () => request(ROUTES.intents),
  createIntent: (payload) => request(ROUTES.intents, { method: "POST", body: payload }),
  simulateIntent: (payload) => request(ROUTES.simulate, { method: "POST", body: payload }),
  getIntent: (id) => request(ROUTES.intent(id)),
  cancelIntent: (id) => request(ROUTES.cancel(id), { method: "POST" }),
  decideIntent: (id, decision) => request(ROUTES.approvals(id), {
    method: "POST",
    body: { decision },
  }),
  getAudit: (id) => request(ROUTES.audit(id)),
  verifyAudit: (id) => request(ROUTES.verifyAudit(id)),
  addObservation: (id, payload) => request(ROUTES.observations(id), {
    method: "POST",
    role: "admin",
    body: payload,
  }),
});

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function normalizeStatus(value) {
  return String(value || "PROPOSED").trim().toUpperCase().replaceAll("-", "_").replaceAll(" ", "_");
}

function normalizeIntent(raw = {}) {
  const amount = raw.amount || {};
  const policy = raw.policy || raw.policy_decision || {};
  const observation = raw.observation || null;
  return {
    ...raw,
    id: raw.id || raw.intent_id || "unknown",
    status: normalizeStatus(raw.status),
    payeeReference: raw.payee_reference || raw.payeeReference || "undisclosed_reference",
    purpose: raw.purpose || "No purpose provided",
    amountMinor: String(amount.minor ?? raw.amount_minor ?? raw.amountMinor ?? "0"),
    currency: amount.currency || raw.currency || "INR",
    requestedBy: raw.requested_by || raw.requestedBy || null,
    requiredApprovals: Number(raw.required_approvals ?? raw.requiredApprovals ?? 1),
    approvalCount: Number(raw.approval_count ?? raw.approvalCount ?? raw.approvals?.length ?? 0),
    approvals: Array.isArray(raw.approvals) ? raw.approvals : [],
    policy: {
      allowed: policy.allowed !== false,
      reasons: Array.isArray(policy.reasons) ? policy.reasons : [],
      rulesVersion: policy.rules_version || policy.rulesVersion || "—",
    },
    intentHash: raw.intent_hash || raw.intentHash || "",
    createdAt: raw.created_at || raw.createdAt || null,
    expiresAt: raw.expires_at || raw.expiresAt || null,
    observation,
    receipt: raw.receipt || null,
  };
}

function normalizeList(payload) {
  const list = Array.isArray(payload) ? payload : payload?.items || payload?.intents || [];
  return list.map(normalizeIntent);
}

function normalizeAudit(payload) {
  const list = Array.isArray(payload) ? payload : payload?.entries || payload?.events || payload?.audit || [];
  return list.map((entry, index) => ({
    ...entry,
    index: entry.sequence ?? entry.index ?? index + 1,
    type: entry.event_type || entry.eventType || entry.type || entry.action || "EVENT",
    actor: entry.actor?.id || entry.actor_id || entry.actor || entry.created_by || "system",
    timestamp: entry.created_at || entry.occurred_at || entry.timestamp || entry.at || null,
    hash: entry.hash || entry.event_hash || "",
  }));
}

function statusGroup(status) {
  const normalized = normalizeStatus(status);
  if (STATUS.pending.has(normalized)) return "pending";
  if (STATUS.authorized.has(normalized)) return "approved";
  if (STATUS.stopped.has(normalized)) return "stopped";
  return "other";
}

function statusPresentation(status, observation) {
  const normalized = normalizeStatus(status);
  const observed = normalizeStatus(observation?.status || "");

  if (normalized === "AUTHORIZED_NO_DISPATCH" || normalized === "AUTHORIZED") {
    return { label: "Authorized — no dispatch", className: "status-approved" };
  }
  if (normalized === "POLICY_DENIED") return { label: "Policy denied", className: "status-rejected" };
  if (normalized === "REJECTED") return { label: "Rejected", className: "status-rejected" };
  if (normalized === "CANCELLED" || normalized === "CANCELED") return { label: "Cancelled", className: "status-cancelled" };
  if (normalized === "EXPIRED") return { label: "Expired", className: "status-neutral" };
  if (STATUS.pending.has(normalized)) return { label: "Needs review", className: "status-pending" };

  if (observed === "SUCCEEDED" || observed === "SUCCESS") return { label: "Mock: succeeded", className: "status-observed-success" };
  if (observed === "FAILED" || observed === "FAILURE") return { label: "Mock: failed", className: "status-failed" };
  if (observed === "IN_DOUBT" || observed === "UNKNOWN") return { label: "Mock: in doubt", className: "status-in-doubt" };
  if (observed === "REVERSED") return { label: "Mock: reversed", className: "status-reversed" };
  return { label: humanize(normalized), className: "status-neutral" };
}

function humanize(value) {
  return String(value || "unknown")
    .toLowerCase()
    .replaceAll("_", " ")
    .replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
}

function formatMoney(minor, currency = "INR") {
  const safeMinor = /^-?\d+$/.test(String(minor)) ? String(minor) : "0";
  try {
    const number = Number(safeMinor) / 100;
    if (Number.isSafeInteger(Number(safeMinor))) {
      return new Intl.NumberFormat("en-IN", {
        style: "currency",
        currency,
        minimumFractionDigits: 2,
      }).format(number);
    }
  } catch {
    // Fall through to lossless display.
  }
  const negative = safeMinor.startsWith("-");
  const digits = safeMinor.replace("-", "").padStart(3, "0");
  const major = digits.slice(0, -2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const symbol = currency === "INR" ? "₹" : `${currency} `;
  return `${negative ? "-" : ""}${symbol}${major}.${digits.slice(-2)}`;
}

function formatDate(value, { compact = false } = {}) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return String(value);
  return new Intl.DateTimeFormat("en-IN", compact
    ? { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }
    : { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function shortId(value, length = 12) {
  const string = String(value || "");
  return string.length > length ? `${string.slice(0, length)}…` : string || "—";
}

function makeIdempotencyKey() {
  if (globalThis.crypto?.randomUUID) return `web-${globalThis.crypto.randomUUID()}`;
  return `web-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function decimalToMinor(value) {
  const normalized = String(value).trim();
  if (!/^\d+(\.\d{1,2})?$/.test(normalized)) return null;
  const [major, fraction = ""] = normalized.split(".");
  return `${BigInt(major) * 100n + BigInt(fraction.padEnd(2, "0"))}`;
}

function actorInitials(actor) {
  const chunks = String(actor || "demo actor").split(/[^a-zA-Z0-9]+/).filter(Boolean);
  return chunks.slice(0, 2).map((chunk) => chunk[0].toUpperCase()).join("") || "DA";
}

function setButtonLoading(button, loading) {
  if (!button) return;
  button.disabled = loading;
  button.classList.toggle("is-loading", loading);
  button.setAttribute("aria-busy", String(loading));
}

function showToast(title, message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast${type === "error" ? " is-error" : ""}`;
  toast.setAttribute("role", type === "error" ? "alert" : "status");
  toast.innerHTML = `
    <span class="toast-icon" aria-hidden="true">${type === "error" ? "!" : "✓"}</span>
    <div><strong>${escapeHtml(title)}</strong><span>${escapeHtml(message)}</span></div>
  `;
  elements.toastRegion.append(toast);
  window.setTimeout(() => toast.remove(), 5500);
}

function showInlineError(container, error) {
  container.textContent = error instanceof Error ? error.message : String(error);
  container.hidden = false;
}

function updateIdentityUi() {
  const { actor, role } = state.identity;
  elements.actorInput.value = actor;
  elements.roleSelect.value = role;
  elements.identitySummary.textContent = `${actor} · ${role}`;
  elements.avatarInitials.textContent = actorInitials(actor);
}

function setIdentityPopover(open) {
  elements.identityPopover.hidden = !open;
  elements.identityButton.setAttribute("aria-expanded", String(open));
  if (open) elements.actorInput.focus();
}

function renderMetrics() {
  const groups = state.intents.map((intent) => statusGroup(intent.status));
  elements.metrics.total.textContent = state.intents.length.toLocaleString("en-IN");
  elements.metrics.pending.textContent = groups.filter((group) => group === "pending").length.toLocaleString("en-IN");
  elements.metrics.approved.textContent = groups.filter((group) => group === "approved").length.toLocaleString("en-IN");
  elements.metrics.stopped.textContent = groups.filter((group) => group === "stopped").length.toLocaleString("en-IN");
}

function filteredIntents() {
  const query = state.query.trim().toLowerCase();
  return state.intents.filter((intent) => {
    const groupMatches = state.filter === "all" || statusGroup(intent.status) === state.filter;
    const queryMatches = !query || [intent.id, intent.payeeReference, intent.purpose, intent.status]
      .some((value) => String(value || "").toLowerCase().includes(query));
    return groupMatches && queryMatches;
  });
}

function renderIntents() {
  const intents = filteredIntents();
  elements.list.innerHTML = intents.map((intent) => {
    const status = statusPresentation(intent.status, intent.observation);
    const required = Math.max(1, intent.requiredApprovals || 1);
    const count = Math.max(0, intent.approvalCount || 0);
    return `
      <article class="intent-card" data-intent-id="${escapeHtml(intent.id)}">
        <div class="intent-primary">
          <span class="intent-glyph" aria-hidden="true">${escapeHtml(intent.payeeReference.slice(0, 1).toUpperCase())}</span>
          <div>
            <strong title="${escapeHtml(intent.payeeReference)}">${escapeHtml(intent.payeeReference)}</strong>
            <small title="${escapeHtml(intent.purpose)}">${escapeHtml(intent.purpose)}</small>
          </div>
        </div>
        <div class="intent-amount">
          <strong>${escapeHtml(formatMoney(intent.amountMinor, intent.currency))}</strong>
          <span>${escapeHtml(intent.currency)} · proposal</span>
        </div>
        <div class="intent-meta">
          <strong>${escapeHtml(formatDate(intent.createdAt, { compact: true }))}</strong>
          <small>ID ${escapeHtml(shortId(intent.id))}</small>
        </div>
        <div class="approval-progress">
          <strong>${count} of ${required} approvals</strong>
          <progress class="progress-track" value="${Math.min(count, required)}" max="${required}" aria-label="${count} of ${required} approvals"></progress>
          <small>${intent.policy.allowed ? "Policy allows review" : "Stopped by policy"}</small>
        </div>
        <span class="status-pill ${status.className} intent-status">${escapeHtml(status.label)}</span>
        <button class="intent-open" type="button" data-open-intent="${escapeHtml(intent.id)}" aria-label="Review proposal ${escapeHtml(shortId(intent.id))}">
          <svg viewBox="0 0 20 20" aria-hidden="true"><path d="m7 4 6 6-6 6" /></svg>
        </button>
      </article>
    `;
  }).join("");

  const isEmpty = intents.length === 0;
  elements.empty.hidden = !isEmpty;
  if (isEmpty) {
    elements.emptyMessage.textContent = state.intents.length
      ? "No proposals match this search and status filter."
      : "Create the first proposal above. It will remain safely inside this review plane.";
  }
}

async function loadIntents({ quiet = false } = {}) {
  if (!quiet) elements.loading.hidden = false;
  elements.connectionNotice.hidden = true;
  try {
    const payload = await api.listIntents();
    state.intents = normalizeList(payload);
    state.intents.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    renderMetrics();
    renderIntents();
  } catch (error) {
    elements.connectionMessage.textContent = error.message;
    elements.connectionNotice.hidden = false;
    if (!quiet) {
      state.intents = [];
      renderMetrics();
      renderIntents();
    }
  } finally {
    elements.loading.hidden = true;
  }
}

async function loadSafetyBoundary() {
  try {
    const safety = await api.getSafety();
    const explicitNoExecution = safety?.moves_money === false
      || safety?.can_move_money === false
      || safety?.payment_execution === false
      || safety?.proposal_only === true
      || safety?.mode === "proposal-only";
    elements.safetyStatus.classList.add("is-confirmed");
    elements.safetyStatus.querySelector("span:last-child").textContent = explicitNoExecution
      ? "Runtime confirms: proposal-only; payment execution unavailable"
      : "Safety endpoint reachable · proposal boundary active";
  } catch {
    elements.safetyStatus.classList.remove("is-confirmed");
    elements.safetyStatus.querySelector("span:last-child").textContent = "Static boundary shown · local API unavailable";
  }
}

function validateProposal(formData) {
  const payeeReference = String(formData.get("payeeReference") || "").trim();
  const purpose = String(formData.get("purpose") || "").trim();
  const minor = decimalToMinor(formData.get("amount"));

  if (!/^[A-Za-z][A-Za-z0-9:_-]{5,63}$/.test(payeeReference)) {
    throw new ApiError("Use an opaque payee reference of 6–64 characters. Start with a letter and use only letters, numbers, colon, underscore, or hyphen.", { code: "INVALID_PAYEE_REFERENCE" });
  }
  if (payeeReference.includes("@") || /^\d+$/.test(payeeReference)) {
    throw new ApiError("Do not enter a UPI ID, phone number, bank account, or other payment credential. Use an opaque internal reference.", { code: "SENSITIVE_PAYEE_REFERENCE" });
  }
  if (!minor || BigInt(minor) <= 0n) {
    throw new ApiError("Enter an amount greater than ₹0.00 with no more than two decimal places.", { code: "INVALID_AMOUNT" });
  }
  if (purpose.length < 4) {
    throw new ApiError("Add a brief business purpose for reviewers.", { code: "INVALID_PURPOSE" });
  }

  return {
    idempotency_key: String(formData.get("idempotencyKey") || "").trim() || makeIdempotencyKey(),
    requested_by: {
      type: "agent",
      id: state.identity.role === "agent" ? state.identity.actor : "demo-agent",
    },
    amount: {
      currency: String(formData.get("currency") || "INR"),
      minor,
    },
    payee_reference: payeeReference,
    purpose,
  };
}

async function handleProposalSubmit(event) {
  event.preventDefault();
  elements.proposalError.hidden = true;
  elements.proposalError.textContent = "";

  const form = event.currentTarget;
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }

  let payload;
  try {
    payload = validateProposal(new FormData(form));
  } catch (error) {
    showInlineError(elements.proposalError, error);
    return;
  }

  setButtonLoading(elements.createProposal, true);
  try {
    const created = normalizeIntent(await api.createIntent(payload));
    state.intents = [created, ...state.intents.filter((item) => item.id !== created.id)];
    renderMetrics();
    renderIntents();
    form.reset();
    $("#currency").value = "INR";
    elements.purposeCount.textContent = "0";
    showToast("Proposal created", "The intent is ready for review. No payment was sent.");
    await openIntent(created.id);
  } catch (error) {
    showInlineError(elements.proposalError, error);
    showToast("Proposal not created", error.message, "error");
  } finally {
    setButtonLoading(elements.createProposal, false);
  }
}

function detailMarkup(intent, audit = []) {
  const status = statusPresentation(intent.status, intent.observation);
  const required = Math.max(1, intent.requiredApprovals || 1);
  const count = Math.max(0, intent.approvalCount || 0);
  const pending = statusGroup(intent.status) === "pending";
  const actorCanApprove = state.identity.role === "approver" || state.identity.role === "admin";
  const canDecide = pending && intent.policy.allowed && actorCanApprove;
  const requesterId = intent.requestedBy?.id || "";
  const actorCanCancel = state.identity.role === "admin"
    || (state.identity.role === "agent" && state.identity.actor === requesterId);
  const canCancel = !TERMINAL_STATUSES.has(intent.status) && actorCanCancel;
  const observationFrozen = normalizeStatus(intent.observation?.status || "") === "IN_DOUBT";
  const canObserve = STATUS.authorized.has(intent.status) && !observationFrozen;
  const reasons = intent.policy.reasons.length
    ? intent.policy.reasons.map((reason) => `<li>${escapeHtml(typeof reason === "string" ? reason : reason.message || reason.code || JSON.stringify(reason))}</li>`).join("")
    : `<li>No blocking policy reason was returned.</li>`;
  const approvals = intent.approvals.length
    ? intent.approvals.map((approval) => `
        <li><span><strong>${escapeHtml(humanize(approval.decision || "approved"))}</strong><small>${escapeHtml(approval.actor?.id || approval.actor_id || approval.actor || "demo approver")}</small></span><small>${escapeHtml(formatDate(approval.created_at || approval.timestamp, { compact: true }))}</small></li>
      `).join("")
    : `<li><span><strong>${count} recorded</strong><small>Approval identities are not included in this response.</small></span><small>${required} required</small></li>`;

  const observation = intent.observation
    ? `<ul class="observations-list"><li><span><strong>${escapeHtml(humanize(intent.observation.status))}</strong><small>Mock provider reference: ${escapeHtml(intent.observation.provider_reference || intent.observation.providerReference || "not supplied")}</small></span><small>${escapeHtml(formatDate(intent.observation.observed_at || intent.observation.created_at, { compact: true }))}</small></li></ul>`
    : `<p class="audit-empty">No mock outcome has been attached.</p>`;

  const auditMarkup = audit.length
    ? `<ol class="audit-list">${audit.map((entry) => `
        <li><strong>#${escapeHtml(entry.index)} · ${escapeHtml(humanize(entry.type))}</strong><span>${escapeHtml(entry.actor)} · ${escapeHtml(formatDate(entry.timestamp, { compact: true }))}</span>${entry.hash ? `<span>Hash ${escapeHtml(shortId(entry.hash, 20))}</span>` : ""}</li>
      `).join("")}</ol>`
    : `<p class="audit-empty">No audit events were returned.</p>`;

  return `
    <div class="detail-hero">
      <div class="detail-payee">
        <small>Opaque payee reference</small>
        <h3>${escapeHtml(intent.payeeReference)}</h3>
        <p>${escapeHtml(intent.purpose)}</p>
      </div>
      <div class="detail-amount"><strong>${escapeHtml(formatMoney(intent.amountMinor, intent.currency))}</strong><span>${escapeHtml(intent.currency)} · proposed amount</span></div>
    </div>

    <div class="detail-grid">
      <div class="detail-stat"><small>Status</small><strong><span class="status-pill ${status.className}">${escapeHtml(status.label)}</span></strong></div>
      <div class="detail-stat"><small>Approvals</small><strong>${count} of ${required}</strong></div>
      <div class="detail-stat"><small>Created</small><strong>${escapeHtml(formatDate(intent.createdAt, { compact: true }))}</strong></div>
      <div class="detail-stat"><small>Intent ID</small><strong title="${escapeHtml(intent.id)}">${escapeHtml(shortId(intent.id, 18))}</strong></div>
      <div class="detail-stat"><small>Expires</small><strong>${escapeHtml(formatDate(intent.expiresAt, { compact: true }))}</strong></div>
      <div class="detail-stat"><small>Rules</small><strong>${escapeHtml(intent.policy.rulesVersion)}</strong></div>
    </div>

    <section class="detail-section" aria-labelledby="policy-heading">
      <div class="detail-section-heading"><h3 id="policy-heading">Policy decision</h3><span class="status-pill ${intent.policy.allowed ? "status-approved" : "status-rejected"}">${intent.policy.allowed ? "Review allowed" : "Denied"}</span></div>
      <div class="decision-box">
        <div class="decision-summary"><strong>${intent.policy.allowed ? "Deterministic policy allows human review" : "Deterministic policy stopped this proposal"}</strong><small>Version ${escapeHtml(intent.policy.rulesVersion)}</small></div>
        <ul class="decision-reasons">${reasons}</ul>
      </div>
    </section>

    <section class="detail-section" aria-labelledby="approvals-heading">
      <div class="detail-section-heading"><h3 id="approvals-heading">Human decisions</h3><small>Distinct actors only</small></div>
      <ul class="approvals-list">${approvals}</ul>
      <div class="action-bar">
        <button class="button button-primary" type="button" data-dialog-action="APPROVE" ${canDecide ? "" : "disabled"}>Approve intent</button>
        <button class="button button-danger" type="button" data-dialog-action="REJECT" ${canDecide ? "" : "disabled"}>Reject intent</button>
        <button class="button button-secondary" type="button" data-dialog-action="CANCEL" ${canCancel ? "" : "disabled"}>Cancel proposal</button>
        <p class="action-bar-note">${actorCanApprove ? `Decision actor: ${escapeHtml(state.identity.actor)} · ${escapeHtml(state.identity.role)}` : `Switch the demo identity to the approver or admin role to record a decision.`} ${actorCanCancel ? "This identity may also cancel the open proposal." : "Cancellation requires its requesting agent or an admin."} Approval authorizes a record only; it does not dispatch funds.</p>
      </div>
    </section>

    <section class="detail-section" aria-labelledby="observation-heading">
      <div class="detail-section-heading"><h3 id="observation-heading">Mock rail observation</h3><small>Simulation label required</small></div>
      ${observation}
      <form class="observation-form" id="observation-form">
        <div class="field-group">
          <label for="observation-status">Mock status</label>
          <select id="observation-status" name="status" ${canObserve ? "" : "disabled"}>
            <option value="SUCCEEDED">Succeeded</option>
            <option value="FAILED">Failed</option>
            <option value="IN_DOUBT">In doubt</option>
            <option value="REVERSED">Reversed</option>
          </select>
        </div>
        <div class="field-group">
          <label for="provider-reference">Mock provider reference <span class="optional">optional</span></label>
          <input id="provider-reference" name="providerReference" maxlength="80" placeholder="mock_obs_001" autocomplete="off" ${canObserve ? "" : "disabled"} />
        </div>
        <button class="button button-secondary" type="submit" ${canObserve ? "" : "disabled"}>Attach mock result</button>
        ${canObserve ? "" : `<p class="action-bar-note">${observationFrozen ? "IN_DOUBT froze this mock observation stream. The alpha accepts no later outcome and has no reconciliation mechanism." : "Mock observations can be attached only after the proposal reaches Authorized — no dispatch."}</p>`}
      </form>
    </section>

    <section class="detail-section" aria-labelledby="audit-heading">
      <div class="detail-section-heading">
        <h3 id="audit-heading">Hash-linked audit trail</h3>
        <div class="audit-toolbar">
          <span class="verification-result" id="verification-result">Not verified</span>
          <button class="button button-secondary" type="button" data-dialog-action="VERIFY">Verify trail</button>
        </div>
      </div>
      ${auditMarkup}
    </section>
  `;
}

async function openIntent(id) {
  state.activeIntentId = id;
  state.activeIntent = null;
  state.audit = [];
  elements.dialogTitle.textContent = "Review intent";
  elements.dialogContent.innerHTML = `<div class="dialog-loading"><span class="spinner" aria-hidden="true"></span><span>Loading proposal and audit trail…</span></div>`;
  if (!elements.dialog.open) elements.dialog.showModal();

  try {
    const [intentResult, auditResult] = await Promise.allSettled([api.getIntent(id), api.getAudit(id)]);
    if (state.activeIntentId !== id) return;
    if (intentResult.status === "rejected") throw intentResult.reason;
    state.activeIntent = normalizeIntent(intentResult.value);
    state.audit = auditResult.status === "fulfilled" ? normalizeAudit(auditResult.value) : [];
    elements.dialogTitle.textContent = `Proposal ${shortId(id, 12)}`;
    elements.dialogContent.innerHTML = detailMarkup(state.activeIntent, state.audit);
  } catch (error) {
    elements.dialogContent.innerHTML = `<div class="dialog-error"><strong>Could not load this proposal.</strong><br />${escapeHtml(error.message)}</div>`;
  }
}

async function refreshActiveIntent() {
  if (!state.activeIntentId) return;
  const id = state.activeIntentId;
  const [intentPayload, auditPayload] = await Promise.all([api.getIntent(id), api.getAudit(id)]);
  state.activeIntent = normalizeIntent(intentPayload);
  state.audit = normalizeAudit(auditPayload);
  elements.dialogContent.innerHTML = detailMarkup(state.activeIntent, state.audit);
  state.intents = [state.activeIntent, ...state.intents.filter((intent) => intent.id !== id)];
  renderMetrics();
  renderIntents();
}

async function handleDialogAction(button, action) {
  if (!state.activeIntentId) return;
  const id = state.activeIntentId;

  if (action === "REJECT" && !window.confirm("Reject this proposal? This records a human decision; no payment has been or will be sent.")) return;
  if (action === "CANCEL" && !window.confirm("Cancel this proposal? This cannot affect any real payment because none is connected.")) return;

  setButtonLoading(button, true);
  try {
    if (action === "APPROVE" || action === "REJECT") {
      await api.decideIntent(id, action);
      showToast(
        action === "APPROVE" ? "Approval recorded" : "Rejection recorded",
        action === "APPROVE" ? "The proposal may become authorized, but it cannot dispatch money." : "The proposal was stopped safely.",
      );
    } else if (action === "CANCEL") {
      await api.cancelIntent(id);
      showToast("Proposal cancelled", "The intent has been stopped. No payment was sent.");
    }
    await refreshActiveIntent();
  } catch (error) {
    showToast("Action not recorded", error.message, "error");
  } finally {
    setButtonLoading(button, false);
  }
}

async function handleAuditVerify(button) {
  if (!state.activeIntentId) return;
  const resultNode = $("#verification-result", elements.dialogContent);
  setButtonLoading(button, true);
  if (resultNode) {
    resultNode.className = "verification-result";
    resultNode.textContent = "Verifying…";
  }
  try {
    const result = await api.verifyAudit(state.activeIntentId);
    const valid = result === true || result?.valid === true || result?.verified === true || result?.integrity === "valid";
    if (resultNode) {
      resultNode.classList.add(valid ? "is-valid" : "is-invalid");
      resultNode.textContent = valid ? "✓ Chain valid" : "! Chain invalid";
    }
    showToast(
      valid ? "Audit trail verified" : "Audit integrity warning",
      valid ? "Every returned event is linked consistently." : "The server could not validate the event chain.",
      valid ? "success" : "error",
    );
  } catch (error) {
    if (resultNode) {
      resultNode.classList.add("is-invalid");
      resultNode.textContent = "Verification failed";
    }
    showToast("Could not verify audit trail", error.message, "error");
  } finally {
    setButtonLoading(button, false);
  }
}

async function handleObservationSubmit(form) {
  if (!state.activeIntentId) return;
  const submit = $("button[type='submit']", form);
  const formData = new FormData(form);
  const providerReference = String(formData.get("providerReference") || "").trim();
  const payload = { status: String(formData.get("status") || "IN_DOUBT") };
  if (providerReference) payload.provider_reference = providerReference;

  setButtonLoading(submit, true);
  try {
    await api.addObservation(state.activeIntentId, payload);
    showToast("Mock observation attached", "This simulated result is labelled and did not come from a payment rail.");
    await refreshActiveIntent();
  } catch (error) {
    showToast("Observation not attached", error.message, "error");
  } finally {
    setButtonLoading(submit, false);
  }
}

function bindEvents() {
  elements.identityButton.addEventListener("click", () => setIdentityPopover(elements.identityPopover.hidden));
  elements.closeIdentity.addEventListener("click", () => setIdentityPopover(false));
  elements.saveIdentity.addEventListener("click", () => {
    const actor = elements.actorInput.value.trim();
    const role = elements.roleSelect.value;
    if (!/^[A-Za-z0-9][A-Za-z0-9:_-]{2,63}$/.test(actor)) {
      showToast("Invalid demo actor", "Use 3–64 letters, numbers, colons, underscores, or hyphens.", "error");
      elements.actorInput.focus();
      return;
    }
    state.identity = { actor, role };
    saveIdentity(state.identity);
    updateIdentityUi();
    setIdentityPopover(false);
    if (state.activeIntent) elements.dialogContent.innerHTML = detailMarkup(state.activeIntent, state.audit);
    showToast("Demo identity updated", `Requests now identify ${actor} as ${role}.`);
  });

  document.addEventListener("click", (event) => {
    if (!elements.identityPopover.hidden
      && !elements.identityPopover.contains(event.target)
      && !elements.identityButton.contains(event.target)) {
      setIdentityPopover(false);
    }
  });

  elements.proposalForm.addEventListener("submit", handleProposalSubmit);
  elements.purpose.addEventListener("input", () => {
    elements.purposeCount.textContent = elements.purpose.value.length;
  });
  elements.generateKey.addEventListener("click", () => {
    elements.idempotencyKey.value = makeIdempotencyKey();
    elements.idempotencyKey.focus();
  });

  elements.refreshIntents.addEventListener("click", async () => {
    setButtonLoading(elements.refreshIntents, true);
    await loadIntents({ quiet: true });
    setButtonLoading(elements.refreshIntents, false);
  });
  elements.retryConnection.addEventListener("click", () => loadIntents());
  elements.search.addEventListener("input", () => {
    state.query = elements.search.value;
    renderIntents();
  });
  elements.statusTabs.addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter]");
    if (!button) return;
    state.filter = button.dataset.filter;
    $$("[data-filter]", elements.statusTabs).forEach((tab) => {
      const active = tab === button;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-pressed", String(active));
    });
    renderIntents();
  });

  elements.list.addEventListener("click", (event) => {
    const button = event.target.closest("[data-open-intent]");
    if (button) openIntent(button.dataset.openIntent);
  });

  $(".dialog-close", elements.dialog).addEventListener("click", () => elements.dialog.close());
  elements.dialog.addEventListener("click", (event) => {
    if (event.target === elements.dialog) elements.dialog.close();
  });
  elements.dialog.addEventListener("close", () => {
    state.activeIntentId = null;
    state.activeIntent = null;
    state.audit = [];
  });

  elements.dialogContent.addEventListener("click", (event) => {
    const button = event.target.closest("[data-dialog-action]");
    if (!button) return;
    const action = button.dataset.dialogAction;
    if (action === "VERIFY") handleAuditVerify(button);
    else handleDialogAction(button, action);
  });
  elements.dialogContent.addEventListener("submit", (event) => {
    if (event.target.id !== "observation-form") return;
    event.preventDefault();
    handleObservationSubmit(event.target);
  });
}

async function init() {
  updateIdentityUi();
  bindEvents();
  elements.idempotencyKey.value = makeIdempotencyKey();
  await Promise.all([loadIntents(), loadSafetyBoundary()]);
}

init();
