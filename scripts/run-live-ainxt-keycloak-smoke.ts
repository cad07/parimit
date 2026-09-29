import type {
  AiNxtCreationResult,
  AiNxtDraftRequest,
  AiNxtSimulationResult,
} from "../integrations/ainxt/adapter.ts";

export const LIVE_AINXT_KEYCLOAK_REPORT_CLASSIFICATION =
  "LIVE_AINXT_KEYCLOAK_PROPOSAL_SMOKE" as const;

interface ProposalSmokeAdapter {
  createProposal(request: AiNxtDraftRequest): Promise<AiNxtCreationResult>;
  simulateProposal(request: AiNxtDraftRequest): Promise<AiNxtSimulationResult>;
}

export interface LiveAiNxtKeycloakSmokeEvidence {
  classification: typeof LIVE_AINXT_KEYCLOAK_REPORT_CLASSIFICATION;
  expected_control_plane_sha: string;
  interactive_humans: false;
  approvals_attempted: 0;
  payment_execution_capability: false;
  coffee_order: {
    idempotency_key: string;
    intent_id: string;
    status: "AWAITING_APPROVAL";
    approval_count: 0;
    required_approvals: 1;
    proposal_persisted: true;
    same_process_idempotent_replay: true;
    control_plane_sha: string;
    moves_money: false;
  };
  mobility_pass: {
    idempotency_key: string;
    policy_allowed: false;
    policy_reasons: string[];
    simulation_persisted: false;
    creation_attempted: false;
    control_plane_sha: string;
    moves_money: false;
  };
}

export type LiveAiNxtCoffeeEvidence = LiveAiNxtKeycloakSmokeEvidence["coffee_order"];
export type LiveAiNxtMobilityEvidence = LiveAiNxtKeycloakSmokeEvidence["mobility_pass"];

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function requireLoopbackOnlyAiNxtBindings(
  platform: string,
  listenerOutput: string,
): string[] {
  let endpoints: string[];
  if (platform === "darwin") {
    endpoints = listenerOutput
      .split(/\r?\n/u)
      .filter((line) => line.startsWith("n"))
      .map((line) => line.slice(1).trim())
      .filter((line) => line.length > 0);
  } else if (platform === "linux") {
    endpoints = listenerOutput
      .split(/\r?\n/u)
      .map((line) => line.trim().split(/\s+/u)[3] ?? "")
      .filter((endpoint) => /(?:^|\]|:)8080$/u.test(endpoint));
  } else {
    throw new Error("Cannot prove the AiNxt listener binding on this operating system");
  }

  const uniqueEndpoints = [...new Set(endpoints)].sort();
  expect(uniqueEndpoints.length > 0, "No AiNxt listener was found on TCP port 8080");
  expect(
    uniqueEndpoints.every(
      (endpoint) => endpoint === "127.0.0.1:8080" || endpoint === "[::1]:8080",
    ),
    "AiNxt TCP port 8080 is not bound exclusively to loopback",
  );
  return uniqueEndpoints;
}

export function requireExpectedControlPlaneSha(value: unknown): string {
  expect(
    typeof value === "string" && /^[0-9a-f]{64}$/u.test(value),
    "The expected AiNxt control-plane SHA must be exactly 64 lowercase hexadecimal characters",
  );
  return value;
}

function assertObservedControlPlaneSha(observed: string, expected: string, context: string): void {
  expect(observed !== "unpinned", `${context} returned an unpinned AiNxt control plane`);
  expect(observed === expected, `${context} returned an unexpected AiNxt control-plane SHA`);
}

function requireRunId(value: string): string {
  expect(
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/u.test(value),
    "The live AiNxt smoke run id must be a bounded identifier",
  );
  return value;
}

export function liveAiNxtSmokeIdempotencyKeys(runIdValue: string): {
  coffee: string;
  mobility: string;
} {
  const runId = requireRunId(runIdValue);
  return {
    coffee: `ainxt-keycloak-${runId}-coffee`,
    mobility: `ainxt-keycloak-${runId}-mobility`,
  };
}

function assertReplayMatchesOriginal(
  original: AiNxtCreationResult,
  replay: AiNxtCreationResult,
): void {
  expect(
    JSON.stringify(replay.draft) === JSON.stringify(original.draft),
    "coffee_order replay changed the validated model draft",
  );
  expect(
    JSON.stringify(replay.simulation_policy) === JSON.stringify(original.simulation_policy),
    "coffee_order replay changed the simulation policy snapshot",
  );
  expect(
    replay.ainxt.reviewed_source_commit === original.ainxt.reviewed_source_commit &&
      replay.ainxt.transport === original.ainxt.transport,
    "coffee_order replay changed the AiNxt adapter provenance",
  );
  expect(replay.intent.id === original.intent.id, "coffee_order replay returned a different proposal");
  expect(
    replay.intent.idempotency_key === original.intent.idempotency_key,
    "coffee_order replay changed the idempotency key",
  );
  expect(
    replay.intent.intent_version === original.intent.intent_version &&
      replay.intent.tenant_id === original.intent.tenant_id &&
      replay.intent.state_version === original.intent.state_version,
    "coffee_order replay changed the versioned proposal identity",
  );
  expect(
    replay.intent.requested_by.type === original.intent.requested_by.type &&
      replay.intent.requested_by.id === original.intent.requested_by.id,
    "coffee_order replay changed the requesting agent",
  );
  expect(
    replay.intent.on_behalf_of === original.intent.on_behalf_of &&
      replay.intent.amount.currency === original.intent.amount.currency &&
      replay.intent.amount.minor === original.intent.amount.minor &&
      replay.intent.payee_reference === original.intent.payee_reference &&
      replay.intent.purpose === original.intent.purpose,
    "coffee_order replay changed immutable proposal fields",
  );
  expect(
    replay.intent.initial_status === original.intent.initial_status &&
      replay.intent.status === original.intent.status &&
      replay.intent.required_approvals === original.intent.required_approvals &&
      replay.intent.approval_count === original.intent.approval_count,
    "coffee_order replay changed the human-review state",
  );
  expect(
    replay.intent.policy.allowed === original.intent.policy.allowed &&
      replay.intent.policy.rules_version === original.intent.policy.rules_version &&
      replay.intent.policy.config_digest === original.intent.policy.config_digest &&
      JSON.stringify(replay.intent.policy.reasons) === JSON.stringify(original.intent.policy.reasons),
    "coffee_order replay changed the policy snapshot",
  );
  expect(
    replay.intent.intent_hash === original.intent.intent_hash &&
      replay.intent.created_at === original.intent.created_at &&
      replay.intent.expires_at === original.intent.expires_at,
    "coffee_order replay changed immutable integrity fields",
  );
  expect(
    JSON.stringify(replay.intent.approvals) === JSON.stringify(original.intent.approvals),
    "coffee_order replay changed approval records",
  );
}

export async function runLiveAiNxtCoffeeProposalSmoke(
  adapter: ProposalSmokeAdapter,
  options: {
    runId: string;
    expectedControlPlaneSha: string;
    onProposalCreateAttempt?: (idempotencyKey: string) => void;
    onProposalCreated?: (intentId: string, idempotencyKey: string) => void;
  },
): Promise<LiveAiNxtCoffeeEvidence> {
  const idempotencyKey = liveAiNxtSmokeIdempotencyKeys(options.runId).coffee;
  const expectedControlPlaneSha = requireExpectedControlPlaneSha(
    options.expectedControlPlaneSha,
  );

  const coffeeRequest: AiNxtDraftRequest = {
    scenario: "coffee_order",
    idempotency_key: idempotencyKey,
  };
  const preflight = await adapter.simulateProposal(coffeeRequest);
  assertObservedControlPlaneSha(
    preflight.ainxt.control_plane_sha,
    expectedControlPlaneSha,
    "coffee_order preflight",
  );
  expect(preflight.simulation_persisted === false, "coffee_order preflight unexpectedly persisted");
  expect(preflight.moves_money === false, "coffee_order preflight crossed the no-money boundary");
  expect(preflight.simulation_policy.allowed === true, "coffee_order preflight was denied by policy");
  expect(
    preflight.simulation_policy.required_approvals === 1,
    "coffee_order preflight did not require exactly one human review",
  );

  options.onProposalCreateAttempt?.(idempotencyKey);
  const coffee = await adapter.createProposal(coffeeRequest);
  options.onProposalCreated?.(coffee.intent.id, idempotencyKey);
  assertObservedControlPlaneSha(
    coffee.ainxt.control_plane_sha,
    expectedControlPlaneSha,
    "coffee_order",
  );
  expect(
    JSON.stringify(coffee.draft) === JSON.stringify(preflight.draft),
    "coffee_order create changed the preflight-validated draft",
  );
  expect(
    JSON.stringify(coffee.simulation_policy) === JSON.stringify(preflight.simulation_policy),
    "coffee_order create changed the preflight policy snapshot",
  );
  expect(coffee.simulation_persisted === false, "coffee_order simulation unexpectedly persisted");
  expect(coffee.proposal_persisted === true, "coffee_order proposal was not persisted");
  expect(coffee.moves_money === false, "coffee_order crossed the no-money boundary");
  expect(
    coffee.intent.idempotent_replay !== true,
    "coffee_order first create unexpectedly returned an existing proposal",
  );
  expect(
    coffee.intent.initial_status === "AWAITING_APPROVAL" &&
      coffee.intent.status === "AWAITING_APPROVAL",
    "coffee_order did not remain in AWAITING_APPROVAL",
  );
  expect(coffee.intent.approval_count === 0, "coffee_order unexpectedly carried an approval");
  expect(coffee.intent.approvals.length === 0, "coffee_order unexpectedly carried approval records");
  expect(
    coffee.intent.required_approvals === 1,
    "coffee_order did not retain the pilot's single-human-review policy",
  );
  expect(
    coffee.intent.policy.allowed === coffee.simulation_policy.allowed &&
      coffee.intent.policy.rules_version === coffee.simulation_policy.rules_version &&
      coffee.intent.policy.config_digest === coffee.simulation_policy.config_digest &&
      JSON.stringify(coffee.intent.policy.reasons) ===
        JSON.stringify(coffee.simulation_policy.reasons),
    "coffee_order intent did not retain the validated policy snapshot",
  );

  const replay = await adapter.createProposal(coffeeRequest);
  assertObservedControlPlaneSha(
    replay.ainxt.control_plane_sha,
    expectedControlPlaneSha,
    "coffee_order replay",
  );
  expect(replay.moves_money === false, "coffee_order replay crossed the no-money boundary");
  expect(replay.simulation_persisted === false, "coffee_order replay simulation unexpectedly persisted");
  expect(replay.proposal_persisted === true, "coffee_order replay lost proposal persistence");
  assertReplayMatchesOriginal(coffee, replay);
  expect(
    replay.intent.idempotent_replay === true,
    "coffee_order replay was not marked as idempotent",
  );

  return {
    idempotency_key: idempotencyKey,
    intent_id: coffee.intent.id,
    status: "AWAITING_APPROVAL",
    approval_count: 0,
    required_approvals: 1,
    proposal_persisted: true,
    same_process_idempotent_replay: true,
    control_plane_sha: coffee.ainxt.control_plane_sha,
    moves_money: false,
  };
}

export async function runLiveAiNxtMobilityDenialSmoke(
  adapter: ProposalSmokeAdapter,
  options: { runId: string; expectedControlPlaneSha: string },
): Promise<LiveAiNxtMobilityEvidence> {
  const idempotencyKey = liveAiNxtSmokeIdempotencyKeys(options.runId).mobility;
  const expectedControlPlaneSha = requireExpectedControlPlaneSha(
    options.expectedControlPlaneSha,
  );

  // Deliberately simulation-only: no create call exists on this branch, so a
  // denied mobility fixture cannot leave even a non-actionable denial record.
  const mobility = await adapter.simulateProposal({
    scenario: "mobility_pass",
    idempotency_key: idempotencyKey,
  });
  assertObservedControlPlaneSha(
    mobility.ainxt.control_plane_sha,
    expectedControlPlaneSha,
    "mobility_pass",
  );
  expect(mobility.simulation_persisted === false, "mobility_pass simulation unexpectedly persisted");
  expect(mobility.moves_money === false, "mobility_pass crossed the no-money boundary");
  expect(mobility.simulation_policy.allowed === false, "mobility_pass was not denied by policy");
  expect(
    mobility.simulation_policy.reasons.includes("PER_TRANSACTION_LIMIT_EXCEEDED"),
    "mobility_pass did not fail the per-transaction ceiling",
  );
  expect(
    mobility.simulation_policy.reasons.includes("PAYEE_NOT_ALLOWLISTED"),
    "mobility_pass did not fail the payee allowlist",
  );

  return {
    idempotency_key: idempotencyKey,
    policy_allowed: false,
    policy_reasons: [...mobility.simulation_policy.reasons],
    simulation_persisted: false,
    creation_attempted: false,
    control_plane_sha: mobility.ainxt.control_plane_sha,
    moves_money: false,
  };
}

export function assembleLiveAiNxtKeycloakSmokeEvidence(
  expectedControlPlaneSha: string,
  coffee: LiveAiNxtCoffeeEvidence,
  mobility: LiveAiNxtMobilityEvidence,
): LiveAiNxtKeycloakSmokeEvidence {
  return {
    classification: LIVE_AINXT_KEYCLOAK_REPORT_CLASSIFICATION,
    expected_control_plane_sha: requireExpectedControlPlaneSha(expectedControlPlaneSha),
    interactive_humans: false,
    approvals_attempted: 0,
    payment_execution_capability: false,
    coffee_order: coffee,
    mobility_pass: mobility,
  };
}

export async function runLiveAiNxtKeycloakProposalSmoke(
  adapter: ProposalSmokeAdapter,
  options: { runId: string; expectedControlPlaneSha: string },
): Promise<LiveAiNxtKeycloakSmokeEvidence> {
  // Complete every non-persistent policy/model gate before the first create.
  // A failed mobility or coffee preflight therefore cannot leave a proposal.
  const mobility = await runLiveAiNxtMobilityDenialSmoke(adapter, options);
  const coffee = await runLiveAiNxtCoffeeProposalSmoke(adapter, options);
  return assembleLiveAiNxtKeycloakSmokeEvidence(
    options.expectedControlPlaneSha,
    coffee,
    mobility,
  );
}
