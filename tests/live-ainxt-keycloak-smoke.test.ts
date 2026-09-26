import assert from "node:assert/strict";
import test from "node:test";

import type {
  AiNxtCreationResult,
  AiNxtDraftRequest,
  AiNxtSimulationResult,
} from "../integrations/ainxt/adapter.ts";
import {
  LIVE_AINXT_KEYCLOAK_REPORT_CLASSIFICATION,
  requireExpectedControlPlaneSha,
  requireLoopbackOnlyAiNxtBindings,
  runLiveAiNxtCoffeeProposalSmoke,
  runLiveAiNxtKeycloakProposalSmoke,
} from "../scripts/run-live-ainxt-keycloak-smoke.ts";

const CONTROL_PLANE_SHA = "a".repeat(64);
const ACTOR_ID = `oidc:${"b".repeat(64)}`;

test("AiNxt listener evidence accepts only loopback bindings", () => {
  assert.deepEqual(
    requireLoopbackOnlyAiNxtBindings("darwin", "p123\nn127.0.0.1:8080\n"),
    ["127.0.0.1:8080"],
  );
  assert.deepEqual(
    requireLoopbackOnlyAiNxtBindings(
      "linux",
      "LISTEN 0 4096 [::1]:8080 [::]:*\n",
    ),
    ["[::1]:8080"],
  );
  assert.throws(
    () => requireLoopbackOnlyAiNxtBindings("darwin", "p123\nn*:8080\n"),
    /not bound exclusively to loopback/u,
  );
  assert.throws(
    () => requireLoopbackOnlyAiNxtBindings("linux", ""),
    /No AiNxt listener was found/u,
  );
});

function coffeeResult(replay: boolean, controlPlaneSha = CONTROL_PLANE_SHA): AiNxtCreationResult {
  return {
    draft: {
      amount: { currency: "INR", minor: "49900" },
      payee_reference: "demo-coffee-merchant",
      purpose: "Synthetic order DEMO-COFFEE-001",
      on_behalf_of: "demo-customer-1",
      expires_in_seconds: 300,
    },
    simulation_policy: {
      allowed: true,
      reasons: ["HUMAN_APPROVAL_REQUIRED"],
      rules_version: "pilot-v1",
      config_digest: "config-digest",
      required_approvals: 1,
      current_daily_exposure_minor: "0",
      projected_daily_exposure_minor: "49900",
    },
    simulation_persisted: false,
    moves_money: false,
    ainxt: {
      reviewed_source_commit: "454fb09cf1fff2bedb5aa3f4f1c391e4915f33dd",
      control_plane_sha: controlPlaneSha,
      transport: "POST /v1/chat (SSE)",
    },
    intent: {
      id: "intent-coffee-1",
      intent_version: "parimit-payment-intent-v3",
      tenant_id: "parimit-pilot-local",
      state_version: 1,
      initial_status: "AWAITING_APPROVAL",
      idempotency_key: "filled-by-fake",
      requested_by: { type: "agent", id: ACTOR_ID },
      on_behalf_of: "demo-customer-1",
      amount: { currency: "INR", minor: "49900" },
      payee_reference: "demo-coffee-merchant",
      purpose: "Synthetic order DEMO-COFFEE-001",
      status: "AWAITING_APPROVAL",
      required_approvals: 1,
      approval_count: 0,
      policy: {
        allowed: true,
        reasons: ["HUMAN_APPROVAL_REQUIRED"],
        rules_version: "pilot-v1",
        config_digest: "config-digest",
      },
      intent_hash: "intent-hash",
      created_at: "2026-09-27T00:00:00.000Z",
      expires_at: "2026-09-27T00:05:00.000Z",
      approvals: [],
      ...(replay ? { idempotent_replay: true } : {}),
    },
    proposal_persisted: true,
  };
}

function mobilityResult(
  allowed = false,
  controlPlaneSha = CONTROL_PLANE_SHA,
): AiNxtSimulationResult {
  return {
    draft: {
      amount: { currency: "INR", minor: "125000" },
      payee_reference: "demo-mobility-pass",
      purpose: "Synthetic mobility evaluation",
      on_behalf_of: "demo-customer-1",
      expires_in_seconds: 300,
    },
    simulation_policy: {
      allowed,
      reasons: allowed
        ? ["DISTINCT_DUAL_APPROVAL_REQUIRED"]
        : [
            "PER_TRANSACTION_LIMIT_EXCEEDED",
            "PAYEE_NOT_ALLOWLISTED",
            "DISTINCT_DUAL_APPROVAL_REQUIRED",
          ],
      rules_version: "pilot-v1",
      config_digest: "config-digest",
      required_approvals: 2,
      current_daily_exposure_minor: "49900",
      projected_daily_exposure_minor: "174900",
    },
    simulation_persisted: false,
    moves_money: false,
    ainxt: {
      reviewed_source_commit: "454fb09cf1fff2bedb5aa3f4f1c391e4915f33dd",
      control_plane_sha: controlPlaneSha,
      transport: "POST /v1/chat (SSE)",
    },
  };
}

function coffeeSimulationResult(controlPlaneSha = CONTROL_PLANE_SHA): AiNxtSimulationResult {
  const result = coffeeResult(false, controlPlaneSha);
  return {
    draft: result.draft,
    simulation_policy: result.simulation_policy,
    simulation_persisted: false,
    moves_money: false,
    ainxt: result.ainxt,
  };
}

class FakeAdapter {
  readonly createRequests: AiNxtDraftRequest[] = [];
  readonly simulateRequests: AiNxtDraftRequest[] = [];
  readonly #controlPlaneSha: string;
  readonly #mobilityAllowed: boolean;
  readonly #replayDrift: boolean;

  constructor(
    options: {
      controlPlaneSha?: string;
      mobilityAllowed?: boolean;
      replayDrift?: boolean;
    } = {},
  ) {
    this.#controlPlaneSha = options.controlPlaneSha ?? CONTROL_PLANE_SHA;
    this.#mobilityAllowed = options.mobilityAllowed ?? false;
    this.#replayDrift = options.replayDrift ?? false;
  }

  async createProposal(request: AiNxtDraftRequest): Promise<AiNxtCreationResult> {
    this.createRequests.push(request);
    assert.equal(request.scenario, "coffee_order", "mobility must never reach proposal creation");
    const result = coffeeResult(this.createRequests.length === 2, this.#controlPlaneSha);
    result.intent.idempotency_key = request.idempotency_key;
    if (this.createRequests.length === 2 && this.#replayDrift) {
      result.intent.purpose = "Synthetic replay drift";
    }
    return result;
  }

  async simulateProposal(request: AiNxtDraftRequest): Promise<AiNxtSimulationResult> {
    this.simulateRequests.push(request);
    return request.scenario === "coffee_order"
      ? coffeeSimulationResult(this.#controlPlaneSha)
      : mobilityResult(this.#mobilityAllowed, this.#controlPlaneSha);
  }
}

test("live AiNxt Keycloak smoke creates/replays coffee and only simulates denied mobility", async () => {
  const adapter = new FakeAdapter();
  const evidence = await runLiveAiNxtKeycloakProposalSmoke(adapter, {
    runId: "pilot-run-001",
    expectedControlPlaneSha: CONTROL_PLANE_SHA,
  });

  assert.equal(evidence.classification, LIVE_AINXT_KEYCLOAK_REPORT_CLASSIFICATION);
  assert.equal(evidence.interactive_humans, false);
  assert.equal(evidence.approvals_attempted, 0);
  assert.equal(evidence.payment_execution_capability, false);
  assert.equal(evidence.coffee_order.status, "AWAITING_APPROVAL");
  assert.equal(evidence.coffee_order.approval_count, 0);
  assert.equal(evidence.coffee_order.same_process_idempotent_replay, true);
  assert.equal(evidence.mobility_pass.policy_allowed, false);
  assert.equal(evidence.mobility_pass.simulation_persisted, false);
  assert.equal(evidence.mobility_pass.creation_attempted, false);
  assert.deepEqual(adapter.createRequests.map((request) => request.scenario), [
    "coffee_order",
    "coffee_order",
  ]);
  assert.deepEqual(adapter.simulateRequests.map((request) => request.scenario), [
    "mobility_pass",
    "coffee_order",
  ]);
});

test("live AiNxt Keycloak smoke rejects unpinned and mismatched control-plane values", async () => {
  assert.throws(
    () => requireExpectedControlPlaneSha("unpinned"),
    /exactly 64 lowercase hexadecimal characters/u,
  );
  assert.throws(
    () => requireExpectedControlPlaneSha("A".repeat(64)),
    /exactly 64 lowercase hexadecimal characters/u,
  );
  const adapter = new FakeAdapter({ controlPlaneSha: "c".repeat(64) });
  let createAttempted = false;
  await assert.rejects(
    runLiveAiNxtCoffeeProposalSmoke(adapter, {
      runId: "pilot-run-002",
      expectedControlPlaneSha: CONTROL_PLANE_SHA,
      onProposalCreateAttempt: () => {
        createAttempted = true;
      },
    }),
    /unexpected AiNxt control-plane SHA/u,
  );
  assert.equal(createAttempted, false, "a pin mismatch must fail before the create attempt");
  assert.equal(adapter.createRequests.length, 0, "a pin mismatch must fail before create");
});

test("live AiNxt Keycloak smoke fails if the mobility fixture is not denied", async () => {
  const adapter = new FakeAdapter({ mobilityAllowed: true });
  await assert.rejects(
    runLiveAiNxtKeycloakProposalSmoke(adapter, {
      runId: "pilot-run-003",
      expectedControlPlaneSha: CONTROL_PLANE_SHA,
    }),
    /mobility_pass was not denied by policy/u,
  );
  assert.equal(adapter.createRequests.length, 0);
  assert.equal(adapter.simulateRequests.length, 1);
});

test("live AiNxt Keycloak smoke rejects replay drift after preserving the first proposal id", async () => {
  const adapter = new FakeAdapter({ replayDrift: true });
  let createdIntent: string | undefined;
  let createAttempted = false;
  await assert.rejects(
    runLiveAiNxtCoffeeProposalSmoke(adapter, {
      runId: "pilot-run-004",
      expectedControlPlaneSha: CONTROL_PLANE_SHA,
      onProposalCreateAttempt: () => {
        createAttempted = true;
      },
      onProposalCreated: (intentId) => {
        createdIntent = intentId;
      },
    }),
    /replay changed immutable proposal fields/u,
  );
  assert.equal(createAttempted, true);
  assert.equal(createdIntent, "intent-coffee-1");
  assert.equal(adapter.createRequests.length, 2);
  assert.deepEqual(adapter.simulateRequests.map((request) => request.scenario), [
    "coffee_order",
  ]);
});
