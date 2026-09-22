import {
  AINXT_SYNTHETIC_SCENARIOS,
  AiNxtParimitAdapter,
  type AiNxtSyntheticScenario,
} from "../integrations/ainxt/adapter.ts";

const accessToken = process.env.PARIMIT_AGENT_ACCESS_TOKEN;
const scenario = process.env.PARIMIT_AINXT_SCENARIO ?? "coffee_order";
const idempotencyKey = process.env.PARIMIT_AINXT_IDEMPOTENCY_KEY;

if (!accessToken || !idempotencyKey) {
  throw new Error(
    "PARIMIT_AGENT_ACCESS_TOKEN and PARIMIT_AINXT_IDEMPOTENCY_KEY are required",
  );
}
if (!AINXT_SYNTHETIC_SCENARIOS.includes(scenario as AiNxtSyntheticScenario)) {
  throw new Error(
    `PARIMIT_AINXT_SCENARIO must be one of: ${AINXT_SYNTHETIC_SCENARIOS.join(", ")}`,
  );
}

const adapter = new AiNxtParimitAdapter({
  ainxtBaseUrl: process.env.AINXT_URL ?? "http://127.0.0.1:8080",
  parimitBaseUrl: process.env.PARIMIT_URL ?? "http://127.0.0.1:8787",
  accessToken,
  ...(process.env.AINXT_DEPARTMENT === undefined
    ? {}
    : { ainxtDepartment: process.env.AINXT_DEPARTMENT }),
});

const request = {
  scenario: scenario as AiNxtSyntheticScenario,
  idempotency_key: idempotencyKey,
};
const result = await adapter.createProposal(request);
const replay = await adapter.createProposal(request);

console.log(
  JSON.stringify(
    {
      intent_id: result.intent.id,
      status: result.intent.status,
      scenario,
      simulation_policy_allowed: result.simulation_policy.allowed,
      required_approvals: result.simulation_policy.required_approvals,
      replay_intent_id: replay.intent.id,
      same_process_idempotent_replay: replay.intent.idempotent_replay === true,
      ainxt_reviewed_source_commit: result.ainxt.reviewed_source_commit,
      ainxt_control_plane_sha: result.ainxt.control_plane_sha,
      moves_money: false,
      notice: "The AiNxt agent drafted a proposal only. Human review remains separate.",
    },
    null,
    2,
  ),
);
