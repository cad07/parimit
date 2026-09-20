import { randomUUID } from "node:crypto";

import { createAgentClient } from "../sdk/typescript/src/index.ts";

const baseUrl = process.env.PARIMIT_BASE_URL;
const accessToken = process.env.PARIMIT_ACCESS_TOKEN;

if (!baseUrl || !accessToken) {
  throw new Error(
    "PARIMIT_BASE_URL and a short-lived PARIMIT_ACCESS_TOKEN are required for the pilot client",
  );
}

const client = createAgentClient({ baseUrl, identity: { accessToken } });
const safety = await client.safety();

if (safety.mode !== "PROPOSAL_ONLY" || safety.moves_money !== false) {
  throw new Error("Refusing to continue: the server did not advertise the proposal-only boundary");
}

const actor = await client.identity();
if (actor.actor_role !== "agent") {
  throw new Error(`Expected an agent access token, received ${actor.actor_role}`);
}

const proposal = {
  idempotency_key: randomUUID(),
  requested_by: { type: "agent" as const, id: actor.actor_id },
  amount: { currency: "INR" as const, minor: "49900" },
  payee_reference: "merchant_pilot_001",
  purpose: "Fictional pilot purchase",
};

const policy = await client.simulateProposal(proposal);
console.log("Policy preview:", policy.policy);

const created = await client.createProposal(proposal);
console.log("Proposal:", created.id, created.status);
console.log("No payment was sent; human review is separate.");
