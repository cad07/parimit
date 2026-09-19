import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { createHttpHandler } from "../src/http.ts";
import { callMcpTool, handleMcpRequest, MCP_TOOLS } from "../src/mcp.ts";
import { createServiceFromEnvironment, ParimitService } from "../src/service.ts";

function proposal(idempotencyKey: string, amountMinor = "100") {
  return {
    idempotency_key: idempotencyKey,
    requested_by: { type: "agent", id: "agent-http" },
    amount: { currency: "INR", minor: amountMinor },
    payee_reference: "merchant_demo_001",
    purpose: "HTTP test",
    expires_in_seconds: 60,
  };
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

test("HTTP API is end-to-end proposal-only with demo human approval and audit verification", async (t) => {
  const service = new ParimitService({ receiptSecret: "http-test-secret" });
  const server = createServer(createHttpHandler(service));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    service.close();
  });
  const address = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${address.port}`;

  const safetyResponse = await fetch(`${base}/v1/safety`);
  assert.equal(safetyResponse.status, 200);
  const safety = ((await json(safetyResponse)).data ?? {}) as Record<string, unknown>;
  assert.equal(safety.name, "Parimit");
  assert.equal(safety.mode, "PROPOSAL_ONLY");
  assert.equal(safety.moves_money, false);
  assert.deepEqual(safety.execution_routes, []);

  const createResponse = await fetch(`${base}/v1/intents`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(proposal("http-create")),
  });
  assert.equal(createResponse.status, 201);
  const created = (await json(createResponse)).data as Record<string, unknown>;
  assert.equal(created.status, "AWAITING_APPROVAL");
  const id = created.id as string;

  const agentApproval = await fetch(`${base}/v1/intents/${id}/approvals`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-parimit-actor": "agent-http",
      "x-parimit-role": "agent",
    },
    body: JSON.stringify({ decision: "APPROVE" }),
  });
  assert.equal(agentApproval.status, 403);

  const approvalResponse = await fetch(`${base}/v1/intents/${id}/approvals`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-parimit-actor": "human-http",
      "x-parimit-role": "approver",
    },
    body: JSON.stringify({ decision: "APPROVE" }),
  });
  assert.equal(approvalResponse.status, 200);
  const authorized = (await json(approvalResponse)).data as Record<string, unknown>;
  assert.equal(authorized.status, "AUTHORIZED_NO_DISPATCH");

  const mockResponse = await fetch(`${base}/v1/demo/intents/${id}/observations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status: "IN_DOUBT", provider_reference: "demo-only" }),
  });
  assert.equal(mockResponse.status, 200);
  const mockPayload = await json(mockResponse);
  assert.match(String(mockPayload.warning), /no funds moved/i);

  const postUncertaintyResponse = await fetch(`${base}/v1/demo/intents/${id}/observations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status: "SUCCEEDED", provider_reference: "not-accepted" }),
  });
  assert.equal(postUncertaintyResponse.status, 409);
  const postUncertaintyPayload = await json(postUncertaintyResponse);
  assert.equal(
    (postUncertaintyPayload.error as Record<string, unknown>).code,
    "IN_DOUBT_FROZEN",
  );

  const auditVerify = await fetch(`${base}/v1/intents/${id}/audit/verify`);
  assert.equal(auditVerify.status, 200);
  assert.equal(((await json(auditVerify)).data as Record<string, unknown>).valid, true);

  for (const path of [
    "/v1/pay",
    "/v1/execute",
    `/v1/intents/${id}/execute`,
    `/v1/intents/${id}/send`,
    `/v1/intents/${id}/retry`,
  ]) {
    const response = await fetch(`${base}${path}`, { method: "POST" });
    assert.equal(response.status, 404, `unsafe path should not exist: ${path}`);
  }
});

test("all HTTP failures use the consistent error envelope", async (t) => {
  const service = new ParimitService({ receiptSecret: "http-test-secret" });
  const server = createServer(createHttpHandler(service));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    service.close();
  });
  const address = server.address() as AddressInfo;
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/intents`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{not-json",
  });
  assert.equal(response.status, 400);
  const payload = await json(response);
  assert.deepEqual(Object.keys(payload), ["error"]);
  assert.deepEqual(Object.keys(payload.error as Record<string, unknown>), ["code", "message"]);

  const oversizedLimit = await fetch(
    `http://127.0.0.1:${address.port}/v1/intents?limit=201`,
  );
  assert.equal(oversizedLimit.status, 400);
  assert.equal(
    ((await json(oversizedLimit)).error as Record<string, unknown>).code,
    "VALIDATION_ERROR",
  );
});

test("MCP exposes proposal/status/policy/cancel/mock/audit tools but no approval or execution tool", async (t) => {
  const service = new ParimitService({ receiptSecret: "mcp-test-secret" });
  t.after(() => service.close());
  const names = MCP_TOOLS.map((tool) => tool.name);
  assert.deepEqual(names, [
    "create_payment_proposal",
    "get_payment_status",
    "cancel_payment_proposal",
    "get_policy_decision",
    "simulate_payment",
    "get_payment_audit",
  ]);
  assert.equal(names.some((name) => /approve|authori[sz]e|execute|send|retry/i.test(name)), false);

  const created = callMcpTool(service, "create_payment_proposal", proposal("mcp-create")) as Record<
    string,
    unknown
  >;
  assert.equal(created.status, "AWAITING_APPROVAL");
  const fetched = callMcpTool(service, "get_payment_status", { intent_id: created.id }) as Record<
    string,
    unknown
  >;
  assert.equal(fetched.id, created.id);

  const list = await handleMcpRequest(service, {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
  });
  assert.equal((list as Record<string, unknown>).jsonrpc, "2.0");

  const initialized = await handleMcpRequest(service, {
    jsonrpc: "2.0",
    id: 2,
    method: "initialize",
  });
  const initializeResult = (initialized?.result ?? {}) as Record<string, unknown>;
  assert.deepEqual(initializeResult.serverInfo, {
    name: "parimit",
    version: "0.1.0-alpha.0",
  });
});

test("environment config accepts canonical names and refuses non-demo startup", (t) => {
  const service = createServiceFromEnvironment({
    PARIMIT_DB_PATH: ":memory:",
    PARIMIT_DEMO_MODE: "true",
    PARIMIT_RECEIPT_KEY: "canonical-test-key",
    PARIMIT_PER_TX_LIMIT: "900",
    PARIMIT_DAILY_AGENT_LIMIT: "1800",
    PARIMIT_DUAL_APPROVAL_THRESHOLD: "600",
    PARIMIT_INTENT_TTL_SECONDS: "120",
    PARIMIT_MAX_EXPIRY_SECONDS: "240",
    PARIMIT_ALLOWED_PAYEES: "",
  });
  t.after(() => service.close());
  assert.equal(service.policy.perTransactionLimitMinor, 900);
  assert.equal(service.policy.dailyAgentLimitMinor, 1800);
  assert.equal(service.policy.dualApprovalThresholdMinor, 600);
  assert.equal(service.policy.defaultExpirySeconds, 120);
  assert.equal(service.policy.maxExpirySeconds, 240);
  assert.equal(service.policy.allowedPayees, null);
  assert.throws(
    () => createServiceFromEnvironment({ PARIMIT_DEMO_MODE: "false", PARIMIT_DB_PATH: ":memory:" }),
    /refuses to start outside demo mode/,
  );
});
