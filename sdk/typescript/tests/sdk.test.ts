import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentClient,
  createEnvelopeConsumerClient,
  createOperatorClient,
  createReviewerClient,
  ParimitApiError,
} from "../src/index.ts";

function response(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("role-shaped clients do not expose approval or execution to agents", () => {
  const fetch = async () => response({ data: {} });
  const identity = { demoIdentity: { actorId: "agent-sdk", role: "agent" as const } };
  const agent = createAgentClient({ baseUrl: "http://127.0.0.1:8787", identity, fetch });
  assert.equal("approveProposal" in agent, false);
  assert.equal("rejectProposal" in agent, false);
  assert.equal("issueEvidenceEnvelope" in agent, false);
  assert.equal("verifyEvidenceEnvelope" in agent, false);
  assert.equal("consumeEvidenceEnvelope" in agent, false);
  assert.equal("recordMockObservation" in agent, false);
  assert.equal(Object.keys(agent).some((name) => /pay|execute|send|dispatch/i.test(name)), false);
});

test("agent client encodes paths, identity, and proposal bodies", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit) => {
    requests.push({ url: String(input), init });
    return response({ data: { id: "intent-sdk", status: "AWAITING_APPROVAL" } });
  };
  const agent = createAgentClient({
    baseUrl: "http://localhost:8787/",
    identity: { accessToken: "test-token" },
    fetch: fetch as typeof globalThis.fetch,
  });
  await agent.identity();
  await agent.createProposal({
    idempotency_key: "sdk-1",
    requested_by: { type: "agent", id: "agent-sdk" },
    amount: { currency: "INR", minor: "49900" },
    payee_reference: "merchant_sdk_001",
    purpose: "SDK test",
  });
  assert.equal(requests[0]?.url, "http://localhost:8787/v1/identity");
  assert.equal(requests[1]?.url, "http://localhost:8787/v1/intents");
  const headers = new Headers(requests[1]?.init?.headers);
  assert.equal(headers.get("authorization"), "Bearer test-token");
  assert.equal(headers.get("x-parimit-actor"), null);
  assert.equal(requests[1]?.init?.method, "POST");
});

test("reviewer, consumer, and operator capabilities remain separate", () => {
  const fetch = async () => response({ data: {} });
  const reviewer = createReviewerClient({
    baseUrl: "https://sandbox.parimit.invalid",
    identity: { demoIdentity: { actorId: "human-sdk", role: "approver" } },
    fetch,
  });
  const operator = createOperatorClient({
    baseUrl: "https://sandbox.parimit.invalid",
    identity: { demoIdentity: { actorId: "admin-sdk", role: "admin" } },
    fetch,
  });
  const consumer = createEnvelopeConsumerClient({
    baseUrl: "https://sandbox.parimit.invalid",
    identity: { demoIdentity: { actorId: "consumer-sdk", role: "consumer" } },
    fetch,
  });
  assert.equal(typeof reviewer.approveProposal, "function");
  assert.equal(typeof reviewer.issueEvidenceEnvelope, "function");
  assert.equal(typeof reviewer.verifyEvidenceEnvelope, "function");
  assert.equal("consumeEvidenceEnvelope" in reviewer, false);
  assert.equal("recordMockObservation" in reviewer, false);
  assert.equal(typeof consumer.verifyEvidenceEnvelope, "function");
  assert.equal(typeof consumer.consumeEvidenceEnvelope, "function");
  assert.equal("getIntent" in consumer, false);
  assert.equal("listIntents" in consumer, false);
  assert.equal("issueEvidenceEnvelope" in consumer, false);
  assert.equal(typeof operator.recordMockObservation, "function");
  assert.equal("approveProposal" in operator, false);
  assert.equal(typeof operator.issueEvidenceEnvelope, "function");
  assert.equal(typeof operator.consumeEvidenceEnvelope, "function");
});

test("envelope clients use direct JWKS and role-appropriate evidence routes", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, init });
    if (url.endsWith("/.well-known/jwks.json")) {
      return response({ keys: [{ kty: "OKP", kid: "test-key" }] });
    }
    return response({ data: { valid: true } });
  };
  const reviewer = createReviewerClient({
    baseUrl: "https://sandbox.parimit.invalid",
    identity: { accessToken: "reviewer-token" },
    fetch: fetch as typeof globalThis.fetch,
  });
  const consumer = createEnvelopeConsumerClient({
    baseUrl: "https://sandbox.parimit.invalid",
    identity: { accessToken: "consumer-token" },
    fetch: fetch as typeof globalThis.fetch,
  });

  const jwks = await consumer.getEnvelopeKeys();
  assert.equal(jwks.keys[0]?.kid, "test-key");
  await reviewer.issueEvidenceEnvelope("intent/with space", {
    audience: "urn:consumer:test",
    idempotency_key: "issue-001",
  });
  await reviewer.verifyEvidenceEnvelope("header.payload.signature", "urn:consumer:test");
  await consumer.consumeEvidenceEnvelope(
    "header.payload.signature",
    "urn:consumer:test",
    "consume-001",
  );

  assert.deepEqual(
    requests.map((request) => request.url),
    [
      "https://sandbox.parimit.invalid/.well-known/jwks.json",
      "https://sandbox.parimit.invalid/v1/intents/intent%2Fwith%20space/evidence-envelopes",
      "https://sandbox.parimit.invalid/v1/evidence-envelopes/verify",
      "https://sandbox.parimit.invalid/v1/evidence-envelopes/consume",
    ],
  );
  assert.deepEqual(JSON.parse(String(requests[1]?.init?.body)), {
    audience: "urn:consumer:test",
    idempotency_key: "issue-001",
  });
  assert.deepEqual(JSON.parse(String(requests[3]?.init?.body)), {
    compact_jws: "header.payload.signature",
    audience: "urn:consumer:test",
    idempotency_key: "consume-001",
  });
});

test("API errors preserve status, code, message, and details", async () => {
  const agent = createAgentClient({
    baseUrl: "http://127.0.0.1:8787",
    identity: { demoIdentity: { actorId: "agent-sdk", role: "agent" } },
    fetch: async () =>
      response(
        { error: { code: "FORBIDDEN", message: "not allowed", details: { reason: "scope" } } },
        403,
      ),
  });
  await assert.rejects(
    () => agent.getIntent("intent-sdk"),
    (error: unknown) =>
      error instanceof ParimitApiError &&
      error.status === 403 &&
      error.code === "FORBIDDEN" &&
      error.message === "not allowed",
  );
});

test("non-loopback HTTP base URLs are rejected", () => {
  assert.throws(
    () =>
      createAgentClient({
        baseUrl: "http://sandbox.example.com",
        identity: { accessToken: "token" },
      }),
    /requires HTTPS/,
  );
  assert.throws(
    () =>
      createAgentClient({
        baseUrl: "ftp://localhost/parimit",
        identity: { accessToken: "token" },
      }),
    /requires HTTPS/,
  );
  assert.throws(
    () =>
      createAgentClient({
        baseUrl: "https://user:secret@sandbox.example.com?tenant=a",
        identity: { accessToken: "token" },
      }),
    /cannot contain credentials/,
  );
  assert.doesNotThrow(() =>
    createAgentClient({
      baseUrl: "http://[::1]:8787",
      identity: { accessToken: "token" },
    }),
  );
});
