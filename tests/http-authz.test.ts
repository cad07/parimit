import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import {
  LocalDemoHeaderIdentityProvider,
  type AuthenticatedActor,
  type AuthenticationHeaders,
  type IdentityProvider,
} from "../src/auth.ts";
import { ParimitError } from "../src/errors.ts";
import { createHttpHandler } from "../src/http.ts";
import { ParimitService } from "../src/service.ts";

const TEST_OIDC_TRUST_DOMAIN_ID = `sha256:${"a".repeat(64)}`;

const identities: Readonly<Record<string, AuthenticatedActor>> = {
  "Bearer agent-a": {
    actorId: "oidc:agent-a",
    actorRole: "agent",
    subject: "agent-a",
    issuer: "https://identity.example.test",
    authenticationMethod: "oidc",
  },
  "Bearer agent-b": {
    actorId: "oidc:agent-b",
    actorRole: "agent",
    subject: "agent-b",
    issuer: "https://identity.example.test",
    authenticationMethod: "oidc",
  },
  "Bearer reviewer": {
    actorId: "oidc:reviewer",
    actorRole: "approver",
    subject: "reviewer",
    issuer: "https://identity.example.test",
    authenticationMethod: "oidc",
  },
  "Bearer consumer": {
    actorId: "oidc:consumer",
    actorRole: "consumer",
    subject: "consumer",
    issuer: "https://identity.example.test",
    authenticationMethod: "oidc",
  },
  "Bearer operator": {
    actorId: "oidc:operator",
    actorRole: "admin",
    subject: "operator",
    issuer: "https://identity.example.test",
    authenticationMethod: "oidc",
  },
};

const identityProvider: IdentityProvider = {
  authenticationMethod: "oidc",
  identityTrustDomainId: TEST_OIDC_TRUST_DOMAIN_ID,
  async authenticate(headers: AuthenticationHeaders): Promise<AuthenticatedActor> {
    const authorization = headers.authorization;
    if (typeof authorization !== "string" || identities[authorization] === undefined) {
      throw new ParimitError("AUTHENTICATION_REQUIRED", "Bearer token required", 401);
    }
    return identities[authorization]!;
  },
};

function headers(token: string, json = false): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
    ...(json ? { "content-type": "application/json" } : {}),
  };
}

function proposal(agentId: string, key: string) {
  return {
    idempotency_key: key,
    requested_by: { type: "agent", id: agentId },
    amount: { currency: "INR", minor: "49900" },
    payee_reference: "merchant_authz_001",
    purpose: "OIDC authorization boundary test",
  };
}

test("HTTP handlers require an explicit matching identity provider", (t) => {
  assert.throws(
    () => new ParimitService({ authenticationMode: "oidc" }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "INVALID_CONFIGURATION" &&
      error.statusCode === 500,
  );
  const service = new ParimitService({
    receiptSecret: "http-handler-auth-config-test-secret-at-least-32-bytes",
    authenticationMode: "oidc",
    identityTrustDomainId: TEST_OIDC_TRUST_DOMAIN_ID,
  });
  t.after(() => service.close());
  assert.throws(
    () => createHttpHandler(service),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "INVALID_AUTH_CONFIGURATION" &&
      error.statusCode === 500,
  );
  assert.throws(
    () =>
      createHttpHandler(service, {
        identityProvider: {
          ...identityProvider,
          identityTrustDomainId: `sha256:${"b".repeat(64)}`,
        },
      }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "INVALID_AUTH_CONFIGURATION" &&
      error.statusCode === 500,
  );
  assert.throws(
    () =>
      createHttpHandler(service, {
        identityProvider: new LocalDemoHeaderIdentityProvider({
          demoMode: true,
          host: "127.0.0.1",
        }),
      }),
    (error: unknown) =>
      error instanceof ParimitError &&
      error.code === "INVALID_AUTH_CONFIGURATION" &&
      error.statusCode === 500,
  );
});

async function payload(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

test("HTTP identity and RBAC isolate agents, reviewers, and mock operators", async (t) => {
  const service = new ParimitService({
    receiptSecret: "http-authz-test-secret-at-least-32-bytes",
    authenticationMode: "oidc",
    identityTrustDomainId: TEST_OIDC_TRUST_DOMAIN_ID,
  });
  const server = createServer(createHttpHandler(service, { identityProvider }));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    service.close();
  });
  const address = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${address.port}`;

  const unauthenticated = await fetch(`${base}/v1/identity`);
  assert.equal(unauthenticated.status, 401);

  const identityResponse = await fetch(`${base}/v1/identity`, {
    headers: headers("agent-a"),
  });
  assert.equal(identityResponse.status, 200);
  const identityEnvelope = await payload(identityResponse);
  assert.deepEqual(identityEnvelope.data, {
    actor_id: "oidc:agent-a",
    actor_role: "agent",
    authentication_method: "oidc",
    issuer: "https://identity.example.test",
  });
  assert.equal("warning" in identityEnvelope, false);

  const mismatch = await fetch(`${base}/v1/intents`, {
    method: "POST",
    headers: headers("agent-a", true),
    body: JSON.stringify(proposal("oidc:agent-b", "authz-mismatch")),
  });
  assert.equal(mismatch.status, 403);
  assert.equal(
    ((await payload(mismatch)).error as Record<string, unknown>).code,
    "ACTOR_IDENTITY_MISMATCH",
  );

  const createdResponse = await fetch(`${base}/v1/intents`, {
    method: "POST",
    headers: headers("agent-a", true),
    body: JSON.stringify(proposal("oidc:agent-a", "authz-create")),
  });
  assert.equal(createdResponse.status, 201);
  const created = (await payload(createdResponse)).data as Record<string, unknown>;
  const id = String(created.id);

  const otherAgentRead = await fetch(`${base}/v1/intents/${id}`, {
    headers: headers("agent-b"),
  });
  assert.equal(otherAgentRead.status, 404);

  const otherAgentVerification = await fetch(`${base}/v1/intents/${id}/audit/verify`, {
    headers: headers("agent-b"),
  });
  assert.equal(otherAgentVerification.status, 404);

  const otherAgentCancel = await fetch(`${base}/v1/intents/${id}/cancel`, {
    method: "POST",
    headers: headers("agent-b"),
  });
  assert.equal(otherAgentCancel.status, 404);

  const otherAgentList = await fetch(`${base}/v1/intents`, {
    headers: headers("agent-b"),
  });
  assert.deepEqual((await payload(otherAgentList)).data, []);

  const reviewerList = await fetch(`${base}/v1/intents`, {
    headers: headers("reviewer"),
  });
  assert.equal(((await payload(reviewerList)).data as unknown[]).length, 1);

  const reviewerCreate = await fetch(`${base}/v1/intents`, {
    method: "POST",
    headers: headers("reviewer", true),
    body: JSON.stringify(proposal("oidc:reviewer", "reviewer-create")),
  });
  assert.equal(reviewerCreate.status, 403);

  const agentObservation = await fetch(`${base}/v1/demo/intents/${id}/observations`, {
    method: "POST",
    headers: headers("agent-a", true),
    body: JSON.stringify({ status: "SUCCEEDED" }),
  });
  assert.equal(agentObservation.status, 403);

  const approvedResponse = await fetch(`${base}/v1/intents/${id}/approvals`, {
    method: "POST",
    headers: headers("reviewer", true),
    body: JSON.stringify({ decision: "APPROVE" }),
  });
  assert.equal(approvedResponse.status, 200);
  assert.equal(((await payload(approvedResponse)).data as Record<string, unknown>).status, "AUTHORIZED_NO_DISPATCH");

  const publicKeysResponse = await fetch(`${base}/.well-known/jwks.json`);
  assert.equal(publicKeysResponse.status, 200);
  const publicKeys = (await payload(publicKeysResponse)).keys as Array<Record<string, unknown>>;
  assert.equal(publicKeys.length, 1);
  assert.equal(publicKeys[0]?.kty, "OKP");
  assert.equal("d" in publicKeys[0]!, false);

  const agentIssue = await fetch(`${base}/v1/intents/${id}/evidence-envelopes`, {
    method: "POST",
    headers: headers("agent-a", true),
    body: JSON.stringify({
      audience: "urn:parimit:consumer:local-demo",
      idempotency_key: "agent-must-not-issue",
    }),
  });
  assert.equal(agentIssue.status, 403);

  const consumerList = await fetch(`${base}/v1/intents`, {
    headers: headers("consumer"),
  });
  assert.equal(consumerList.status, 403);

  const issueResponse = await fetch(`${base}/v1/intents/${id}/evidence-envelopes`, {
    method: "POST",
    headers: headers("reviewer", true),
    body: JSON.stringify({
      audience: "urn:parimit:consumer:local-demo",
      idempotency_key: "http-envelope-issue",
      expires_in_seconds: 120,
    }),
  });
  assert.equal(issueResponse.status, 201);
  const envelope = (await payload(issueResponse)).data as Record<string, unknown>;
  assert.equal(envelope.execution_authorized, false);
  assert.equal(envelope.moves_money, false);
  const compactJws = String(envelope.compact_jws);

  const missingAudience = await fetch(`${base}/v1/evidence-envelopes/verify`, {
    method: "POST",
    headers: headers("consumer", true),
    body: JSON.stringify({ compact_jws: compactJws }),
  });
  assert.equal(missingAudience.status, 400);

  const agentVerify = await fetch(`${base}/v1/evidence-envelopes/verify`, {
    method: "POST",
    headers: headers("agent-a", true),
    body: JSON.stringify({
      compact_jws: compactJws,
      audience: "urn:parimit:consumer:local-demo",
    }),
  });
  assert.equal(agentVerify.status, 403);

  const verifyResponse = await fetch(`${base}/v1/evidence-envelopes/verify`, {
    method: "POST",
    headers: headers("consumer", true),
    body: JSON.stringify({
      compact_jws: compactJws,
      audience: "urn:parimit:consumer:local-demo",
    }),
  });
  assert.equal(verifyResponse.status, 200);
  assert.equal(((await payload(verifyResponse)).data as Record<string, unknown>).valid, true);

  const consumptionBody = JSON.stringify({
    compact_jws: compactJws,
    audience: "urn:parimit:consumer:local-demo",
    idempotency_key: "http-envelope-consume",
  });
  const consumeResponse = await fetch(`${base}/v1/evidence-envelopes/consume`, {
    method: "POST",
    headers: headers("consumer", true),
    body: consumptionBody,
  });
  assert.equal(consumeResponse.status, 200);
  const consumed = (await payload(consumeResponse)).data as Record<string, unknown>;
  assert.equal((consumed.consumption as Record<string, unknown>).state, "CONSUMED");

  const idempotentConsumeResponse = await fetch(`${base}/v1/evidence-envelopes/consume`, {
    method: "POST",
    headers: headers("consumer", true),
    body: consumptionBody,
  });
  assert.equal(idempotentConsumeResponse.status, 200);
  assert.equal(
    ((await payload(idempotentConsumeResponse)).data as Record<string, unknown>).idempotent_replay,
    true,
  );

  const replayResponse = await fetch(`${base}/v1/evidence-envelopes/consume`, {
    method: "POST",
    headers: headers("operator", true),
    body: JSON.stringify({
      compact_jws: compactJws,
      audience: "urn:parimit:consumer:local-demo",
      idempotency_key: "different-consumer-operation",
    }),
  });
  assert.equal(replayResponse.status, 409);
  assert.equal(
    ((await payload(replayResponse)).error as Record<string, unknown>).code,
    "ENVELOPE_REPLAY_DETECTED",
  );

  const observationResponse = await fetch(`${base}/v1/demo/intents/${id}/observations`, {
    method: "POST",
    headers: headers("operator", true),
    body: JSON.stringify({ status: "SUCCEEDED", provider_reference: "fictional-authz" }),
  });
  assert.equal(observationResponse.status, 200);
  const observed = (await payload(observationResponse)).data as Record<string, unknown>;
  assert.equal((observed.observation as Record<string, unknown>).status, "SUCCEEDED");

  const optionsResponse = await fetch(`${base}/v1/intents`, { method: "OPTIONS" });
  assert.equal(optionsResponse.status, 204);
  assert.match(optionsResponse.headers.get("access-control-allow-headers") ?? "", /authorization/);

  service.database.prepare("UPDATE intents SET amount_minor = amount_minor + 1 WHERE id = ?").run(id);
  const tamperedVerification = await fetch(`${base}/v1/intents/${id}/audit/verify`, {
    headers: headers("agent-a"),
  });
  assert.equal(tamperedVerification.status, 200);
  assert.equal(
    (((await payload(tamperedVerification)).data as Record<string, unknown>).valid),
    false,
  );
  const tamperedRead = await fetch(`${base}/v1/intents/${id}`, {
    headers: headers("agent-a"),
  });
  assert.equal(tamperedRead.status, 500);
  const tamperedOtherAgentCancel = await fetch(`${base}/v1/intents/${id}/cancel`, {
    method: "POST",
    headers: headers("agent-b"),
  });
  assert.equal(tamperedOtherAgentCancel.status, 404);
});

test("HTTP fails closed when an identity provider returns an unknown runtime role", async (t) => {
  const service = new ParimitService({
    receiptSecret: "http-invalid-identity-test-secret-at-least-32-bytes",
    authenticationMode: "oidc",
    identityTrustDomainId: TEST_OIDC_TRUST_DOMAIN_ID,
  });
  const invalidIdentityProvider: IdentityProvider = {
    authenticationMethod: "oidc",
    identityTrustDomainId: TEST_OIDC_TRUST_DOMAIN_ID,
    async authenticate(): Promise<AuthenticatedActor> {
      return {
        actorId: "oidc:invalid-role",
        actorRole: "toString" as AuthenticatedActor["actorRole"],
        subject: "invalid-role",
        issuer: "https://identity.example.test",
        authenticationMethod: "oidc",
      };
    },
  };
  const server = createServer(
    createHttpHandler(service, { identityProvider: invalidIdentityProvider }),
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    service.close();
  });
  const address = server.address() as AddressInfo;
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/intents`);
  assert.equal(response.status, 500);
  assert.equal(
    ((await payload(response)).error as Record<string, unknown>).code,
    "INVALID_IDENTITY_PROVIDER_RESULT",
  );
});
