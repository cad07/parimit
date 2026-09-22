import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { AiNxtParimitAdapter } from "../integrations/ainxt/adapter.ts";
import { createIdentityProviderFromEnvironment } from "../src/auth.ts";
import { createHttpHandler } from "../src/http.ts";
import { createServiceFromEnvironment } from "../src/service.ts";

const ISSUER = "https://identity.integration.test/tenant";
const AUDIENCE = "parimit-integration-api";
const JWKS_URI = "https://identity.integration.test/tenant/jwks";
const NOW_SECONDS = 2_000_000_000;

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function jsonWebToken(
  privateKey: KeyObject,
  audience: string,
  role = "pilot-agent",
  subject = "integration-agent",
): string {
  const header = encode({ alg: "RS256", kid: "integration-key", typ: "at+jwt" });
  const payload = encode({
    iss: ISSUER,
    aud: audience,
    sub: subject,
    exp: NOW_SECONDS + 300,
    iat: NOW_SECONDS,
    roles: [role],
  });
  const input = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(input, "ascii"), privateKey);
  return `${input}.${signature.toString("base64url")}`;
}

async function body(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

test("environment OIDC verifier and HTTP authorization compose end to end", async (t) => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2_048 });
  const envelopePrivateKeyPem = generateKeyPairSync("ed25519").privateKey.export({
    format: "pem",
    type: "pkcs8",
  }) as string;
  const jwk = {
    ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>),
    kid: "integration-key",
    alg: "RS256",
    use: "sig",
    key_ops: ["verify"],
  };
  const environment = {
    PARIMIT_AUTH_MODE: "oidc",
    PARIMIT_DEMO_MODE: "false",
    PARIMIT_DB_PATH: ":memory:",
    PARIMIT_RECEIPT_KEY: "oidc-http-integration-secret-at-least-32-bytes",
    PARIMIT_OIDC_ISSUER: ISSUER,
    PARIMIT_OIDC_AUDIENCE: AUDIENCE,
    PARIMIT_OIDC_JWKS_URI: JWKS_URI,
    PARIMIT_OIDC_ROLE_CLAIM: "roles",
    PARIMIT_OIDC_ROLE_MAPPING: JSON.stringify({
      "pilot-agent": "agent",
      "pilot-reviewer": "approver",
    }),
    PARIMIT_OIDC_CLOCK_SKEW_SECONDS: "0",
    PARIMIT_OIDC_MAX_TOKEN_LIFETIME_SECONDS: "600",
    PARIMIT_OIDC_REQUIRED_TYP: "at+jwt",
    PARIMIT_TENANT_ID: "integration-tenant",
    PARIMIT_ENVELOPE_ISSUER: "urn:parimit:integration:issuer",
    PARIMIT_ENVELOPE_AUDIENCES: "urn:parimit:integration:consumer",
    PARIMIT_ENVELOPE_PRIVATE_KEY_PEM_BASE64: Buffer.from(
      envelopePrivateKeyPem,
      "utf8",
    ).toString("base64"),
  };
  const identityProvider = createIdentityProviderFromEnvironment(environment, {
    clock: () => new Date(NOW_SECONDS * 1_000),
    fetch: (async (input: string | URL | Request) => {
      assert.equal(String(input), JWKS_URI);
      return new Response(JSON.stringify({ keys: [jwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch,
  });
  const service = createServiceFromEnvironment(environment, identityProvider);
  const server = createServer(createHttpHandler(service, { identityProvider }));
  t.after(async () => {
    if (server.listening) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    service.close();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const safetyResponse = await fetch(`${baseUrl}/v1/safety`);
  assert.equal(safetyResponse.status, 200);
  const safety = (await body(safetyResponse)).data as Record<string, unknown>;
  assert.deepEqual(safety.identity, {
    mode: "oidc",
    cryptographically_verified: true,
    trust_domain_id: identityProvider.identityTrustDomainId,
  });

  const demoHeaderOnly = await fetch(`${baseUrl}/v1/identity`, {
    headers: { "x-parimit-actor": "spoofed-agent", "x-parimit-role": "agent" },
  });
  assert.equal(demoHeaderOnly.status, 401);

  const wrongAudience = await fetch(`${baseUrl}/v1/identity`, {
    headers: { authorization: `Bearer ${jsonWebToken(privateKey, "browser-client-id")}` },
  });
  assert.equal(wrongAudience.status, 401);

  const accessToken = jsonWebToken(privateKey, AUDIENCE);
  const identityResponse = await fetch(`${baseUrl}/v1/identity`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  assert.equal(identityResponse.status, 200);
  const identity = (await body(identityResponse)).data as Record<string, unknown>;
  assert.equal(identity.actor_role, "agent");
  assert.match(String(identity.actor_id), /^oidc:[a-f0-9]{64}$/);

  let ainxtCalls = 0;
  const adapterFetch: typeof fetch = async (input, init = {}) => {
    const url = typeof input === "string"
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;
    if (url !== "http://127.0.0.1:8080/v1/chat") return fetch(input, init);
    ainxtCalls += 1;
    const request = JSON.parse(String(init.body)) as { session: string; turn: string };
    const draft = JSON.stringify({
      amount: { currency: "INR", minor: "49900" },
      payee_reference: "demo-coffee-merchant",
      purpose: "Synthetic order DEMO-COFFEE-001",
      on_behalf_of: "demo-customer-1",
      expires_in_seconds: 300,
    });
    const envelope = (seq: number, type: string, fields: Record<string, unknown> = {}) => ({
      v: "1.0",
      session_id: request.session,
      turn_id: request.turn,
      seq,
      ts: `2026-09-22T00:00:0${seq}Z`,
      control_plane_sha: "oidc-integration-control-plane",
      type,
      ...fields,
    });
    const frames = [
      envelope(1, "turn.started"),
      envelope(2, "text.delta", { text: draft }),
      envelope(3, "turn.completed", { outcome: "complete" }),
    ];
    return new Response(
      frames.map((frame, index) => `id: ${index + 1}\ndata: ${JSON.stringify(frame)}\n\n`).join(""),
      { status: 200, headers: { "content-type": "text/event-stream" } },
    );
  };
  const adapter = new AiNxtParimitAdapter({
    ainxtBaseUrl: "http://127.0.0.1:8080",
    parimitBaseUrl: baseUrl,
    accessToken,
    fetch: adapterFetch,
  });
  const adapterRequest = {
    scenario: "coffee_order" as const,
    idempotency_key: "ainxt-oidc-integration",
  };
  const adapterIntent = await adapter.createProposal(adapterRequest);
  const adapterReplay = await adapter.createProposal(adapterRequest);
  assert.equal(adapterIntent.intent.status, "AWAITING_APPROVAL");
  assert.equal(adapterIntent.intent.requested_by.id, identity.actor_id);
  assert.equal(adapterReplay.intent.id, adapterIntent.intent.id);
  assert.equal(adapterReplay.intent.idempotent_replay, true);
  assert.equal(ainxtCalls, 1);

  const createResponse = await fetch(`${baseUrl}/v1/intents`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      idempotency_key: "oidc-http-integration",
      requested_by: { type: "agent", id: identity.actor_id },
      amount: { currency: "INR", minor: "49900" },
      payee_reference: "merchant_oidc_integration",
      purpose: "Signed-token HTTP integration test",
    }),
  });
  assert.equal(createResponse.status, 201);
  const intent = (await body(createResponse)).data as Record<string, unknown>;
  assert.equal(intent.status, "AWAITING_APPROVAL");

  const reviewerToken = jsonWebToken(
    privateKey,
    AUDIENCE,
    "pilot-reviewer",
    "integration-reviewer",
  );
  const approvalResponse = await fetch(`${baseUrl}/v1/intents/${String(intent.id)}/approvals`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${reviewerToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ decision: "APPROVE" }),
  });
  assert.equal(approvalResponse.status, 200);

  const envelopeResponse = await fetch(
    `${baseUrl}/v1/intents/${String(intent.id)}/evidence-envelopes`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${reviewerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        audience: "urn:parimit:integration:consumer",
        idempotency_key: "oidc-envelope-integration",
      }),
    },
  );
  assert.equal(envelopeResponse.status, 201);
  const envelope = (await body(envelopeResponse)).data as Record<string, unknown>;
  const claims = envelope.claims as Record<string, unknown>;
  assert.deepEqual(claims.identity_assurance, {
    authentication_method: "oidc",
    cryptographically_verified: true,
    trust_domain_id: identityProvider.identityTrustDomainId,
  });
});
