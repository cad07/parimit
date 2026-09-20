import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

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
): string {
  const header = encode({ alg: "RS256", kid: "integration-key", typ: "at+jwt" });
  const payload = encode({
    iss: ISSUER,
    aud: audience,
    sub: "integration-agent",
    exp: NOW_SECONDS + 300,
    iat: NOW_SECONDS,
    roles: ["pilot-agent"],
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
    PARIMIT_OIDC_ROLE_MAPPING: JSON.stringify({ "pilot-agent": "agent" }),
    PARIMIT_OIDC_CLOCK_SKEW_SECONDS: "0",
    PARIMIT_OIDC_MAX_TOKEN_LIFETIME_SECONDS: "600",
    PARIMIT_OIDC_REQUIRED_TYP: "at+jwt",
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
  const service = createServiceFromEnvironment(environment);
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
  assert.deepEqual(safety.identity, { mode: "oidc", cryptographically_verified: true });

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
});
