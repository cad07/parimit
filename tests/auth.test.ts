import assert from "node:assert/strict";
import {
  constants as cryptoConstants,
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import test from "node:test";

import {
  createIdentityProviderFromEnvironment,
  LocalDemoHeaderIdentityProvider,
  OidcIdentityProvider,
} from "../src/auth.ts";
import { ParimitError } from "../src/errors.ts";

const ISSUER = "https://identity.example.test/tenant";
const AUDIENCE = "parimit-api";
const JWKS_URI = "https://identity.example.test/.well-known/jwks.json";
const NOW_SECONDS = 2_000_000_000;

interface SigningKey {
  privateKey: KeyObject;
  jwk: Record<string, unknown>;
  kid: string;
  alg: "RS256" | "PS256" | "ES256";
}

function signingKey(
  kid: string,
  alg: SigningKey["alg"] = "RS256",
  rsaModulusLength = 2_048,
): SigningKey {
  const { publicKey, privateKey } =
    alg === "ES256"
      ? generateKeyPairSync("ec", { namedCurve: "P-256" })
      : generateKeyPairSync("rsa", { modulusLength: rsaModulusLength });
  return {
    privateKey,
    kid,
    alg,
    jwk: {
      ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>),
      kid,
      alg,
      use: "sig",
      key_ops: ["verify"],
    },
  };
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function token(
  key: SigningKey,
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
): string {
  const encodedHeader = encode({ alg: key.alg, kid: key.kid, typ: "at+jwt", ...header });
  const encodedClaims = encode({
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "immutable-user-123",
    exp: NOW_SECONDS + 300,
    nbf: NOW_SECONDS - 10,
    iat: NOW_SECONDS - 10,
    roles: ["parimit-reviewer"],
    ...claims,
  });
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const data = Buffer.from(signingInput, "ascii");
  const signature =
    key.alg === "RS256"
      ? sign("RSA-SHA256", data, key.privateKey)
      : key.alg === "PS256"
        ? sign("sha256", data, {
            key: key.privateKey,
            padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
            saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
          })
        : sign("sha256", data, { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  return `${signingInput}.${signature.toString("base64url")}`;
}

function bearer(value: string): Record<string, string> {
  return { authorization: `Bearer ${value}` };
}

function jwksFetch(
  getKeys: () => readonly Record<string, unknown>[],
  onFetch?: () => void,
): typeof globalThis.fetch {
  return (async () => {
    onFetch?.();
    return new Response(JSON.stringify({ keys: getKeys() }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=300",
      },
    });
  }) as typeof globalThis.fetch;
}

function provider(
  keySource: () => readonly Record<string, unknown>[],
  options: Partial<ConstructorParameters<typeof OidcIdentityProvider>[0]> = {},
): OidcIdentityProvider {
  return new OidcIdentityProvider({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri: JWKS_URI,
    roleClaim: "roles",
    roleMapping: {
      "parimit-agent": "agent",
      "parimit-reviewer": "approver",
      "parimit-admin": "admin",
    },
    clockSkewSeconds: 0,
    clock: () => new Date(NOW_SECONDS * 1_000),
    fetch: jwksFetch(keySource),
    ...options,
  });
}

function isParimitError(code: string, statusCode: number) {
  return (error: unknown): boolean =>
    error instanceof ParimitError && error.code === code && error.statusCode === statusCode;
}

test("OIDC verifies signature and registered claims, maps one role, and derives a stable actor ID", async () => {
  const key = signingKey("primary");
  let fetches = 0;
  const identityProvider = provider(() => [key.jwk], {
    fetch: jwksFetch(() => [key.jwk], () => fetches++),
  });
  const jwt = token(key);

  const first = await identityProvider.authenticate(bearer(jwt));
  const second = await identityProvider.authenticate(bearer(jwt));
  const expectedActorId = `oidc:${createHash("sha256")
    .update(ISSUER, "utf8")
    .update("\0", "utf8")
    .update("immutable-user-123", "utf8")
    .digest("hex")}`;

  assert.deepEqual(first, {
    actorId: expectedActorId,
    actorRole: "approver",
    subject: "immutable-user-123",
    issuer: ISSUER,
    authenticationMethod: "oidc",
  });
  assert.deepEqual(second, first);
  assert.equal(fetches, 1, "JWKS should be cached between token validations");
  assert.doesNotMatch(first.actorId, /immutable-user-123/);
});

test("OIDC rejects bad signature, issuer, audience, token times, missing expiry, and algorithms", async () => {
  const trusted = signingKey("trusted");
  const attacker = signingKey("trusted");
  const identityProvider = provider(() => [trusted.jwk]);
  const cases = [
    token(attacker),
    token(trusted, { iss: "https://attacker.example" }),
    token(trusted, { aud: "different-api" }),
    token(trusted, { exp: NOW_SECONDS }),
    token(trusted, { nbf: NOW_SECONDS + 1 }),
    token(trusted, { iat: NOW_SECONDS + 1 }),
    token(trusted, { iat: NOW_SECONDS + 300 }),
    token(trusted, { exp: undefined }),
    token(trusted, {}, { alg: "none" }),
    token(trusted, {}, { alg: "HS256" }),
    token(trusted, {}, { kid: "unknown" }),
  ];

  for (const candidate of cases) {
    await assert.rejects(
      identityProvider.authenticate(bearer(candidate)),
      isParimitError("INVALID_TOKEN", 401),
    );
  }
  await assert.rejects(
    identityProvider.authenticate({}),
    isParimitError("AUTHENTICATION_REQUIRED", 401),
  );
  await assert.rejects(
    identityProvider.authenticate({ authorization: "Basic abc" }),
    isParimitError("INVALID_TOKEN", 401),
  );
});

test("OIDC role mapping fails closed for unmapped and ambiguous provider roles", async () => {
  const key = signingKey("roles");
  const identityProvider = provider(() => [key.jwk]);

  await assert.rejects(
    identityProvider.authenticate(bearer(token(key, { roles: ["unrelated-group"] }))),
    isParimitError("ROLE_NOT_AUTHORIZED", 403),
  );
  await assert.rejects(
    identityProvider.authenticate(
      bearer(token(key, { roles: ["parimit-reviewer", "parimit-admin"] })),
    ),
    isParimitError("AMBIGUOUS_ROLE", 403),
  );

  const agent = await identityProvider.authenticate(
    bearer(token(key, { roles: "parimit-agent" })),
  );
  assert.equal(agent.actorRole, "agent");

  for (const inheritedName of ["toString", "constructor", "__proto__"]) {
    await assert.rejects(
      identityProvider.authenticate(bearer(token(key, { roles: [inheritedName] }))),
      isParimitError("ROLE_NOT_AUTHORIZED", 403),
    );
  }
});

test("OIDC snapshots the validated role mapping instead of retaining caller-owned authority", async () => {
  const key = signingKey("immutable-role-map");
  const mutableMapping: Record<string, "agent" | "approver" | "admin"> = {
    "parimit-agent": "agent",
  };
  const identityProvider = provider(() => [key.jwk], { roleMapping: mutableMapping });
  mutableMapping["parimit-agent"] = "admin";

  const actor = await identityProvider.authenticate(
    bearer(token(key, { roles: ["parimit-agent"] })),
  );
  assert.equal(actor.actorRole, "agent");
});

test("OIDC supports only explicitly allowlisted RSA-PSS and P-256 signatures", async () => {
  const pssKey = signingKey("pss", "PS256");
  const ecKey = signingKey("ec", "ES256");
  const identityProvider = provider(() => [pssKey.jwk, ecKey.jwk], {
    allowedAlgorithms: ["PS256", "ES256"],
  });

  assert.equal((await identityProvider.authenticate(bearer(token(pssKey)))).actorRole, "approver");
  assert.equal((await identityProvider.authenticate(bearer(token(ecKey)))).actorRole, "approver");

  const rsaKey = signingKey("rsa", "RS256");
  await assert.rejects(
    identityProvider.authenticate(bearer(token(rsaKey))),
    isParimitError("INVALID_TOKEN", 401),
  );

  const weakRsaKey = signingKey("weak-rsa", "RS256", 1_024);
  const weakRsaProvider = provider(() => [weakRsaKey.jwk]);
  await assert.rejects(
    weakRsaProvider.authenticate(bearer(token(weakRsaKey))),
    isParimitError("INVALID_TOKEN", 401),
  );
});

test("OIDC can require an access-token type and a bounded issued lifetime", async () => {
  const key = signingKey("token-profile");
  const identityProvider = provider(() => [key.jwk], {
    requiredTokenType: "at+jwt",
    maxTokenLifetimeSeconds: 600,
  });

  assert.equal(
    (await identityProvider.authenticate(bearer(token(key)))).actorRole,
    "approver",
  );
  await assert.rejects(
    identityProvider.authenticate(bearer(token(key, {}, { typ: "JWT" }))),
    isParimitError("INVALID_TOKEN", 401),
  );
  await assert.rejects(
    identityProvider.authenticate(bearer(token(key, { iat: undefined }))),
    isParimitError("INVALID_TOKEN", 401),
  );
  await assert.rejects(
    identityProvider.authenticate(
      bearer(token(key, { iat: NOW_SECONDS - 1_000, exp: NOW_SECONDS + 300 })),
    ),
    isParimitError("INVALID_TOKEN", 401),
  );
  assert.throws(
    () => provider(() => [key.jwk], { clockSkewSeconds: 301 }),
    isParimitError("INVALID_AUTH_CONFIGURATION", 500),
  );
});

test("OIDC refreshes cached JWKS for a rotated key without trusting token-supplied key material", async () => {
  const oldKey = signingKey("old");
  const newKey = signingKey("new");
  let currentKeys: readonly Record<string, unknown>[] = [oldKey.jwk];
  let now = NOW_SECONDS;
  let fetches = 0;
  const identityProvider = provider(() => currentKeys, {
    clock: () => new Date(now * 1_000),
    jwksRefreshSeconds: 30,
    fetch: jwksFetch(() => currentKeys, () => fetches++),
  });

  assert.equal((await identityProvider.authenticate(bearer(token(oldKey)))).actorRole, "approver");
  currentKeys = [newKey.jwk];
  now += 31;
  assert.equal((await identityProvider.authenticate(bearer(token(newKey)))).actorRole, "approver");
  assert.equal(fetches, 2);

  await assert.rejects(
    identityProvider.authenticate(
      bearer(token(newKey, {}, { jwk: newKey.jwk })),
    ),
    isParimitError("INVALID_TOKEN", 401),
  );
});

test("OIDC stops reading an oversized JWKS response without relying on Content-Length", async () => {
  const key = signingKey("oversized-jwks");
  const identityProvider = provider(() => [key.jwk], {
    fetch: (async () =>
      new Response(new Uint8Array(1_048_577), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as typeof globalThis.fetch,
  });

  await assert.rejects(
    identityProvider.authenticate(bearer(token(key))),
    isParimitError("AUTH_PROVIDER_UNAVAILABLE", 503),
  );
});

test("local demo headers are available only in explicit loopback demo mode", async () => {
  assert.throws(
    () => new LocalDemoHeaderIdentityProvider({ demoMode: false, host: "127.0.0.1" }),
    isParimitError("INVALID_AUTH_CONFIGURATION", 500),
  );
  assert.throws(
    () => new LocalDemoHeaderIdentityProvider({ demoMode: true, host: "0.0.0.0" }),
    isParimitError("INVALID_AUTH_CONFIGURATION", 500),
  );

  const explicitContainerDemo = new LocalDemoHeaderIdentityProvider({
    demoMode: true,
    host: "0.0.0.0",
    allowNonLoopback: true,
  });
  assert.equal(
    (
      await explicitContainerDemo.authenticate({
        "x-parimit-actor": "container-agent",
        "x-parimit-role": "agent",
      })
    ).actorRole,
    "agent",
  );

  const demo = new LocalDemoHeaderIdentityProvider({ demoMode: true, host: "127.0.0.1" });
  assert.deepEqual(
    await demo.authenticate({
      "x-parimit-actor": "human-demo",
      "x-parimit-role": "APPROVER",
    }),
    {
      actorId: "human-demo",
      actorRole: "approver",
      subject: "human-demo",
      authenticationMethod: "local_demo_headers",
    },
  );
  await assert.rejects(
    demo.authenticate({ "x-parimit-actor": "human-demo", "x-parimit-role": "owner" }),
    isParimitError("INVALID_DEMO_IDENTITY", 401),
  );
});

test("environment factory requires an explicit safe authentication mode", async () => {
  assert.throws(
    () => createIdentityProviderFromEnvironment({}),
    isParimitError("INVALID_AUTH_CONFIGURATION", 500),
  );
  assert.throws(
    () =>
      createIdentityProviderFromEnvironment({
        PARIMIT_AUTH_MODE: "demo_headers",
        PARIMIT_DEMO_MODE: "true",
        PARIMIT_HOST: "0.0.0.0",
      }),
    isParimitError("INVALID_AUTH_CONFIGURATION", 500),
  );

  const demo = createIdentityProviderFromEnvironment({
    PARIMIT_AUTH_MODE: "demo_headers",
    PARIMIT_DEMO_MODE: "true",
    PARIMIT_HOST: "::1",
  });
  assert.equal(
    (await demo.authenticate({ "x-parimit-actor": "agent-a", "x-parimit-role": "agent" }))
      .actorRole,
    "agent",
  );

  const numericDemo = createIdentityProviderFromEnvironment({
    PARIMIT_AUTH_MODE: "demo_headers",
    PARIMIT_DEMO_MODE: "1",
    PARIMIT_HOST: "127.0.0.1",
  });
  assert.equal(
    (
      await numericDemo.authenticate({
        "x-parimit-actor": "agent-b",
        "x-parimit-role": "agent",
      })
    ).actorRole,
    "agent",
  );

  assert.throws(
    () =>
      createIdentityProviderFromEnvironment({
        PARIMIT_AUTH_MODE: "oidc",
        PARIMIT_OIDC_ISSUER: ISSUER,
        PARIMIT_OIDC_AUDIENCE: AUDIENCE,
      }),
    isParimitError("INVALID_AUTH_CONFIGURATION", 500),
  );
  assert.throws(
    () =>
      createIdentityProviderFromEnvironment({
        PARIMIT_AUTH_MODE: "oidc",
        PARIMIT_OIDC_ISSUER: ISSUER,
        PARIMIT_OIDC_AUDIENCE: AUDIENCE,
        PARIMIT_OIDC_JWKS_URI: JWKS_URI,
      }),
    isParimitError("INVALID_AUTH_CONFIGURATION", 500),
  );
});
