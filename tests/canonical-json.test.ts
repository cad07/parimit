import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { canonicalJson } from "../src/crypto.ts";
import { oidcIdentityTrustDomainId } from "../src/identity-trust.ts";
import { ParimitService } from "../src/service.ts";

test("published canonical JSON vectors preserve every key and sort lexicographically", () => {
  const vector = JSON.parse(
    readFileSync(new URL("../test-vectors/canonical-json-v1.json", import.meta.url), "utf8"),
  ) as { cases: Array<{ name: string; input: unknown; canonical: string }> };
  for (const item of vector.cases) {
    assert.equal(canonicalJson(item.input), item.canonical, item.name);
  }
});

test("OIDC trust-domain digest binds prototype-shaped role names", () => {
  const configuration = {
    issuer: "https://identity.example.test/tenant",
    audiences: ["parimit-api"],
    jwksUri: "https://identity.example.test/tenant/jwks",
    roleClaim: "roles",
    allowedAlgorithms: ["RS256"],
    requiredTokenType: "at+jwt" as const,
    clockSkewSeconds: 60,
    maxTokenLifetimeSeconds: 3_600,
  };
  const regular = JSON.parse('{"regular":"agent"}') as Record<string, "agent" | "admin">;
  const withPrototypeKey = JSON.parse(
    '{"regular":"agent","__proto__":"admin"}',
  ) as Record<string, "agent" | "admin">;
  assert.notEqual(
    oidcIdentityTrustDomainId({ ...configuration, roleMapping: regular }),
    oidcIdentityTrustDomainId({ ...configuration, roleMapping: withPrototypeKey }),
  );
});

test("canonical JSON rejects sparse and undefined array members", () => {
  const sparse = [1, 2, 3];
  delete sparse[1];
  assert.throws(() => canonicalJson(sparse), /sparse arrays/);
  assert.throws(() => canonicalJson([1, undefined, 3]), /Unsupported canonical JSON value/);
});

test("published identity and policy configuration digest vectors remain stable", (t) => {
  const vector = JSON.parse(
    readFileSync(
      new URL("../test-vectors/configuration-digests-v1.json", import.meta.url),
      "utf8",
    ),
  ) as {
    oidc: {
      input: Parameters<typeof oidcIdentityTrustDomainId>[0];
      preimage: Record<string, unknown>;
      canonical_preimage: string;
      digest: string;
    };
    policy: {
      preimage: Record<string, unknown>;
      canonical_preimage: string;
      digest: string;
    };
  };
  assert.equal(canonicalJson(vector.oidc.preimage), vector.oidc.canonical_preimage);
  assert.equal(oidcIdentityTrustDomainId(vector.oidc.input), vector.oidc.digest);
  assert.equal(canonicalJson(vector.policy.preimage), vector.policy.canonical_preimage);

  const service = new ParimitService({
    receiptSecret: "v".repeat(32),
    policy: {
      rulesVersion: "parimit-policy-vector-v1",
      perTransactionLimitMinor: 100_000,
      dailyAgentLimitMinor: 500_000,
      dualApprovalThresholdMinor: 50_000,
      defaultExpirySeconds: 1_800,
      maxExpirySeconds: 86_400,
      blockedPayees: ["merchant_blocked_z", "merchant_blocked_a"],
      allowedPayees: ["merchant_allowed_z", "merchant_allowed_a"],
    },
  });
  t.after(() => service.close());
  assert.equal(service.policyConfigurationDigest, vector.policy.digest);
});
