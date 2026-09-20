import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import {
  parseAuthorizationEnvelope,
  verifyAuthorizationEnvelopeSignature,
} from "../src/envelope.ts";
import { ParimitError } from "../src/errors.ts";
import { LOCAL_DEMO_IDENTITY_TRUST_DOMAIN } from "../src/identity-trust.ts";
import { ParimitService } from "../src/service.ts";

const TEST_OIDC_TRUST_DOMAIN_ID = `sha256:${"e".repeat(64)}`;

test("published Authorization Envelope v1 signature vector remains stable", () => {
  const vector = JSON.parse(
    readFileSync(
      new URL("../test-vectors/authorization-envelope-v1.json", import.meta.url),
      "utf8",
    ),
  ) as {
    public_jwk: Record<string, unknown>;
    payload: Record<string, unknown>;
    compact_jws: string;
  };
  const parsed = verifyAuthorizationEnvelopeSignature(vector.compact_jws, vector.public_jwk);
  assert.deepEqual(parsed.payload, vector.payload);
  const segments = vector.compact_jws.split(".");
  segments[2] = `${segments[2]!.slice(0, -1)}${segments[2]!.endsWith("A") ? "B" : "A"}`;
  assert.throws(
    () => verifyAuthorizationEnvelopeSignature(segments.join("."), vector.public_jwk),
    /signature|base64url/,
  );
  const nonCanonicalHeader = Buffer.from(
    JSON.stringify({
      typ: "parimit-authz-envelope+jws",
      kid: "parimit-vector-2026-09",
      alg: "EdDSA",
    }),
    "utf8",
  ).toString("base64url");
  assert.throws(
    () => parseAuthorizationEnvelope([nonCanonicalHeader, ...vector.compact_jws.split(".").slice(1)].join(".")),
    /protected header is not canonical JSON/,
  );
  assert.throws(
    () =>
      verifyAuthorizationEnvelopeSignature(vector.compact_jws, {
        ...vector.public_jwk,
        jku: "https://attacker.invalid/jwks.json",
      }),
    /verification key is incompatible/,
  );
  assert.throws(
    () =>
      verifyAuthorizationEnvelopeSignature(vector.compact_jws, {
        ...vector.public_jwk,
        x: `${String(vector.public_jwk.x)}=`,
      }),
    /verification key is incompatible/,
  );
  assert.throws(
    () =>
      verifyAuthorizationEnvelopeSignature(vector.compact_jws, {
        ...vector.public_jwk,
        x: String(vector.public_jwk.x).replaceAll("-", "+").replaceAll("_", "/"),
      }),
    /verification key is incompatible/,
  );
});

function signingKeyPem(): string {
  return generateKeyPairSync("ed25519").privateKey.export({
    format: "pem",
    type: "pkcs8",
  }) as string;
}

function proposal(key: string) {
  return {
    idempotency_key: key,
    requested_by: { type: "agent", id: "agent-envelope" },
    on_behalf_of: "demo-user",
    amount: { currency: "INR", minor: "49900" },
    payee_reference: "merchant_envelope_001",
    purpose: "Bound evidence-envelope test",
    expires_in_seconds: 900,
  };
}

function isParimitError(code: string, statusCode: number) {
  return (error: unknown): boolean =>
    error instanceof ParimitError && error.code === code && error.statusCode === statusCode;
}

function createEnvelopeService(options: {
  databasePath?: string;
  privateKeyPem?: string;
  receiptSecret?: string;
  envelopeIssuer?: string;
  envelopeAudience?: string;
  authenticationMode?: "demo_headers" | "oidc";
  identityTrustDomainId?: string;
  envelopeTtlSeconds?: number;
  perTransactionLimitMinor?: number;
  clock: () => Date;
}) {
  return new ParimitService({
    databasePath: options.databasePath,
    receiptSecret: options.receiptSecret ?? "e".repeat(40),
    authenticationMode: options.authenticationMode ?? "demo_headers",
    identityTrustDomainId:
      options.identityTrustDomainId ??
      (options.authenticationMode === "oidc" ? TEST_OIDC_TRUST_DOMAIN_ID : undefined),
    tenantId: "pilot-tenant-01",
    envelopeIssuer: options.envelopeIssuer ?? "urn:parimit:deployment:pilot-01",
    envelopeAudiences: [
      options.envelopeAudience ?? "urn:ainxt:deployment:consumer-01",
    ],
    envelopeSigningPrivateKeyPem: options.privateKeyPem ?? signingKeyPem(),
    envelopeTtlSeconds: options.envelopeTtlSeconds ?? 300,
    ...(options.perTransactionLimitMinor === undefined
      ? {}
      : { policy: { perTransactionLimitMinor: options.perTransactionLimitMinor } }),
    clock: options.clock,
  });
}

test("v3 envelope is audience-bound, publicly verifiable, deterministic on replay, and non-dispatchable", (t) => {
  let now = new Date("2026-09-20T10:00:00.000Z");
  const service = createEnvelopeService({ clock: () => now });
  t.after(() => service.close());

  const created = service.createIntent(proposal("envelope-primary"));
  assert.equal(created.intent_version, "parimit-payment-intent-v3");
  assert.equal(created.tenant_id, "pilot-tenant-01");
  assert.equal(created.state_version, 1);
  assert.throws(
    () =>
      service.issueAuthorizationEnvelope(
        created.id,
        {
          audience: "urn:ainxt:deployment:consumer-01",
          idempotency_key: "issue-too-soon",
        },
        "human-reviewer",
        "approver",
      ),
    isParimitError("INVALID_STATE", 409),
  );

  now = new Date("2026-09-20T10:01:00.000Z");
  const approved = service.approveIntent(created.id, "human-reviewer", "approver", "APPROVE");
  assert.equal(approved.status, "AUTHORIZED_NO_DISPATCH");
  assert.equal(approved.state_version, 2);

  const input = {
    audience: "urn:ainxt:deployment:consumer-01",
    idempotency_key: "issue-envelope-001",
    expires_in_seconds: 180,
  };
  const envelope = service.issueAuthorizationEnvelope(
    created.id,
    input,
    "human-reviewer",
    "approver",
  );
  assert.equal(envelope.execution_authorized, false);
  assert.equal(envelope.moves_money, false);
  assert.equal(envelope.claims.capability.kind, "EVIDENCE_ONLY");
  assert.equal(envelope.claims.capability.payment_dispatch_authorized, false);
  assert.equal(envelope.claims.capability.provider_instruction, false);
  assert.equal(envelope.claims.aud, input.audience);
  assert.equal(envelope.claims.tenant_id, "pilot-tenant-01");
  assert.deepEqual(envelope.claims.identity_assurance, {
    authentication_method: "local_demo_headers",
    cryptographically_verified: false,
    trust_domain_id: LOCAL_DEMO_IDENTITY_TRUST_DOMAIN,
  });
  assert.equal(envelope.claims.intent.snapshot.id, created.id);
  assert.equal(envelope.claims.decision.authorization_state_version, 2);
  assert.equal(envelope.claims.replay.nonce.length, 43);
  assert.equal(envelope.consumption.state, "UNCONSUMED");

  const publicJwk = service.envelopeJwks().keys.find(
    (key) => key.kid === envelope.signature.key_id,
  );
  assert.ok(publicJwk);
  assert.equal("d" in publicJwk, false);
  const independentlyParsed = verifyAuthorizationEnvelopeSignature(
    envelope.compact_jws,
    publicJwk,
  );
  assert.equal(independentlyParsed.payload.jti, envelope.claims.jti);

  const verification = service.verifyAuthorizationEnvelope(envelope.compact_jws, input.audience);
  assert.equal(verification.valid, true);
  assert.deepEqual(verification.failures, []);

  const replay = service.issueAuthorizationEnvelope(
    created.id,
    input,
    "human-reviewer",
    "approver",
  );
  assert.equal(replay.compact_jws, envelope.compact_jws);
  assert.equal(replay.idempotent_replay, true);
  assert.throws(
    () =>
      service.issueAuthorizationEnvelope(
        created.id,
        { ...input, expires_in_seconds: 179 },
        "human-reviewer",
        "approver",
      ),
    isParimitError("IDEMPOTENCY_CONFLICT", 409),
  );
  assert.equal(
    service.getAudit(created.id).filter((event) => event.event_type === "EVIDENCE_ENVELOPE_ISSUED")
      .length,
    1,
  );
  assert.throws(
    () =>
      service.issueAuthorizationEnvelope(
        created.id,
        { ...input, idempotency_key: "different-issuance-key" },
        "human-reviewer",
        "approver",
      ),
    isParimitError("IDEMPOTENCY_CONFLICT", 409),
  );
  assert.throws(
    () =>
      service.issueAuthorizationEnvelope(
        created.id,
        input,
        "agent-envelope",
        "agent",
      ),
    isParimitError("FORBIDDEN", 403),
  );
});

test("approval evidence uses locale-independent UTF-16 code-unit ordering", (t) => {
  const service = createEnvelopeService({
    clock: () => new Date("2026-09-20T10:30:00.000Z"),
  });
  t.after(() => service.close());
  const created = service.createIntent({
    ...proposal("envelope-approval-order"),
    amount: { currency: "INR", minor: "60000" },
  });
  service.approveIntent(created.id, "human_z", "approver", "APPROVE");
  service.approveIntent(created.id, "human-a", "approver", "APPROVE");
  const envelope = service.issueAuthorizationEnvelope(
    created.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-approval-order",
    },
    "human-a",
    "approver",
  );
  assert.deepEqual(
    envelope.claims.decision.approvals.map((approval) => approval.subject),
    ["human-a", "human_z"],
  );
});

test("one-time consumption is atomic, idempotent only for the same consumer operation, and survives restart", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-envelope-"));
  const databasePath = join(directory, "parimit.db");
  const privateKeyPem = signingKeyPem();
  let now = new Date("2026-09-20T11:00:00.000Z");
  let service = createEnvelopeService({ databasePath, privateKeyPem, clock: () => now });
  t.after(() => service.close());

  const created = service.createIntent(proposal("envelope-consume"));
  now = new Date("2026-09-20T11:01:00.000Z");
  service.approveIntent(created.id, "human-a", "approver", "APPROVE");
  const envelope = service.issueAuthorizationEnvelope(
    created.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-consume-001",
      expires_in_seconds: 240,
    },
    "human-a",
    "approver",
  );

  now = new Date("2026-09-20T11:02:00.000Z");
  const consumed = service.consumeAuthorizationEnvelope(
    envelope.compact_jws,
    "urn:ainxt:deployment:consumer-01",
    "consumer-a",
    "consumer",
    "consume-001",
  );
  assert.equal(consumed.consumption.state, "CONSUMED");
  assert.equal(consumed.consumption.consumed_by, "consumer-a");
  const replay = service.consumeAuthorizationEnvelope(
    envelope.compact_jws,
    "urn:ainxt:deployment:consumer-01",
    "consumer-a",
    "consumer",
    "consume-001",
  );
  assert.equal(replay.idempotent_replay, true);
  assert.throws(
    () =>
      service.consumeAuthorizationEnvelope(
        envelope.compact_jws,
        "urn:ainxt:deployment:consumer-01",
        "consumer-b",
        "consumer",
        "consume-002",
      ),
    isParimitError("ENVELOPE_REPLAY_DETECTED", 409),
  );
  assert.equal(
    service.getAudit(created.id).filter((event) => event.event_type === "EVIDENCE_ENVELOPE_CONSUMED")
      .length,
    1,
  );
  assert.equal(service.verifyIntegrity(created.id).valid, true);

  service.close();
  service = createEnvelopeService({ databasePath, privateKeyPem, clock: () => now });
  assert.equal(
    service.verifyAuthorizationEnvelope(
      envelope.compact_jws,
      "urn:ainxt:deployment:consumer-01",
    ).consumption?.state,
    "CONSUMED",
  );
  now = new Date(envelope.claims.exp * 1_000);
  const retryAfterExpiry = service.consumeAuthorizationEnvelope(
    envelope.compact_jws,
    "urn:ainxt:deployment:consumer-01",
    "consumer-a",
    "consumer",
    "consume-001",
  );
  assert.equal(retryAfterExpiry.idempotent_replay, true);
  assert.throws(
    () =>
      service.consumeAuthorizationEnvelope(
        envelope.compact_jws,
        "urn:ainxt:deployment:consumer-01",
        "consumer-b",
        "consumer",
        "consume-after-restart",
      ),
    isParimitError("ENVELOPE_REPLAY_DETECTED", 409),
  );
});

test("signing-key rotation retains old public verification keys while new envelopes use the new key", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-envelope-rotation-"));
  const databasePath = join(directory, "parimit.db");
  const firstPrivateKeyPem = signingKeyPem();
  const secondPrivateKeyPem = signingKeyPem();
  let now = new Date("2026-09-20T11:30:00.000Z");

  const firstService = createEnvelopeService({
    databasePath,
    privateKeyPem: firstPrivateKeyPem,
    clock: () => now,
  });
  const firstIntent = firstService.createIntent(proposal("envelope-before-rotation"));
  now = new Date("2026-09-20T11:31:00.000Z");
  firstService.approveIntent(firstIntent.id, "human-before-rotation", "approver", "APPROVE");
  const oldEnvelope = firstService.issueAuthorizationEnvelope(
    firstIntent.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-before-rotation",
      expires_in_seconds: 240,
    },
    "human-before-rotation",
    "approver",
  );
  const oldKeyId = oldEnvelope.signature.key_id;
  firstService.close();

  const rotatedService = createEnvelopeService({
    databasePath,
    privateKeyPem: secondPrivateKeyPem,
    clock: () => now,
  });
  t.after(() => rotatedService.close());
  assert.equal(
    rotatedService.verifyAuthorizationEnvelope(
      oldEnvelope.compact_jws,
      "urn:ainxt:deployment:consumer-01",
    ).valid,
    true,
  );
  const secondIntent = rotatedService.createIntent(proposal("envelope-after-rotation"));
  now = new Date("2026-09-20T11:32:00.000Z");
  rotatedService.approveIntent(secondIntent.id, "human-after-rotation", "approver", "APPROVE");
  const newEnvelope = rotatedService.issueAuthorizationEnvelope(
    secondIntent.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-after-rotation",
      expires_in_seconds: 180,
    },
    "human-after-rotation",
    "approver",
  );
  assert.notEqual(newEnvelope.signature.key_id, oldKeyId);
  const jwks = rotatedService.envelopeJwks();
  assert.deepEqual(
    new Set(jwks.keys.map((key) => key.kid)),
    new Set([oldKeyId, newEnvelope.signature.key_id]),
  );
  assert.equal(jwks.keys.some((key) => "d" in key), false);
});

test("protected signing-key registry detects deletion of historical keys", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-envelope-registry-deletion-"));
  const databasePath = join(directory, "parimit.db");
  const firstPrivateKeyPem = signingKeyPem();
  const secondPrivateKeyPem = signingKeyPem();
  const clock = () => new Date("2026-09-20T11:40:00.000Z");
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const firstService = createEnvelopeService({
    databasePath,
    privateKeyPem: firstPrivateKeyPem,
    clock,
  });
  const firstKeyId = String(firstService.envelopeJwks().keys[0]?.kid);
  firstService.close();

  const rotatedService = createEnvelopeService({
    databasePath,
    privateKeyPem: secondPrivateKeyPem,
    clock,
  });
  assert.equal(rotatedService.envelopeJwks().keys.length, 2);
  rotatedService.close();

  const tampered = new DatabaseSync(databasePath);
  tampered.prepare("DELETE FROM envelope_signing_keys WHERE key_id = ?").run(firstKeyId);
  tampered.close();

  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem: secondPrivateKeyPem,
        clock,
      }),
    isParimitError("SIGNING_KEY_INTEGRITY_FAILURE", 500),
  );
});

test("database-bound receipt integrity root rejects the wrong key before signing-key registration", () => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-receipt-root-"));
  const databasePath = join(directory, "parimit.db");
  const firstPrivateKeyPem = signingKeyPem();
  const secondPrivateKeyPem = signingKeyPem();
  const clock = () => new Date("2026-09-20T11:45:00.000Z");
  const correctReceiptSecret = "c".repeat(40);
  const wrongReceiptSecret = "w".repeat(40);

  const firstService = createEnvelopeService({
    databasePath,
    privateKeyPem: firstPrivateKeyPem,
    receiptSecret: correctReceiptSecret,
    clock,
  });
  firstService.close();

  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem: secondPrivateKeyPem,
        receiptSecret: wrongReceiptSecret,
        clock,
      }),
    isParimitError("RECEIPT_KEY_MISMATCH", 500),
  );
  const afterRejectedStartup = new DatabaseSync(databasePath);
  assert.equal(
    (
      afterRejectedStartup
        .prepare("SELECT COUNT(*) AS count FROM envelope_signing_keys")
        .get() as { count: number }
    ).count,
    1,
  );
  assert.equal(
    (
      afterRejectedStartup
        .prepare("SELECT COUNT(*) AS count FROM service_metadata WHERE name = ?")
        .get("receipt_integrity_root_v1") as { count: number }
    ).count,
    1,
  );
  afterRejectedStartup.close();

  const correctlyRotatedService = createEnvelopeService({
    databasePath,
    privateKeyPem: secondPrivateKeyPem,
    receiptSecret: correctReceiptSecret,
    clock,
  });
  assert.equal(correctlyRotatedService.envelopeJwks().keys.length, 2);
  correctlyRotatedService.close();
});

test("database-bound receipt integrity root rejects trust or authentication-mode drift on restart", () => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-trust-root-"));
  const databasePath = join(directory, "parimit.db");
  const privateKeyPem = signingKeyPem();
  const clock = () => new Date("2026-09-20T11:50:00.000Z");

  const initialService = createEnvelopeService({ databasePath, privateKeyPem, clock });
  initialService.close();

  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem,
        envelopeIssuer: "urn:parimit:deployment:different-pilot",
        clock,
      }),
    isParimitError("RECEIPT_KEY_MISMATCH", 500),
  );
  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem,
        authenticationMode: "oidc",
        clock,
      }),
    isParimitError("RECEIPT_KEY_MISMATCH", 500),
  );
  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem,
        envelopeTtlSeconds: 60,
        clock,
      }),
    isParimitError("RECEIPT_KEY_MISMATCH", 500),
  );
  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem,
        envelopeAudience: "urn:ainxt:deployment:different-consumer",
        clock,
      }),
    isParimitError("RECEIPT_KEY_MISMATCH", 500),
  );
  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem,
        perTransactionLimitMinor: 200_000,
        clock,
      }),
    isParimitError("RECEIPT_KEY_MISMATCH", 500),
  );

  const matchingService = createEnvelopeService({ databasePath, privateKeyPem, clock });
  matchingService.close();

  const oidcDatabasePath = join(directory, "oidc.db");
  const oidcService = createEnvelopeService({
    databasePath: oidcDatabasePath,
    privateKeyPem,
    authenticationMode: "oidc",
    identityTrustDomainId: TEST_OIDC_TRUST_DOMAIN_ID,
    clock,
  });
  oidcService.close();
  assert.throws(
    () =>
      createEnvelopeService({
        databasePath: oidcDatabasePath,
        privateKeyPem,
        authenticationMode: "oidc",
        identityTrustDomainId: `sha256:${"f".repeat(64)}`,
        clock,
      }),
    isParimitError("RECEIPT_KEY_MISMATCH", 500),
  );
});

test("deleting a v3 receipt root cannot rebind existing approval and envelope evidence", () => {
  const directory = mkdtempSync(join(tmpdir(), "parimit-unattested-auth-history-"));
  const databasePath = join(directory, "parimit.db");
  const privateKeyPem = signingKeyPem();
  const clock = () => new Date("2026-09-20T11:52:00.000Z");

  const legacyDemoService = createEnvelopeService({ databasePath, privateKeyPem, clock });
  const created = legacyDemoService.createIntent(proposal("legacy-auth-mode-history"));
  legacyDemoService.approveIntent(created.id, "demo-header-reviewer", "approver", "APPROVE");
  legacyDemoService.issueAuthorizationEnvelope(
    created.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "root-deletion-envelope",
      expires_in_seconds: 60,
    },
    "demo-header-reviewer",
    "approver",
  );
  legacyDemoService.database
    .prepare("DELETE FROM service_metadata WHERE name = ?")
    .run("receipt_integrity_root_v1");
  legacyDemoService.close();

  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem,
        authenticationMode: "oidc",
        clock,
      }),
    isParimitError("TRUST_ROOT_MISSING", 500),
  );
  assert.throws(
    () =>
      createEnvelopeService({
        databasePath,
        privateKeyPem,
        envelopeAudience: "urn:ainxt:deployment:retargeted-consumer",
        clock,
      }),
    isParimitError("TRUST_ROOT_MISSING", 500),
  );
});

test("fractional issuance preserves audit chronology and refuses a same-second clock rewind", (t) => {
  let now = new Date("2026-09-20T11:55:00.800Z");
  const service = createEnvelopeService({ clock: () => now });
  t.after(() => service.close());

  const created = service.createIntent(proposal("envelope-fractional-clock"));
  now = new Date("2026-09-20T11:55:01.900Z");
  const approved = service.approveIntent(
    created.id,
    "human-fractional",
    "approver",
    "APPROVE",
  );
  now = new Date("2026-09-20T11:55:01.100Z");
  assert.throws(
    () =>
      service.issueAuthorizationEnvelope(
        created.id,
        {
          audience: "urn:ainxt:deployment:consumer-01",
          idempotency_key: "issue-fractional-clock",
          expires_in_seconds: 60,
        },
        "human-fractional",
        "approver",
      ),
    isParimitError("ENVELOPE_INVALID", 409),
  );
  assert.equal(
    (
      service.database
        .prepare("SELECT COUNT(*) AS count FROM authorization_envelopes WHERE intent_id = ?")
        .get(created.id) as { count: number }
    ).count,
    0,
  );
  assert.equal(
    service
      .getAudit(created.id)
      .filter((event) => event.event_type === "EVIDENCE_ENVELOPE_ISSUED").length,
    0,
  );
  assert.equal(service.verifyIntegrity(created.id).valid, true);

  now = new Date("2026-09-20T11:55:01.950Z");
  const envelope = service.issueAuthorizationEnvelope(
    created.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-fractional-clock",
      expires_in_seconds: 60,
    },
    "human-fractional",
    "approver",
  );

  assert.equal(approved.receipt?.fully_approved_at, "2026-09-20T11:55:01.900Z");
  assert.equal(
    envelope.claims.iat,
    Math.floor(Date.parse("2026-09-20T11:55:01.950Z") / 1_000),
  );
  const issueEvent = service
    .getAudit(created.id)
    .find((event) => event.event_type === "EVIDENCE_ENVELOPE_ISSUED");
  assert.equal(issueEvent?.occurred_at, "2026-09-20T11:55:01.950Z");

  now = new Date("2026-09-20T11:55:01.100Z");
  assert.throws(
    () =>
      service.consumeAuthorizationEnvelope(
        envelope.compact_jws,
        "urn:ainxt:deployment:consumer-01",
        "consumer-fractional",
        "consumer",
        "consume-fractional-clock",
      ),
    isParimitError("ENVELOPE_INVALID", 409),
  );
  now = new Date("2026-09-20T11:55:01.975Z");
  assert.equal(
    service.consumeAuthorizationEnvelope(
      envelope.compact_jws,
      "urn:ainxt:deployment:consumer-01",
      "consumer-fractional",
      "consumer",
      "consume-fractional-clock",
    ).consumption.state,
    "CONSUMED",
  );
  assert.equal(service.verifyIntegrity(created.id).valid, true);
});

test("tamper, wrong audience, exact expiry, and protected key-registry changes fail closed", (t) => {
  let now = new Date("2026-09-20T12:00:00.000Z");
  const service = createEnvelopeService({ clock: () => now });
  t.after(() => service.close());
  const created = service.createIntent(proposal("envelope-negative"));
  now = new Date("2026-09-20T12:01:00.000Z");
  service.approveIntent(created.id, "human-a", "approver", "APPROVE");
  const envelope = service.issueAuthorizationEnvelope(
    created.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-negative-001",
      expires_in_seconds: 60,
    },
    "human-a",
    "approver",
  );

  const parts = envelope.compact_jws.split(".");
  parts[1] = `${parts[1]!.slice(0, -1)}${parts[1]!.endsWith("A") ? "B" : "A"}`;
  const tampered = service.verifyAuthorizationEnvelope(
    parts.join("."),
    "urn:ainxt:deployment:consumer-01",
  );
  assert.equal(tampered.valid, false);
  assert.equal(tampered.signature_valid, false);
  assert.equal(
    service.verifyAuthorizationEnvelope(envelope.compact_jws, "urn:other:consumer").valid,
    false,
  );

  now = new Date("2026-09-20T12:02:00.000Z");
  const expired = service.verifyAuthorizationEnvelope(
    envelope.compact_jws,
    "urn:ainxt:deployment:consumer-01",
  );
  assert.equal(expired.valid, false);
  assert.equal(expired.time_valid, false);

  service.database
    .prepare("UPDATE envelope_signing_keys SET public_jwk = '{}' WHERE key_id = ?")
    .run(envelope.signature.key_id);
  assert.throws(
    () => service.envelopeJwks(),
    isParimitError("SIGNING_KEY_INTEGRITY_FAILURE", 500),
  );
});

test("envelope issuance and consumption metadata are reconciled with audit evidence", (t) => {
  const issueService = createEnvelopeService({
    clock: () => new Date("2026-09-20T13:00:00.000Z"),
  });
  t.after(() => issueService.close());
  const issuedIntent = issueService.createIntent(proposal("envelope-issue-row-tamper"));
  issueService.approveIntent(issuedIntent.id, "human-a", "approver", "APPROVE");
  const issuedEnvelope = issueService.issueAuthorizationEnvelope(
    issuedIntent.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-row-original",
    },
    "human-a",
    "approver",
  );
  issueService.database
    .prepare("UPDATE authorization_envelopes SET issuance_idempotency_key = ? WHERE id = ?")
    .run("issue-row-tampered", issuedEnvelope.claims.jti);
  assert.equal(issueService.verifyIntegrity(issuedIntent.id).valid, false);

  const consumptionService = createEnvelopeService({
    clock: () => new Date("2026-09-20T14:00:00.000Z"),
  });
  t.after(() => consumptionService.close());
  const consumedIntent = consumptionService.createIntent(proposal("envelope-consume-row-tamper"));
  consumptionService.approveIntent(consumedIntent.id, "human-b", "approver", "APPROVE");
  const consumable = consumptionService.issueAuthorizationEnvelope(
    consumedIntent.id,
    {
      audience: "urn:ainxt:deployment:consumer-01",
      idempotency_key: "issue-consume-row",
    },
    "human-b",
    "approver",
  );
  consumptionService.consumeAuthorizationEnvelope(
    consumable.compact_jws,
    "urn:ainxt:deployment:consumer-01",
    "consumer-a",
    "consumer",
    "consume-row-original",
  );
  consumptionService.database
    .prepare("UPDATE authorization_envelopes SET consumption_idempotency_key = ? WHERE id = ?")
    .run("consume-row-tampered", consumable.claims.jti);
  assert.equal(consumptionService.verifyIntegrity(consumedIntent.id).valid, false);
});
