# Parimit Authorization Envelope v1

Status: experimental in `v0.1.0-alpha.3`.

The Authorization Envelope is a portable, public-key-verifiable record that
Parimit observed the required human approvals for one exact proposal. It is a
governance evidence object, not a payment instruction or bearer capability.

Every signed envelope states all four safety facts explicitly:

- `payment_dispatch_authorized: false`
- `execution_authorized: false`
- `provider_instruction: false`
- `moves_money: false`

Parimit has no UPI, bank, PSP, settlement, mandate, collect, or payment-execution
route. Presenting or consuming an envelope never changes that boundary.

## Lifecycle

1. An agent creates a tenant-bound `parimit-payment-intent-v3` proposal.
2. Deterministic policy records one or two required human approvals.
3. Distinct human reviewers approve the exact intent before its deadline.
4. A verified `approver` or `admin` issues a short-lived envelope for one
   configured audience.
5. A relying party verifies the compact JWS against a trusted Parimit public
   key, expected issuer, audience, tenant, time, intent digest, approval set,
   authorization-state version, and source audit tip.
6. A verified `consumer` or `admin` may atomically mark the envelope consumed.
   That transition records evidence acceptance only; it performs no downstream
   action.

Issuance is idempotent for `(tenant, intent, state version, audience)`. The same
issuance key and requested lifetime return the byte-identical compact JWS and
do not create another audit event. Reusing the key with a different lifetime,
or using a different key for the same scope, fails with an idempotency conflict.

Alpha.3 deliberately permits only one envelope for that scope. An expired,
unconsumed envelope is not replaced or extended; the agent must create a fresh
proposal and the human review must be repeated. This keeps expiry from becoming
an implicit authorization-renewal path.

## JWS profile

The envelope is compact JWS with a protected header containing only:

```json
{
  "alg": "EdDSA",
  "kid": "<trusted-key-id>",
  "typ": "parimit-authz-envelope+jws"
}
```

Version 1 supports Ed25519 only. Verification rejects unknown algorithms,
extra protected-header fields, embedded keys and key URLs, padded or
non-canonical base64url, invalid UTF-8, non-object JSON, non-canonical payload
serialization, wrong key type, and signatures that are not exactly 64 bytes.

The payload binds:

- standard trust claims: `iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`, plus
  exact millisecond `issued_at` evidence;
- the deployment-trusted `tenant_id`;
- the authentication method, whether it was cryptographically verified, and
  the exact identity trust-domain identifier;
- the exact v3 intent snapshot and SHA-256 digest;
- a separate policy-decision digest, including the deployment policy-
  configuration digest;
- `AUTHORIZED_NO_DISPATCH`, the authorization-state version, threshold and
  deterministically ordered approver set;
- a 256-bit random nonce and one-use limit;
- the event count and audit-chain tip before issuance; and
- the explicit evidence-only capability boundary.

Compact JWS provides integrity and authenticity, not confidentiality. The
purpose and opaque payee alias are readable by anyone holding the artifact. Do
not put a VPA, bank account, phone number, card identifier, secret, or sensitive
free text into a Parimit proposal.

The complete request and response schema is normative in
[`../openapi.yaml`](../openapi.yaml). The intentionally small, ASCII-only public
signature vector in
[`../test-vectors/authorization-envelope-v1.json`](../test-vectors/authorization-envelope-v1.json)
checks the Ed25519 compact-JWS profile. Independent implementations must also
use the Unicode, nested-object and numeric-looking-key vectors in
[`../test-vectors/canonical-json-v1.json`](../test-vectors/canonical-json-v1.json).

### Canonical JSON and digest formulas

`parimit-canonical-json-v1` is a deliberately small deterministic serializer;
it is not RFC 8785/JCS. Recursively sort each object's own enumerable keys by
ECMAScript's default UTF-16 code-unit ordering, preserve array order, and emit
no insignificant whitespace. Serialize every key and every string, finite
number, boolean or null with ECMAScript `JSON.stringify` semantics, then encode
the resulting text as UTF-8. Non-ASCII characters remain non-ASCII rather than
being converted to `\u` escapes. Undefined values are omitted from objects and
are invalid inside arrays or at the top level; sparse array holes are also
invalid. Envelope integers are finite JavaScript safe integers.

`iat` and `nbf` are the whole-second NumericDate containing `issued_at`; they
are used for ordinary token-validity checks. `issued_at` is the authoritative
signed timestamp for ordering exact proposal, approval and audit evidence, so
sub-second events never appear reversed merely because NumericDate was rounded.

All SHA-256 values below are lowercase hex over the UTF-8 bytes of that exact
canonical text:

```text
intent.digest.value = sha256(canonicalJson(intent.snapshot))
policy_digest.value = sha256(canonicalJson(intent.snapshot.policy))
decision.approval_set_digest.value = sha256(canonicalJson(decision.approvals))
```

Approval entries are ordered first by exact `decided_at`, then by `subject`,
using ECMAScript UTF-16 code-unit comparison rather than locale collation.

Each signed approval `record_digest` is issuer-internal evidence over canonical
`{actor_id, actor_role, decision, intent_hash, created_at, receipt_hmac}`. The
HMAC is deliberately not carried in the envelope, so an offline recipient can
verify the signed `record_digest` value but cannot independently reconstruct
its preimage. Online Parimit verification reconciles it with local records.

The signed policy `config_digest` is SHA-256 over the canonical form of this
exact preimage:

```json
{
  "version": "parimit-policy-configuration-v1",
  "rules_version": "<exact non-empty version>",
  "per_transaction_limit_minor": "<decimal integer string>",
  "daily_agent_limit_minor": "<decimal integer string>",
  "dual_approval_threshold_minor": "<decimal integer string>",
  "default_expiry_seconds": 1800,
  "maximum_expiry_seconds": 86400,
  "blocked_payees": ["<normalized values sorted by UTF-16 code unit>"],
  "allowed_payees": null
}
```

`allowed_payees` is either `null` or a sorted normalized array. The published
[configuration digest vector](../test-vectors/configuration-digests-v1.json)
fixes the exact string-versus-number representation, canonical text and digest.
A relying party that cares about a particular policy must pin this digest to an
out-of-band reviewed configuration; the human-readable rules version alone is
not enough.

## HTTP surfaces

| Method and path | Allowed roles | Effect |
| --- | --- | --- |
| `GET /.well-known/jwks.json` | public | Returns verification-only OKP JWKs; never private material |
| `POST /v1/intents/{id}/evidence-envelopes` | approver, admin | Idempotently signs evidence after full approval |
| `POST /v1/evidence-envelopes/verify` | approver, consumer, admin | Read-only verification; does not prevent replay |
| `POST /v1/evidence-envelopes/consume` | consumer, admin | Atomically records one-time evidence acceptance |

Issuance and consumption are deliberately absent from the MCP server and agent
SDK. An AI agent can propose and inspect its own proposal but cannot mint or
consume the review evidence that might later be used by another trust domain.

## Verification order

A relying party should fail closed in this order:

1. Enforce the 65,536-byte maximum and compact-JWS three-segment shape.
2. Parse the protected header and require the exact v1 algorithm and type.
3. Select `kid` only from the issuer's preconfigured JWKS trust relationship;
   never follow a URL supplied by the artifact.
4. Verify Ed25519 over the encoded protected header and payload.
5. Require the strict v1 claim schema and canonical JSON payload.
6. Compare exact issuer, audience, tenant and expected intent context.
7. Require signed `identity_assurance.authentication_method=oidc` and
   `cryptographically_verified=true` for an external pilot, and compare
   `trust_domain_id` with the relying party's pinned value. The OIDC identifier
   is `sha256:` plus the canonical digest of the exact versioned preimage in the
   identity guide and configuration vector. Demo-header envelopes use a fixed
   URN and deliberately fail this assurance gate.
8. Require `nbf <= now < exp` and a lifetime within deployment policy.
9. Recompute the intent, policy and approval-set digests and require the pinned
   policy-configuration digest when policy identity matters.
10. Require the signed capability boundary to remain entirely false.
11. Atomically claim `(jti, nonce)` in a durable replay ledger before taking
    any relying-party action.

The `/verify` endpoint performs steps relevant to the issuing Parimit instance,
including local issuance and current intent/audit binding. It intentionally does
not consume the artifact.

## Consumption and replay limits

The signed JWS is immutable; consumption state is stored separately. The first
successful consume operation records `consumed_at`, `consumed_by`, its request
idempotency key, and exactly one hash-linked audit event. The same consumer and
idempotency key receive an idempotent replay. Every different replay receives
`ENVELOPE_REPLAY_DETECTED`.

This alpha runtime uses one SQLite writer. Its atomic claim is credible only
inside that single service instance and database. Multiple offline verifiers
can all verify the same signature, so each independent relying party must keep
its own durable replay ledger or call one authoritative Parimit consumption
service. The proposed PostgreSQL contract preserves the one-way transition,
but PostgreSQL is not yet runtime-selectable.

## Keys and restart behaviour

Local demo mode creates an ephemeral Ed25519 key. Its public JWK is protected in
the SQLite registry, so previously issued envelopes remain mathematically
verifiable by that registry, but the demo configuration is not a production
trust anchor.

On first startup, a receipt-key HMAC root binds the database to its tenant,
envelope issuer, sole relying-party audience, maximum envelope lifetime,
authentication mode, exact identity trust domain and policy-configuration
digest. Later startup with a different receipt key or any different bound trust
value fails closed. An OIDC deployment also refuses to adopt pre-root approval
history because the original authentication mode cannot be proven. A v3
database whose root is missing is treated as corruption, not as a legacy
database that may be rebound. Alpha.3 does not migrate that root in place; a
deliberate identity, policy or envelope trust change requires a fresh database
and recovery set. Envelope-signing keys remain independently rotatable, with
historical public keys retained for verification.

Each signing-key row has its own receipt-key HMAC. SQLite additionally stores a
required receipt-key HMAC checkpoint over the complete semantic key set sorted
by `key_id`; the empty checkpoint is created with the schema, and key insertion
plus checkpoint replacement is one transaction. Startup, JWKS publication and
key lookup verify every row and the full-set checkpoint, so deleting a retained
historical row fails closed. Restoring an older internally consistent database
and checkpoint snapshot cannot be detected without an external monotonic
anchor; that remains an explicit alpha limitation.

Non-demo mode requires:

- a base64-encoded PKCS#8 Ed25519 private-key PEM supplied through protected
  secret injection;
- a stable tenant identifier;
- an explicit HTTPS or URN issuer; and
- exactly one explicit relying-party audience. Alpha.3 rejects multiple
  audiences because its broad `consumer` role is not yet bound to a per-client
  audience claim.

The public-key registry is append-only in the PostgreSQL design and HMAC-bound
in the current SQLite runtime. A new active private key creates a new `kid`,
while retained historical public keys continue verifying old envelopes. Managed
or hardware-backed signing, revocation status and an external transparency
anchor remain future work.

## AiNxt and AtOM integration boundary

An AiNxt-built agent or another agent runtime can create a Parimit proposal
through the existing OIDC-protected REST/SDK interface. After separate human
review, a trusted integration service can receive and verify the envelope.
AtOM-style change, onboarding or certification workflows could also transport
the artifact as evidence.

Neither integration turns the envelope into a UPI API. A real payment adapter
still requires an independently reviewed provider contract, credentials,
certification, reconciliation, dispute handling and regulatory approval. Those
capabilities are intentionally absent.
