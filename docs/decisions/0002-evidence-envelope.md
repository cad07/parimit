# ADR 0002: Public-key-verifiable evidence envelopes

- Status: accepted for alpha.3
- Date: 2026-09-20

## Context

Parimit's v1 approval receipt uses HMAC-SHA-256. It detects modification inside
one deployment, but an independent relying party cannot verify it without the
shared secret. The receipt also does not bind tenant, audience, a monotonic
authorization-state revision, one-time nonce, or replay state.

NPCI's public AiNxt and AtOM projects reinforce the need for a narrow
interoperability object between an agent runtime, human governance boundary and
ecosystem workflow. They do not provide a public UPI execution API, and Parimit
must not imply otherwise.

## Decision

Add `parimit-payment-intent-v3` and
`parimit-authorization-envelope-v1` with these constraints:

- v3 binds the deployment tenant into the immutable intent digest;
- authorization-relevant state changes increment a monotonic state version;
- only a fully approved, unexpired v3 proposal can produce an envelope;
- the envelope is canonical compact JWS signed only with Ed25519/EdDSA;
- the protected header carries no remote key location or embedded key;
- claims bind the exact intent, policy configuration, approvers, audience,
  tenant, exact millisecond issuance time, nonce and source audit tip;
- claims bind the exact identity trust-domain identifier and mark only
  OIDC-backed identities as cryptographically verified;
- the signed capability is evidence-only and explicitly non-dispatchable;
- issuance is unavailable to agents and MCP;
- consumption is a separate, audited, atomic one-way transition; and
- verification without a durable replay claim is not treated as one-time use.

Only one envelope exists for a tenant, intent state, and audience. Expiry does
not permit reissuance from the old approval state; a fresh proposal and review
are required.

Legacy v1/v2 intents remain readable and keep their historical digest rules.
They cannot mint v1 envelopes because tenant binding was absent when they were
created.

Authentication mode is database-bound. OIDC mode cannot adopt approval rows
from a database that predates that binding; the service cannot prove whether
those reviewers were authenticated or spoofable demo headers.

The receipt-key root also binds issuer, sole audience, maximum envelope
lifetime, identity trust domain and policy-configuration digest. A protected
full-registry checkpoint detects removal of historical signing keys. Missing
v3 roots or checkpoints fail closed rather than adopting the remaining rows.

## Consequences

The artifact can be checked with a public key and carried into another runtime
without sharing Parimit's HMAC secret. Exact audience, short expiry and replay
state sharply reduce ambiguous reuse.

The artifact is not confidential, not a provider instruction and not authority
to move funds. SQLite replay protection is single-instance only. Private-key
custody, revocation distribution, external audit anchoring and any real payment
adapter remain explicit later gates.
