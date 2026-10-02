# ADR 0005: PostgreSQL remains a non-selectable vertical slice

- Status: Accepted
- Date: 2026-10-02

## Context

The SQLite service is synchronous and owns schema bootstrap, integrity
verification, approvals, observations, signed envelopes, and one-time envelope
consumption. Replacing its database behind a configuration flag before those
behaviors have parity would turn a durability experiment into an unsafe product
claim.

## Decision

Add a Promise-based repository seam and one PostgreSQL vertical slice for:

- initial proposal creation;
- agent-scoped idempotent replay;
- daily-exposure calculation under a per-agent lock;
- atomic initial audit append; and
- normalized repeatable-read lookup.

Run mutations under `SERIALIZABLE`, retry only the whole idempotent transaction
with a fresh pool checkout and transaction, and retain PostgreSQL `BIGINT`
sequences as decimal strings. Live tests must use two independent pools and cover duplicate
and conflicting idempotency requests, a daily-exposure race, rollback between
intent and audit insertion, and competing audit appends.

`POSTGRES_RUNTIME_SUPPORT.runtimeSelectable` remains `false`. No database URL,
deployment profile, or production runtime dependency is introduced.

## Consequences

This slice validates the riskiest creation-time concurrency assumptions without
changing the running application. It does not provide approval, cancellation,
expiry, integrity, envelope, observation, backup, restore, multi-tenant, or
operational parity. Those gates must land before PostgreSQL can be selected by
the service or described as production support.

This decision changes storage engineering only. It adds no execution route,
payment-provider credential, UPI connection, or money-movement authority.
