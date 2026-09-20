# PostgreSQL integration track

## Status

This directory is a reviewed starting point for durable storage, not a runtime
feature. `ParimitService` remains synchronous and directly coupled to
`node:sqlite`; setting a database URL does nothing. The repository must not
claim PostgreSQL runtime support until the async port and live parity suite in
this document are complete.

What is available now:

- a PostgreSQL 14+ schema preserving the tenant-bound proposal, approval,
  observation, signed-envelope, one-time-consumption, signing-key, and ordered
  hash-chain data model;
- database constraints for the current validation boundary;
- append-only triggers for approval, observation, and audit evidence;
- immutable intent evidence with only valid outward status transitions;
- a unique `(intent_id, previous_hash)` constraint to reject audit forks;
- stable observation insertion order to replace SQLite `rowid`;
- tenant-scoped agent idempotency and envelope-to-intent constraints;
- append-only signing keys and immutable envelope evidence with a one-way
  consumption transition;
- a receipt-key HMAC checkpoint over the complete signing-key registry, updated
  atomically with each key insert so missing historical keys fail closed;
- an append-only, fixed-name `receipt_integrity_root_v1` record binding the
  configured receipt secret and tenant to this database; alpha.3 does not
  rotate this root;
- a small driver-neutral transaction and audit-append contract in
  `src/storage/postgres-contract.ts`;
- dependency-free contract tests.

What is not available now:

- a PostgreSQL driver or connection pool;
- a repository implementation for every service operation;
- a runtime configuration switch;
- SQLite-to-PostgreSQL data migration;
- a live PostgreSQL parity or concurrency test in CI;
- multi-tenant request routing, row-level security, backups, or operational
  monitoring.

The schema is therefore suitable for development of the adapter, not a claim
that the alpha can be deployed on PostgreSQL today.

## Why this is not a drop-in database change

SQLite's `BEGIN IMMEDIATE` serializes the current synchronous process. With
PostgreSQL, several application instances can race unless the service makes
locking and snapshots explicit. The port must preserve these rules:

1. Run every mutation in a `SERIALIZABLE` transaction.
2. Lock the `policy_subjects` row before idempotency lookup, daily-exposure
   calculation, policy decision, and proposal insertion for an agent.
3. Lock the intent row before verifying or changing an existing proposal.
4. Re-read and verify intent, approvals, observations, and audit events inside
   that same transaction; a verification performed before the lock is a
   time-of-check/time-of-use bug.
5. Insert state, evidence, and the corresponding audit event atomically.
6. Run read-only integrity checks in one `REPEATABLE READ READ ONLY` snapshot.
7. Retry the entire idempotent transaction, with a low bounded retry count,
   after PostgreSQL SQLSTATE `40001` (serialization failure) or `40P01`
   (deadlock). Never retry just the final statement.
8. Order observations by their PostgreSQL `sequence`, never by timestamps.

The migration also locks the parent intent before each audit insert and
rejects a second event using the same predecessor. These are database
backstops; application code must still recompute and verify the complete
intent, receipt, state, and audit hashes before returning data.

## Applying the schema in a disposable database

Use a dedicated empty database and a migration-owner credential:

```sh
psql "$PARIMIT_TEST_POSTGRES_URL" \
  --set ON_ERROR_STOP=1 \
  --file db/postgres/001_initial.sql
```

The migration is deliberately apply-once rather than superficially
idempotent. A real migration runner must record its checksum and refuse edited
or out-of-order migrations.

Use separate migration-owner and runtime roles. The runtime role should own no
tables and should receive only:

- `USAGE` on schema `parimit`;
- `SELECT` and `INSERT` on `policy_subjects` plus the privilege needed for its
  row lock;
- `SELECT` and `INSERT` on `intents`, with `UPDATE (status, state_version)` only;
- `SELECT` and `INSERT` on `approvals`, `observations`, and `audit_events`;
- `SELECT` and `INSERT` on `envelope_signing_keys` and
  `authorization_envelopes`, with `UPDATE (consumed_at, consumed_by,
  consumption_idempotency_key)` only on envelopes;
- `SELECT` and `INSERT` on `envelope_signing_key_registry_state`, with
  `UPDATE (value)` but no delete privilege; key insertion and checkpoint
  replacement must share one transaction;
- `SELECT` and `INSERT` on `service_integrity_roots`, with no update or delete
  privilege;
- required sequence privileges for identity columns.

Do not grant runtime `DELETE`, schema `CREATE`, trigger-management, or
ownership privileges. Triggers are defence in depth, not a substitute for
role separation; a table owner or superuser can disable them.

## Exact runtime integration sequence

1. Define an async repository interface covering every storage operation now
   embedded in `ParimitService`. Keep canonical hashing and policy decisions in
   the domain layer.
2. Add a maintained PostgreSQL driver and a bounded pool at the process edge.
   Convert PostgreSQL `BIGINT` values deliberately: amounts must remain within
   JavaScript's safe-integer limit, while audit and observation sequences
   should remain decimal strings or become a documented API-wide bigint type.
3. Implement the PostgreSQL repository with the helpers in
   `src/storage/postgres-contract.ts`. Never share a checked-out transaction
   client across requests.
4. Map `jsonb` policy reasons and audit payloads back into domain values before
   canonical hashing. Timestamp columns intentionally retain exact
   `Date#toISOString()` text because those bytes participate in signatures and
   hashes. The domain checks both the exact millisecond-UTC shape and a
   PostgreSQL UTC parse/format round trip, so impossible calendar dates are
   rejected rather than treated as canonical text.
5. Register `receipt_integrity_root_v1` before registering envelope signing
   keys. Compute the same HMAC over canonical
   `{ version: "parimit-receipt-integrity-root-v1", tenant_id,
   envelope_issuer, envelope_audience, envelope_maximum_lifetime_seconds,
   authentication_mode, identity_trust_domain_id,
   policy_configuration_digest }` as SQLite. If
   the row exists, compare it in constant time and fail startup on mismatch. If
   it is absent on a genuine pre-v3 database, verify all existing approval
   receipts and signing-key attestations before the first insert. A v3 database
   with a missing root is corruption and must fail closed. Never update, delete,
   or upsert the root: alpha.3 receipt-secret or trust-configuration rotation
   requires a future explicit migration design.
   In the same bootstrap transaction, insert
   `envelope_signing_key_registry_state_v1` as the receipt-key HMAC of canonical
   `{ version: "parimit-envelope-signing-key-registry-state-v1", keys: [] }`.
   For every key rotation, sort the complete semantic rows by `key_id`; each
   member is `{ key_id, public_jwk, created_at, attestation_hmac }`. Insert the
   new row and replace the checkpoint HMAC in one transaction after validating
   all row attestations and the previous checkpoint. A missing checkpoint on a
   v3 database, or any full-set mismatch, is corruption and must fail closed.
6. Port operations in this order:
   create/idempotent replay, reads and integrity verification, approval,
   rejection, cancellation, expiry, envelope-key registration, envelope
   issuance/verification/consumption, and mock observation.
7. Insert every authorization envelope with all three consumption columns
   null. The only legal update changes that exact null triple to a complete
   `(consumed_at, consumed_by, consumption_idempotency_key)` triple, with
   `issued_at <= consumed_at < expires_at`, in the same transaction as its
   audit event.
8. Keep the SQLite repository for local use while running the same behavioral
   suite against both repositories. Do not add a runtime storage selector until
   parity is green.
9. Add live PostgreSQL concurrency tests for duplicate idempotency keys, daily
   exposure, two simultaneous final approvals, approval-versus-cancellation,
   expiry-versus-approval, concurrent envelope issuance, concurrent one-time
   consumption, consumption-versus-expiry, competing audit appends, and
   `IN_DOUBT` versus a later observation.
10. Add backup/restore and point-in-time-recovery drills, connection saturation
   metrics, slow-query visibility, migration rollback policy, and secret
   lifecycle procedures before any external pilot depends on the database.
   The alpha.3 receipt secret is explicitly excluded from rotation because its
   database-bound integrity root is non-rotatable.

## Required parity gates

Runtime support becomes truthful only when all of these pass against a real
PostgreSQL server:

- every existing service and HTTP/MCP test through the PostgreSQL repository;
- corruption tests for every hashed or receipt-bound field;
- concurrent race tests proving the locks above;
- envelope-signing-key rotation, envelope-tamper, audience, expiry, and replay
  tests;
- startup mismatch and mutation tests for the non-rotatable receipt integrity
  root;
- process-kill tests proving mutation and audit evidence commit together;
- migration checks on every supported PostgreSQL major version;
- restore verification from an encrypted backup;
- a boundary check confirming that no payment executor, provider credential,
  or money-movement route was introduced.

## Remaining product decision: tenancy

The schema binds tenant identifiers into policy subjects, intents, agent
idempotency, and authorization-envelope relationships. That is a necessary
storage invariant, not a complete multi-tenant product. The running service
still has one configured tenant and no request-level tenant routing or tenant
claim. The future adapter must make every authorization-aware query
tenant-scoped and should add row-level security as a secondary control. Until
those controls and cross-tenant negative tests exist, a PostgreSQL-backed
deployment must still be treated as single-tenant only.

PostgreSQL changes durability and concurrency characteristics; it does not
change Parimit's boundary. This schema contains no payment execution table,
provider credential, dispatch queue, or live rail connector.
