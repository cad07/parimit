# PostgreSQL integration track

## Status

This directory is a reviewed starting point for durable storage, not a runtime
feature. `ParimitService` remains synchronous and directly coupled to
`node:sqlite`; setting a database URL does nothing. The repository must not
claim PostgreSQL runtime support until the async port and live parity suite in
this document are complete.

What is available now:

- a PostgreSQL 14+ schema preserving the proposal, approval, observation, and
  ordered hash-chain data model;
- database constraints for the current validation boundary;
- append-only triggers for approval, observation, and audit evidence;
- immutable intent evidence with only valid outward status transitions;
- a unique `(intent_id, previous_hash)` constraint to reject audit forks;
- stable observation insertion order to replace SQLite `rowid`;
- a small driver-neutral transaction and audit-append contract in
  `src/storage/postgres-contract.ts`;
- dependency-free contract tests.

What is not available now:

- a PostgreSQL driver or connection pool;
- a repository implementation for every service operation;
- a runtime configuration switch;
- SQLite-to-PostgreSQL data migration;
- a live PostgreSQL parity or concurrency test in CI;
- multi-tenancy, row-level security, backups, or operational monitoring.

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
- `SELECT` and `INSERT` on `intents`, with `UPDATE (status)` only;
- `SELECT` and `INSERT` on `approvals`, `observations`, and `audit_events`;
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
   hashes.
5. Port operations in this order:
   create/idempotent replay, reads and integrity verification, approval,
   rejection, cancellation, expiry, and mock observation.
6. Keep the SQLite repository for local use while running the same behavioral
   suite against both repositories. Do not add a runtime storage selector until
   parity is green.
7. Add live PostgreSQL concurrency tests for duplicate idempotency keys, daily
   exposure, two simultaneous final approvals, approval-versus-cancellation,
   expiry-versus-approval, competing audit appends, and `IN_DOUBT` versus a
   later observation.
8. Add backup/restore and point-in-time-recovery drills, connection saturation
   metrics, slow-query visibility, migration rollback policy, and secret
   rotation before any external pilot depends on the database.

## Required parity gates

Runtime support becomes truthful only when all of these pass against a real
PostgreSQL server:

- every existing service and HTTP/MCP test through the PostgreSQL repository;
- corruption tests for every hashed or receipt-bound field;
- concurrent race tests proving the locks above;
- process-kill tests proving mutation and audit evidence commit together;
- migration checks on every supported PostgreSQL major version;
- restore verification from an encrypted backup;
- a boundary check confirming that no payment executor, provider credential,
  or money-movement route was introduced.

## Remaining product decision: tenancy

The migration mirrors today's single-tenant alpha. An external multi-tenant
pilot needs a tenant model before runtime wiring: tenant identifiers on every
row, tenant-scoped idempotency and actor constraints, authorization-aware
queries, and preferably row-level security as a secondary control. Until that
design lands and is tested, a PostgreSQL-backed deployment must be treated as
single-tenant only.

PostgreSQL changes durability and concurrency characteristics; it does not
change Parimit's boundary. This schema contains no payment execution table,
provider credential, dispatch queue, or live rail connector.
