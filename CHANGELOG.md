# Changelog

All notable changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/) after its first stable
release.

## [Unreleased]

### Added

- Added OIDC bearer-token verification with issuer, audience, signature,
  lifetime, algorithm, JWKS rotation, and fail-closed role-mapping checks.
- Added authenticated identity discovery and server-enforced `agent`,
  `approver`, and `admin` route boundaries, including agent ownership scope.
- Added a dependency-free, role-shaped TypeScript SDK preview and a pilot
  client example with no execution capability.
- Added a conservative single-instance, single-tenant OIDC pilot deployment
  guide, Compose profile, acceptance criteria, backup, rollback, and stop
  procedures.
- Added a PostgreSQL 14+ schema and transaction contract covering per-agent
  policy locks, per-intent mutation locks, consistent integrity snapshots,
  append-only evidence, audit-fork prevention, and stable observation order.

### Changed

- Protected every REST operation except safety metadata and preflight with an
  authenticated identity; local demo headers now require explicit demo mode
  and loopback isolation (or the documented host-loopback container escape
  hatch).
- Advanced runtime, MCP, OpenAPI, and SDK metadata to `0.1.0-alpha.2`.
- Disabled stdio MCP in OIDC mode until that transport can bind a verified
  actor identity; the hosted pilot remains REST/SDK-only.
- Hardened identity handling with explicit server-side role mappings,
  provider/service mode matching, bounded token lifetimes and JWKS streaming,
  RSA key-strength checks, ownership-first cancellation, and generic internal
  error responses.
- Serialized idempotency, policy evaluation, and lifecycle transitions inside
  immediate SQLite write transactions, and expanded integrity verification to
  bind review event types, state thresholds, and ordered observation evidence.

### Known limitations

- The PostgreSQL work is schema and contract only. The running service remains
  SQLite-backed until an async repository port and live parity/concurrency
  suite are complete.
- The hosted pilot is REST/SDK-only; the browser dashboard remains a local demo
  because no browser OIDC login or token flow is shipped.

## [0.1.0-alpha.1] - 2026-09-19

### Security

- Bound every newly recorded mock observation to its hash-linked audit event by
  stable observation ID and reconciled observation count, order, status, provider
  reference, source, timestamp, retry policy, and no-money flag on every read.
- Made intent, list, and audit reads fail closed when stored observation evidence
  diverges from the audit history. Existing alpha events without an observation ID
  remain readable only through exact legacy field, order, and count matching.
- Added adversarial coverage for observation edits, deletion, insertion, and
  reordering.

### Changed

- Rejected unknown fields in human-decision and demo-observation REST bodies,
  enforced documented agent-filter bounds, and normalized malformed proposal
  identifiers to `400 INVALID_PATH` so runtime validation matches OpenAPI.
- Documented request-size and integrity-failure responses in OpenAPI.

## [0.1.0-alpha.0] - 2026-09-19

### Added

- Adopted the Parimit name: bounded authority for agent payments.
- Proposal-only REST and MCP interfaces.
- Deterministic payment-intent validation and policy evaluation.
- Human approval flow with exact-intent binding and dual-control support.
- Hash-chained audit events and non-dispatchable authorization receipts.
- Versioned v2 intent digests that bind the initial state and stored policy decision,
  with archival read compatibility for existing v1 database rows. Legacy v1 rows
  cannot be mutated, and their authorization state is rejected as untrusted.
- Cross-checks between lifecycle state, valid distinct approvals, policy metadata,
  observations, and hash-linked audit evidence.
- Mock outcome simulator, browser dashboard, tests, and boundary scanner.
- Open-source governance, security, architecture, and integration guidance.
