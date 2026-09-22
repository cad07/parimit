# ADR 0004: Optional AiNxt trusted-sidecar reference adapter

- Status: accepted design; contract and local OIDC integration tests implemented; live acceptance pending
- Date: 2026-09-22
- Scope: proposal drafting only

## Context

NPCI publishes AiNxt OS as a governed runtime for AI applications and agents.
Parimit is independently implemented and narrower: it binds exact payment
intent, deterministic policy, separate human approval, signed evidence, and a
non-dispatchable boundary.

AiNxt's current public repository has a documented HTTP/SSE docking contract.
Its native HTTP connector abstraction is compile-time, not dynamically
registerable in the shipped runtime. Its MCP implementation is wire-compatible
with Parimit's local MCP server, but upstream still labels MCP design-only, and
Parimit disables stdio MCP in OIDC mode because stdio lacks verified actor
binding.

## Decision

Ship an optional trusted-sidecar adapter under `integrations/ainxt/` that:

1. anchors the source review to an exact AiNxt commit and separately records the
   runtime-reported control-plane SHA;
2. validates Parimit's proposal-only safety metadata and OIDC `agent` identity;
3. sends only one of a closed set of code-owned synthetic fixture turns to
   AiNxt's `POST /v1/chat` SSE surface;
4. treats all model output as untrusted and validates an exact closed schema;
5. injects Parimit's verified actor identifier server-side;
6. simulates policy before persistence; and
7. exposes only simulate, create, get, and cancel for the agent's own proposals.

The Parimit bearer token is never sent to AiNxt. This alpha requires a loopback
AiNxt trusted-gateway sidecar and emits a derived user plus configured
department with only `chat.send`; remote and `jwt-sso` AiNxt modes are deferred.
Approval, evidence issuance, verification, consumption, mock outcomes, and
execution stay outside the adapter.

## Consequences

- Parimit remains runtime-neutral; AiNxt is optional.
- The reference flow can demonstrate complementary behavior without claiming
  NPCI endorsement, UPI integration, or money movement.
- Invalid, incomplete, oversized, non-SSE, or non-JSON model output fails
  before Parimit simulation or persistence.
- Same-process retries reuse one validated draft. Across restarts, exact fixture
  matching makes every accepted draft deterministic; model drift fails before
  Parimit. A durable ledger remains required before accepting open-ended input.
- A simulation denial makes no create request. A policy change between
  simulation and atomic creation may leave a non-actionable `POLICY_DENIED`
  audit record.
- A native model-invoked connector remains deferred until upstream offers a
  stable registration and authenticated transport path or a reviewed custom
  AiNxt build is justified by a pilot partner.
- AtOM and any UPI/Reserve Pay executor remain separate future decisions.

## Acceptance gate

The compatibility pilot is accepted only when one supported synthetic fixture
produces one `AWAITING_APPROVAL` proposal, a same-process retry replays that
proposal, a simulation denial makes no create request, a creation-time denial
remains non-actionable, and the agent cannot reach approval, evidence, or
execution operations. Passing automated contract and in-process OIDC tests does
not constitute a live AiNxt run, the separate interactive Keycloak acceptance,
or any external/NPCI acceptance.
