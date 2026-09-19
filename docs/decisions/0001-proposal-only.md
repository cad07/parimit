# ADR 0001: Proposal-only agent boundary

- Status: Accepted
- Date: 2026-09-19

## Context

AI agents can be manipulated by prompt injection, mistaken inference, poisoned
context, excessive authority, or compromised tools. Payment execution is an
irreversible or costly effect. NPCI AiNxt OS's public payment boundary also
models payment initiation as non-dispatchable and keeps settlement logic free
of bank I/O.

## Decision

Parimit exposes only proposal, read, eligible cancellation, and explicit
mock-simulation operations to agents and MCP clients. Human approval is a
separate authority. The default build has no live payment connector. Approval
produces a non-dispatchable receipt, not a rail instruction.

The domain and policy core remains deterministic and network-free. Authority-
bearing MCP tool names and core network imports are rejected in CI.

## Consequences

- The project can safely demonstrate policy and human-in-the-loop workflows
  without bank access or payment credentials.
- Users cannot turn the demo into a live payment product by adding environment
  variables.
- A real integration requires a separate deterministic executor, regulated
  provider relationship, new threat model, and explicit security review.
- Some end-to-end experiences must remain simulated in this repository.

## Provenance

This decision is independently implemented and was informed by the public
AiNxt OS documentation at audited commit
[`5b6fbb90eb715384559256f7257e4d661cb1d17b`](https://github.com/NPCI/ainxt-os/tree/5b6fbb90eb715384559256f7257e4d661cb1d17b).
No AiNxt code was copied into the initial implementation.
