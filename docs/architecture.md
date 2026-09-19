# Architecture

Parimit separates an untrusted agent-facing proposal plane from a
human-controlled decision plane. The shipped system ends at a mock simulator;
there is no live payment executor.

```mermaid
flowchart LR
    A[Untrusted AI agent] -->|propose, inspect, cancel| I[REST or MCP interface]
    H[Human operator] -->|approve or reject| D[Human dashboard]
    I --> V[Intent validation]
    V --> P[Deterministic policy]
    P --> S[(Proposal store)]
    D --> B[Approval service]
    B --> S
    B --> R[Non-dispatchable receipt]
    S --> L[Hash-chained audit log]
    R --> M[Mock outcome simulator]
    M --> L
    X[Bank / PSP / payment rail]:::blocked
    M -. no connection .-> X

    classDef blocked fill:#fff1f1,stroke:#c62828,stroke-dasharray: 5 5
```

## Trust zones

| Zone | Trust | Allowed capabilities |
| --- | --- | --- |
| Agent / MCP client | Untrusted | Propose, read, cancel eligible proposals, request mock simulation |
| Public REST edge | Untrusted input | Parse and validate; demo headers are spoofable, with no authentication or rate limiting |
| Domain and policy core | Trusted deterministic code | Validate and transition state; no network I/O |
| Human dashboard | Human-controlled demo surface | Approve or reject an exact immutable proposal |
| Store and audit log | Integrity-sensitive | Persist proposals and append events |
| Mock rail | Non-financial | Generate labelled demo outcomes only |
| Real provider | Out of scope | No connector exists in the default build |

## Core objects

**Payment proposal.** A request containing a generated identifier,
idempotency key, amount in minor units, ISO-style currency, payee reference,
purpose, timestamps, and policy context. Monetary values never use floating
point.

**Policy decision.** A deterministic result recording the rules and versions
that allowed, rejected, or escalated a proposal. A higher-risk proposal can
require two distinct human approvers.

**Approval.** A demo reviewer decision bound to the v2 digest of immutable
proposal inputs and the initial policy decision. The integrity verifier also
cross-checks later decisions and lifecycle state against the local event
history before returning an authorization receipt.

**Authorization receipt.** Evidence that policy and human decision conditions
were met. It is intentionally not shaped like a provider payment instruction
and has no dispatch method.

**Audit event.** A local record containing the previous event hash. Application
code appends events, but SQLite does not enforce append-only storage. The chain
detects isolated rewriting; it does not replace durable, externally anchored
audit storage.

## State model

```mermaid
stateDiagram-v2
    [*] --> POLICY_DENIED: policy rejects
    [*] --> AWAITING_APPROVAL: policy allows
    AWAITING_APPROVAL --> AUTHORIZED_NO_DISPATCH: required humans approve
    AWAITING_APPROVAL --> REJECTED: human rejects
    AWAITING_APPROVAL --> CANCELLED: eligible cancellation
    AWAITING_APPROVAL --> EXPIRED: time elapses and service runs
    state AUTHORIZED_NO_DISPATCH {
        [*] --> NO_OBSERVATION
        NO_OBSERVATION --> SUCCEEDED: demo observation
        NO_OBSERVATION --> FAILED: demo observation
        NO_OBSERVATION --> REVERSED: demo observation
        NO_OBSERVATION --> IN_DOUBT: demo uncertainty
        note right of IN_DOUBT
            Frozen in alpha:
            all later mock observations reject
        end note
    }
```

Terminal and exact names in the implementation are authoritative. No state in
this diagram means that funds were transferred. Other mock outcomes may be
replaced by a later mock outcome, but `IN_DOUBT` is fail-closed: after it is
recorded, the alpha rejects every later observation and exposes no
reconciliation mechanism.

## Process boundaries

The HTTP server serves the dashboard and REST API. The MCP process communicates
over standard input/output so protocol data is not mixed with ordinary logs.
Both call the same proposal-oriented application services. Domain and policy
modules do not import networking modules; the CI boundary scanner enforces that
constraint statically.

The alpha implementation is optimized for local evaluation. Production-grade
identity, tenancy, durable transactional storage, key management, and external
audit anchoring are deliberately not implied.

## Source provenance

This architecture is independently implemented. Its safety separation was
informed by NPCI AiNxt OS's public payment boundary at commit
[`5b6fbb90eb715384559256f7257e4d661cb1d17b`](https://github.com/NPCI/ainxt-os/tree/5b6fbb90eb715384559256f7257e4d661cb1d17b).
No AiNxt source code was copied into the initial implementation.
