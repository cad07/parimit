# API and MCP usage

The machine-readable REST contract is [`../openapi.yaml`](../openapi.yaml).
This page explains the safety semantics that a schema alone cannot express.

## REST rules

- Send and receive JSON.
- Express money as a decimal string in `amount.minor`; `"49900"` with `INR`
  means ₹499.00. Floating-point amounts are rejected.
- Supply `idempotency_key` in the proposal body. Its scope is the requesting
  agent; replaying it with different content returns a conflict.
- Call `GET /v1/identity` with the bearer token, then use the returned
  `actor_id` as `requested_by.id`. Identity substitution is rejected.
- Treat proposal identifiers and audit metadata as opaque.
- Do not infer that `AUTHORIZED_NO_DISPATCH` means paid. It means only that the
  configured approval condition was satisfied.
- A simulated outcome is always labelled as mock data.
- Recording `IN_DOUBT` freezes the mock observation stream. The REST endpoint
  rejects every later mock observation with HTTP `409` and code
  `IN_DOUBT_FROZEN`; the alpha has no reconciliation mechanism.

Local-demo proposal body (OIDC clients must replace `requested_by.id` with the
derived value returned by `/v1/identity`):

```json
{
  "idempotency_key": "demo-agent-2026-09-19-001",
  "requested_by": {
    "type": "agent",
    "id": "open-source-demo-agent"
  },
  "on_behalf_of": "demo-user",
  "amount": {
    "currency": "INR",
    "minor": "49900"
  },
  "payee_reference": "demo-merchant-001",
  "purpose": "Demo order 1042",
  "expires_in_seconds": 900
}
```

Use only fictional data. Exact routes, errors, and response fields are defined
in OpenAPI and may change before 1.0.

## MCP rules

The MCP transport is standard input/output. Protocol messages go to stdout;
diagnostic logs, if any, go to stderr. An MCP host should run the process with a
dedicated low-privilege OS identity and no payment credentials.
It is a local demo surface and refuses to start with
`PARIMIT_AUTH_MODE=oidc`: alpha.2 does not bind a verified OIDC identity to a
stdio MCP session. The supported external pilot uses REST or the TypeScript SDK.

Allowed tools are `create_payment_proposal`, `get_payment_status`,
`cancel_payment_proposal`, `get_policy_decision`, `simulate_payment`, and
`get_payment_audit`. The simulator can only attach a `DEMO_MOCK` observation to
a fully human-authorized proposal. After `IN_DOUBT`, `simulate_payment` returns
an `IN_DOUBT_FROZEN` tool error for every later outcome. A tool result never
represents bank confirmation.

The MCP client must not receive human dashboard credentials. Do not proxy
human-only REST routes through a generic browser or HTTP tool available to the
same agent.

## Errors

Clients should expect structured errors for invalid input, policy denial,
conflicting state, duplicate/replayed operations, expired proposals, missing
authorization, and unavailable records. Fail closed on an unrecognized state or
error; do not translate it into approval or success.
