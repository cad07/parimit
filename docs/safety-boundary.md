# Safety boundary

This document is normative. When documentation, convenience, or a feature
conflicts with this boundary, the boundary wins.

## One-sentence rule

An AI agent-facing capability may propose and observe but must not decide;
decisions belong to a separate human trust domain, and the open-source default
build can never execute a payment. The alpha's spoofable demo headers illustrate
this workflow but do not authenticate a human.

## Permitted agent operations

- Create a new payment proposal.
- Read a proposal and its policy/status metadata when authorized.
- List authorized proposals with bounded pagination.
- Cancel an eligible proposal created in the same authority scope.
- Request a clearly labelled mock outcome in demo mode.

## Forbidden agent and MCP operations

- Approve, reject on behalf of a human, or satisfy dual control.
- Execute, initiate, dispatch, pay, transfer, or send money.
- Create or alter human identity, policy, limits, allowlists, or signing keys.
- Mutate an approved proposal or reuse its approval for another intent.
- Resolve `IN_DOUBT` without an explicit reconciliation authority.
- Obtain human-dashboard credentials or call its privileged routes.

MCP tool names containing authority-bearing verbs such as `approve`,
`authorize`, `debit`, `dispatch`, `execute`, `initiate`, `pay`, `retry`, `send`,
or `transfer` are prohibited. The repository's static boundary check fails on
such exposure.

## Immutable approval binding

The v2 alpha digest binds:

- proposal identifier and version;
- amount in integer minor units and currency;
- opaque payee reference;
- purpose or order reference;
- requester and optional on-behalf-of label;
- initial policy result, reasons, rules version, and required approval count; and
- creation and expiry timestamps.

Canonicalization must be deterministic. Any bound-field change invalidates all
prior approvals and requires a new policy evaluation. Tenant, mutable state,
nonce, one-time consumption state, and the later approval set are not members
of the v2 digest; the alpha cross-checks lifecycle state and decision records
separately against HMACs and the local event history.

## Human decision requirements

- Approval routes are separate from agent tools. A real deployment must require
  strongly authenticated, authorized human identity; the alpha does not.
- The UI shows the exact amount, currency, payee, purpose, and relevant risk
  signals before confirmation.
- High-risk policy may require two distinct authorized identities.
- The requester does not count as an approver where separation is required.
- Reject and cancel are terminal for the proposal version.
- Authentication assertions, CSRF protection, and session strength must be
  upgraded before any shared deployment.

## Non-dispatchable receipt

The receipt is evidence for demonstration and audit. It must not contain a
provider credential, rail endpoint, executable callback, or method that sends
it to a provider. Its type and schema must remain distinct from any future
provider instruction.

## Uncertain outcomes

`IN_DOUBT` means the outcome is unknown. The system must freeze automatic
progress and must not retry. Only explicit reconciliation with an authoritative
source can transition out of this state. The mock simulator demonstrates this
rule without contacting an external source: every later mock observation is
rejected with `IN_DOUBT_FROZEN`. No reconciliation mechanism exists in the
alpha.

## Network-free core

Domain, policy, approval, audit, and state-machine code must be deterministic
and cannot import HTTP, socket, DNS, TLS, fetch, WebSocket, or provider SDK
modules. I/O belongs at an adapter boundary. `scripts/check-boundary.ts`
enforces common violations, and human review covers semantic bypasses.

## Fail-closed conditions

Reject or halt when:

- an amount, currency, payee, purpose, identity, or expiry is invalid;
- policy is missing, malformed, or unavailable;
- lifecycle, event-history, or idempotency expectations do not match;
- required approvals are missing, duplicated, expired, or invalid;
- the intent digest or audit chain does not verify;
- an outcome is uncertain; or
- a capability is not explicitly allowed.

## Changing the boundary

Any expansion of agent authority or any real-provider connection requires a
new architecture decision record, threat-model update, two security reviews,
new adversarial tests, and a major-version discussion. A live executor must be
separate from the agent runtime and is not authorized by this repository's
current design.
