# Safety boundary

This document is normative. When documentation, convenience, or a feature
conflicts with this boundary, the boundary wins.

## One-sentence rule

An AI agent-facing capability may propose and observe but must not decide;
decisions belong to a separate human trust domain, and the open-source default
build can never execute a payment. Alpha.3 verifies OIDC identity for a
single-tenant REST pilot; spoofable headers remain only for an explicit local
demo and do not authenticate a human.

## Permitted agent operations

- Create a new payment proposal.
- Read a proposal and its policy/status metadata when authorized.
- List authorized proposals with bounded pagination.
- Cancel an eligible proposal created in the same authority scope.
- Request a clearly labelled mock outcome through the local MCP simulator.

## Forbidden agent and MCP operations

- Approve, reject on behalf of a human, or satisfy dual control.
- Execute, initiate, dispatch, pay, transfer, or send money.
- Create or alter human identity, policy, limits, allowlists, or signing keys.
- Mutate an approved proposal or reuse its approval for another intent.
- Resolve `IN_DOUBT` without an explicit reconciliation authority.
- Obtain human-dashboard credentials or call its privileged routes.
- Issue, consume, revoke, or reinterpret an evidence envelope as a payment command.

MCP tool names containing authority-bearing verbs such as `approve`,
`authorize`, `debit`, `dispatch`, `execute`, `initiate`, `pay`, `retry`, `send`,
or `transfer` are prohibited. The repository's static boundary check fails on
such exposure.

## Immutable approval binding

The v3 digest binds:

- proposal identifier and version;
- amount in integer minor units and currency;
- opaque payee reference;
- purpose or order reference;
- requester and optional on-behalf-of label;
- initial policy result, reasons, rules version, policy-configuration digest,
  and required approval count;
- creation and expiry timestamps; and
- the deployment-trusted tenant identifier.

Canonicalization must be deterministic. Any bound-field change invalidates all
prior approvals and requires a new policy evaluation. Mutable state, nonce,
one-time consumption state, and the later approval set are not members of the
intent digest; the alpha binds those into a separate signed envelope and
cross-checks them against the HMAC records and local event history. Historical
v1/v2 rows keep their original digest rules and cannot mint v1 envelopes.

## Human decision requirements

- Approval routes are separate from agent tools. A shared pilot must use OIDC,
  map each subject to exactly one role, and require the identity provider's
  strong authentication controls for reviewers.
- The UI shows the exact amount, currency, payee, purpose, and relevant risk
  signals before confirmation.
- High-risk policy may require two distinct authorized identities.
- The requester does not count as an approver where separation is required.
- Reject and cancel are terminal for the proposal version.
- The alpha does not implement browser login, token acquisition, step-up
  authentication, revocation lookup, or multi-tenant authorization. Those
  remain outside the supported single-tenant API/SDK pilot.
- Stdio MCP is disabled in OIDC mode because the alpha cannot bind a verified
  OIDC actor to that transport. The external pilot uses REST or the SDK.

## Non-dispatchable receipt

The receipt is evidence for demonstration and audit. It must not contain a
provider credential, rail endpoint, executable callback, or method that sends
it to a provider. Its type and schema must remain distinct from any future
provider instruction.

## Signed evidence envelope

Only a verified `approver` or `admin` may issue an envelope, and only after a
v3 proposal reaches `AUTHORIZED_NO_DISPATCH`. Agents and MCP receive no issuance
or consumption capability. The compact Ed25519 JWS binds exact issuer,
audience, tenant, identity trust domain, intent/policy digests,
policy-configuration digest, exact millisecond issuance time,
authorization-state version, approver set, short expiry, nonce and source audit
tip.

Every envelope signs `payment_dispatch_authorized: false`,
`execution_authorized: false`, `provider_instruction: false`, and
`moves_money: false`. A verified `consumer` or `admin` may record one-time
acceptance, but that transition is audit evidence only. Verification without a
durable consumption claim is not replay prevention. SQLite consumption is
authoritative only inside one service instance; offline or distributed
recipients require their own durable replay ledger.

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
- an envelope signature, issuer, audience, tenant, identity trust domain,
  policy-configuration digest, state, exact issuance time, expiry, nonce,
  issuance record, replay claim, or signed capability does not verify;
- audit chronology, the receipt root, or the complete signing-key registry
  checkpoint does not verify;
- an outcome is uncertain; or
- a capability is not explicitly allowed.

## Changing the boundary

Any expansion of agent authority or any real-provider connection requires a
new architecture decision record, threat-model update, two security reviews,
new adversarial tests, and a major-version discussion. A live executor must be
separate from the agent runtime and is not authorized by this repository's
current design.
