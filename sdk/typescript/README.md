# `@parimit/sdk` pilot preview

This dependency-free TypeScript client keeps Parimit's trust zones separate:

- `createAgentClient` can propose, simulate policy, inspect, audit, and cancel.
- `createReviewerClient` can inspect, approve or reject, issue signed evidence,
  and request read-only envelope verification.
- `createEnvelopeConsumerClient` can fetch public keys, verify an envelope, and
  atomically record one evidence acceptance without browsing proposals.
- `createOperatorClient` can issue, verify, or consume evidence and attach
  clearly labelled mock observations.

No client exposes a payment execution, dispatch, transfer, debit, or UPI method.

This is an in-repository, private source preview, not a published npm package.
The import name below shows the intended package surface. Until a build and
release pipeline exists, pin the Parimit commit and use a workspace link or the
relative import demonstrated by `examples/pilot-client.ts`.

The SDK does not acquire or refresh OIDC tokens. A pilot client must obtain a
short-lived access token for Parimit's configured audience and pass it at
runtime. Call `identity()` first: agent proposals must use the returned
`actor_id` as `requested_by.id`, preventing requester substitution.

```ts
import { createAgentClient } from "@parimit/sdk";

const parimit = createAgentClient({
  baseUrl: "https://parimit-sandbox.example.com",
  identity: { accessToken: process.env.PARIMIT_ACCESS_TOKEN! },
});

const actor = await parimit.identity();

if (actor.actor_role !== "agent") {
  throw new Error(`Expected agent identity, received ${actor.actor_role}`);
}

const proposal = await parimit.createProposal({
  idempotency_key: crypto.randomUUID(),
  requested_by: { type: "agent", id: actor.actor_id },
  amount: { currency: "INR", minor: "49900" },
  payee_reference: "merchant_demo_001",
  purpose: "Fictional pilot purchase",
});

console.log(proposal.status); // AWAITING_APPROVAL
```

Use `demoIdentity` only with an explicitly local demo server. Shared pilots
must use an OIDC access token over HTTPS. Reviewer and operator clients should
use separate human identities; never give either token to an agent process.

Their surfaces remain role-shaped:

- `createAgentClient`: simulate, create, and cancel an eligible own proposal;
- `createReviewerClient`: approve or reject an exact proposal and issue signed,
  non-dispatchable evidence after full approval;
- `createEnvelopeConsumerClient`: verify and consume evidence once, with no
  proposal-list or proposal-read method; and
- `createOperatorClient`: issue/verify/consume evidence and attach a fictional
  mock observation.

`getEnvelopeKeys()` reads the standard, unwrapped JWKS document from
`/.well-known/jwks.json`. `verifyEvidenceEnvelope()` is read-only and is not
replay protection. `consumeEvidenceEnvelope()` records evidence acceptance
inside the configured Parimit persistence boundary; it does not dispatch or
execute a payment. Offline recipients still need their own durable replay
ledger.

These method shapes are guardrails for integration code. The server's OIDC,
role, ownership, lifecycle, and policy checks are the security boundary.
