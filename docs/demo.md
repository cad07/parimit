# Safe demo

This walkthrough exercises the safety model without contacting a bank, PSP, or
payment network.

## Start

```sh
npm start
```

Open <http://localhost:8787>. Use only fictional payees and non-sensitive demo
data.

## Scenario 1: ordinary proposal

1. Select the `agent` identity and create a proposal for INR 499.00 (store it as `49900` minor units) to a
   fictional payee reference.
2. Reuse the same idempotency key and confirm that no second proposal appears.
3. Review the amount, currency, payee, purpose, policy result, and expiry.
4. Switch to a distinct `approver` identity and approve the exact intent.
5. Switch to `admin`, select the mock-success outcome, and inspect the audit events.

The success label means only that the simulator returned success.

## Scenario 2: dual control

1. Create a ₹600.00 proposal (`60000` minor units), above the demo's ₹500.00
   dual-approval threshold and below its ₹1,000.00 per-transaction ceiling.
2. Approve once as the first demo identity.
3. Confirm that the proposal remains awaiting approval.
4. Attempt another approval with the same identity and confirm rejection.
5. Approve as a distinct second identity and inspect the receipt.

## Scenario 3: uncertainty

1. Create and approve a new fictional proposal.
2. Select the mock `IN_DOUBT` outcome.
3. Attempt to record any second mock outcome, including `SUCCEEDED` or another
   `IN_DOUBT`.
4. Confirm that it fails with `IN_DOUBT_FROZEN` and the latest observation
   remains `IN_DOUBT`.
5. Verify that the audit history contains only the accepted uncertainty event.
   The alpha provides no reconciliation mechanism.

## Scenario 4: fail closed

Try malformed currency, zero or fractional minor units, a configured blocked
payee (or one absent from a configured allowlist), an expired intent, approval
after cancellation, and mutation after approval. Each must reject or require a
new proposal; none may silently continue.

## MCP smoke test

Run `npm run mcp` from an MCP-compatible client and inspect its tool list. It
must contain only proposal creation, status, cancellation, policy, audit, and
mock-simulation capabilities. Run `npm run check:boundary` to statically reject
authority-bearing tool names.

## End the demo

Stop the process. The alpha has no in-app reset. For the default local setup,
move `./data/parimit.db` aside if you want a fresh database on the next start.
Docker Compose stores data in its named `parimit-data` volume. Never copy demo
state into a production system.
