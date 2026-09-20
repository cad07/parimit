# Adapter guide

The default repository includes only a mock outcome adapter. It is deliberately
incapable of reaching a network or moving value.

## Adapter contract

An adapter receives an immutable, approved simulation request and returns a
normalized mock result:

- `UNKNOWN`
- `PENDING`
- `SUCCEEDED`
- `FAILED`
- `REVERSED`
- `DISPUTED`
- `IN_DOUBT`

The application owns state transitions, idempotency, audit events, and the
fail-closed uncertainty rule. Once it records `IN_DOUBT`, it rejects every
later mock observation. The alpha deliberately has no reconciliation mechanism.
An adapter must not mutate a proposal or invent approval.

## Adding a mock scenario

1. Add the scenario implementation under the adapter or simulation boundary,
   never in the domain/policy core.
2. Make the scenario deterministic when given the same explicit test input.
3. Label every result as simulated in the API, UI, logs, and audit event.
4. Cover success, validation failure, timeout/uncertainty, and duplicate calls.
5. Run the complete gate with `npm run check`.

An acceptable mock adapter may introduce delay or return an `IN_DOUBT` result.
It cannot later replace that uncertainty with another outcome through the alpha
API. It must not use `fetch`, open a socket, read provider credentials, render
a real payment QR code, or invoke another executable that can reach a rail.

## Do not disguise a live connector as an adapter

A PSP or bank integration is not a small extension of the mock interface. It
changes the trust model and requires a separate deterministic executor outside
the AI agent process. Do not add provider URLs, secrets, SDKs, webhooks, or live
payment methods to the default build.

If the project later supports a separately reviewed executor, use a one-way
handoff of an exact, short-lived authorization artifact. The executor must
independently verify policy version, human identities, intent digest, expiry,
nonce, replay status, and scope before mapping to a provider-specific command.
It must never accept free-form agent instructions.

See [real integration requirements](real-integration-requirements.md) before
designing such a component.
