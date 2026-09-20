# External pilot guide

This guide defines the narrow external-pilot envelope for Parimit's alpha.2
track. It is an evaluation of proposal governance, not a payment pilot.

> **Boundary:** Parimit does not connect to UPI, a bank, a PSP, a wallet, or
> any other payment rail. It has no execute, debit, transfer, dispatch, or retry
> capability. An `AUTHORIZED_NO_DISPATCH` result and every observation are
> non-financial evidence only.

## Pilot profile

The supported pilot shape is deliberately small:

- one participating organization;
- one tenant and one policy configuration;
- one Parimit application instance;
- one persistent SQLite database on an encrypted host volume;
- OIDC bearer-token authentication for API and SDK clients;
- an HTTPS reverse proxy, rate limits, logs, and backups operated by the pilot
  host; and
- fictional payee aliases, synthetic purposes, and test amounts only.

Do not put customer payment data, bank details, UPI identifiers, provider
credentials, OTPs, PINs, production secrets, or a real provider callback into
the pilot. The browser dashboard remains a local demonstration surface unless
it is separately equipped with an audited OIDC login and token flow. The
external pilot should use the REST API or the in-repository TypeScript SDK
preview. The SDK package is private and is not published to a package registry;
pin or vendor the reviewed source commit for pilot use.

PostgreSQL is not part of this deployment. The repository includes a schema
and transaction contract to guide a future adapter, but it does not include a
driver, repository implementation, runtime switch, or live parity suite. See
[`../db/postgres/README.md`](../db/postgres/README.md).

## What the pilot should learn

The pilot should answer four questions:

1. Can an agent express a useful, deterministic proposal without receiving
   approval or payment authority?
2. Can a reviewer understand and decide the exact immutable proposal?
3. Do policy denials, idempotency, dual control, cancellation, expiry, and
   uncertainty behave predictably under the participant's workflow?
4. Is the evidence useful to security, risk, and operations teams?

The pilot must not be used to measure payment success, latency, settlement,
reconciliation, or provider compatibility. No such integration exists.

## Roles and separation

Each OIDC subject must map to exactly one Parimit role. Use separate accounts
for each test role.

| Role | Pilot responsibility | Allowed authority |
| --- | --- | --- |
| `agent` | Propose and inspect its own work | Simulate policy, create a proposal using its authenticated `actor_id`, read its own proposals and evidence, cancel an eligible proposal |
| `approver` | Human review | Read proposals, approve or reject an exact proposal; cannot create for an agent or attach an observation |
| `admin` | Pilot operation | Read, approve or reject, cancel when permitted, and attach a clearly labelled mock observation |

An agent cannot approve, even if it submits an altered role in request data.
Two-approval policy requires two distinct authenticated reviewer identities.
Do not give an automated agent an `approver` or `admin` token.

The API exposes `GET /v1/identity` so a client can discover its derived,
non-PII `actor_id`. An agent must use that exact value as
`requested_by.id`; the server rejects identity substitution. Identity setup,
claim requirements, and route authorization are documented in
[`identity.md`](identity.md).

## Entry gates

Do not invite participants until every gate below is evidenced for the exact
commit and container image being deployed.

| Gate | Required evidence |
| --- | --- |
| Safety boundary | Repository tests and boundary scan pass; `/v1/safety` reports `PROPOSAL_ONLY`, `moves_money: false`, and no execution routes |
| Authentication | OIDC-mode integration tests pass; missing or invalid bearer tokens fail; spoofed demo headers alone fail |
| Authorization | Agent, approver, and admin positive and negative route tests pass, including ownership and distinct-reviewer checks |
| Transport | Only the HTTPS proxy is externally reachable; the Parimit upstream is bound to host loopback |
| Storage | A fresh encrypted SQLite volume is used; restore of a stopped-instance snapshot has been rehearsed |
| Secrets | A unique receipt key and OIDC configuration are stored outside Git; access and rotation owners are named |
| Operations | Logs, basic rate limits, uptime checks, incident contacts, maintenance window, and stop procedure are assigned |
| Data | Written agreement limits input to fictional aliases and synthetic test data |

Use [`../deploy/README.md`](../deploy/README.md) for the reference deployment
and validation sequence.

## End-to-end acceptance run

Run this sequence through the same HTTPS hostname participants will use:

1. Fetch `/v1/safety` without a token and confirm the proposal-only flags.
2. Call a protected route without a token and with demo identity headers only;
   both attempts must fail.
3. Authenticate as an agent, call `/v1/identity`, and simulate a proposal.
   Confirm simulation persists nothing and reports `moves_money: false`.
4. Create the proposal with a new idempotency key and the returned `actor_id`.
   Replay the identical request and confirm the same proposal is returned.
5. Authenticate as an approver, inspect the exact amount, payee alias, purpose,
   policy result, and expiry, then approve it.
6. Confirm the result is `AUTHORIZED_NO_DISPATCH` and the receipt says
   `execution_authorized: false`.
7. Authenticate as an admin and add one fictional mock observation. Confirm it
   does not alter the authorization status or claim funds moved.
8. Fetch the audit trail and integrity report; require every integrity flag to
   be true.
9. Repeat with a denial, rejection, cancellation, expired proposal, duplicate
   approver, two-person approval, and `IN_DOUBT`. Confirm `IN_DOUBT` rejects
   every later observation.
10. Probe likely execution paths such as `/v1/pay`, `/v1/execute`, and
    `/v1/intents/{id}/execute`; every one must be absent.

Record the release tag, commit, image identifier, policy values, OIDC issuer
and audience, timestamps, and expected results. Never record bearer tokens or
the receipt key.

## Suggested success criteria

Agree on numbers with the participant before the pilot. A useful minimum is:

- at least 20 synthetic proposals covering every acceptance scenario above;
- 100% of accepted proposals require a human decision before
  `AUTHORIZED_NO_DISPATCH`;
- zero agent approvals, cross-agent reads, identity substitutions, or exposed
  execution routes;
- zero duplicate proposals for identical agent/idempotency-key pairs;
- all sampled integrity reports valid before and after restart/restore;
- reviewers can identify amount, payee alias, purpose, policy result, and
  expiry before deciding;
- the participant can explain the distinction between authorization evidence,
  a mock observation, and actual payment execution; and
- the stop-and-restore drill completes within the pilot's agreed recovery
  objective.

A pilot is unsuccessful if it requires live money movement, shared reviewer
credentials, multiple tenants, multiple application replicas, payment data,
or unreviewed changes to the safety boundary. Those are design inputs for a
later phase, not exceptions to this one.

## Monitoring and daily operation

- Monitor the HTTPS endpoint and container state. `/v1/safety` is a process
  health signal, not proof that storage, identity, or end-to-end authorization
  is healthy.
- Alert on authentication failures, authorization denials, rate-limit events,
  repeated policy denials, integrity failures, and unexpected restarts. The
  alpha does not provide a complete monitoring stack; the proxy and host must
  supply it.
- Review disk space and take a stopped-instance snapshot on the agreed
  schedule. Test a restore before participant access begins.
- Keep the application single-instance. Do not use autoscaling or rolling
  multi-replica deployment with the SQLite database.
- Treat `IN_DOUBT` as a frozen test result. The alpha has no reconciliation
  workflow.

## Stop, rollback, and incident response

Stop external access immediately if authentication can be bypassed, an agent
can act outside its role or ownership scope, integrity verification fails, the
receipt key may be exposed, the database is damaged, or any real payment data
or credential enters the system.

1. Disable the public proxy route or its access policy.
2. Stop the Parimit container without deleting its volume.
3. Preserve host, proxy, identity-provider, release, and database evidence.
   Do not copy bearer tokens or secrets into an issue.
4. Revoke the affected OIDC client, session, or subject and rotate exposed
   credentials.
5. Restore the last known-good application image together with its matching
   stopped-instance SQLite snapshot and receipt key.
6. Re-run the acceptance checks before reopening access.

The database and receipt key are a verification pair. Rotating the key in
place makes existing approval receipts fail integrity checks. Preserve each
snapshot with the secret version needed to verify it, using the organization's
secret manager and retention rules. Never weaken verification to make an old
snapshot readable.

## Exit decision

At the end, choose one of three explicit outcomes:

- **stop:** the workflow is not useful or the controls are not credible;
- **iterate:** retain the proposal-only boundary and address documented gaps;
  or
- **design a regulated integration:** begin the separate legal, partner,
  security, executor, reconciliation, and certification work described in
  [`real-integration-requirements.md`](real-integration-requirements.md).

Completing this pilot does not authorize a real payment connection and does
not imply NPCI, bank, PSP, or regulatory endorsement.
