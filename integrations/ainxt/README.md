# AiNxt reference adapter

This directory contains an optional, proposal-only compatibility adapter between
NPCI's public AiNxt OS docking contract and Parimit's OIDC REST API.

It is an independent reference integration. It is not an NPCI product,
endorsement, certification, AtOM integration, UPI connection, or payment
executor.

## Reviewed source and integration status

This adapter's wire-contract review is anchored to AiNxt OS commit
[`454fb09cf1fff2bedb5aa3f4f1c391e4915f33dd`](https://github.com/npci/ainxt-os/tree/454fb09cf1fff2bedb5aa3f4f1c391e4915f33dd).
The repository did not expose a matching release tag when reviewed. This is a
source-review anchor, not runtime binary attestation. The adapter separately
validates and reports AiNxt's SSE `control_plane_sha`. In the reviewed upstream
contract, that field is the control-repository commit to which the turn is
pinned. Upstream carries it as a string; Parimit applies a stricter local policy
requiring a canonical full 40-character lowercase Git object identifier. For
the study below, the reviewed AiNxt checkout was deliberately designated as the
control repository, so its source-review and control-repository commits are the
same value. Parimit does not repurpose this field for a deployment-manifest
digest or treat it as runtime binary attestation.

The adapter uses AiNxt's documented `POST /v1/chat` Server-Sent Events contract.
It does not install a native AiNxt tool. The current public AiNxt runtime requires
a custom build to register an additional `ConnectorCapability`, while its MCP
surface is still described upstream as design-only. Parimit also intentionally
disables stdio MCP in OIDC mode because stdio does not bind a verified agent
identity. The current artifact is a TypeScript library plus a synthetic CLI,
not a native AiNxt connector, MCP server, or public network service.

## Boundary

```text
short-lived agent token
          |
          v
trusted adapter preflight ----> Parimit /v1/safety + /v1/identity
          |
          | no bearer token forwarded
          v
AiNxt POST /v1/chat ----> untrusted JSON draft
          |
          v
strict local validation ----> Parimit simulation ----> policy allowed?
                                                       |
                                                       v
                                               proposal creation only
                                                       |
                                                       v
                                                AWAITING_APPROVAL
```

The library's public runtime surface has four methods, and declares these four
allowlisted operation names for any future dispatcher:

- `parimit_simulate_proposal`
- `parimit_create_proposal`
- `parimit_get_proposal`
- `parimit_cancel_proposal`

It does not expose proposal listing, approval, rejection, evidence issuance,
evidence verification or consumption, mock observations, payment execution,
UPI, bank, or PSP operations.

Before every operation, Parimit must report all of the following:

- `mode: PROPOSAL_ONLY`
- `moves_money: false`
- `connects_to_upi: false`
- `live_payment_credentials_accepted: false`
- an empty `execution_routes` array
- one OIDC-verified identity carrying exactly the Parimit `agent` role

AiNxt output is never trusted as authorization. Callers select only one of two
code-defined synthetic fixtures (`coffee_order` or `mobility_pass`); arbitrary
free text and live payment identifiers are not accepted by this alpha adapter.
It accepts exact JSON only, rejects extra fields, permits INR minor units only,
caps expiry at 900 seconds, and requires synthetic `demo-` identifiers and a
`Synthetic ` purpose. The returned values must also exactly match the selected
fixture; a different but otherwise valid-looking synthetic draft is refused.
It obtains `requested_by.id` from Parimit's verified identity endpoint and
never accepts that field from the model.

## Deployment shape

This alpha requires AiNxt on loopback with its trusted-gateway posture
explicitly enabled. The adapter derives bounded `X-AInxt-*` headers from the
OIDC-verified Parimit agent and grants only `chat.send`; the AiNxt process must
never be browser- or network-reachable. Remote and `jwt-sso` AiNxt deployments
are deferred until their least-privilege claim contract can be verified by the
adapter.

Run Parimit in OIDC mode and give the adapter a short-lived access token for a
dedicated `agent` workload identity. That token is sent only to Parimit. Human
reviewer/admin identities and the evidence consumer remain separate processes.
The adapter maps the verified, hashed actor identifier into a deterministic
AiNxt session identifier.

## Test

The normal repository check includes the adapter contract tests:

```sh
npm run check
```

The mocked adapter contract tests cover fail-closed safety metadata, the public
runtime surface, strict SSE and JSON validation, actor injection, simulation
before create, same-process draft reuse, response ownership, cancellation, and
absence of authority routes. A separate in-process integration test composes the
adapter with Parimit's real cryptographic OIDC verifier and HTTP authorization,
using a synthetic AiNxt SSE peer. These tests do not prove a live AiNxt model,
an external identity provider, Keycloak acceptance, or external/NPCI acceptance.

## Synthetic manual run

First run the reviewed AiNxt source at `http://127.0.0.1:8080` with a working
model/provider, `AINXT_TRUSTED_GATEWAY=1`, and an operator-selected
`AINXT_CONTROL_PLANE_SHA` equal to the designated control repository's exact
40-character commit.
Stock offline mode returns explanatory prose, which
the adapter intentionally rejects instead of treating as a draft. Also run an
OIDC-enabled Parimit instance. Load the dedicated agent token through a local
secret mechanism rather than source, prompts, logs, or retained shell history.

### Reviewed local Ollama profile

The repository includes an optional profile for Ollama's `qwen3.5:4b`. Pull the
tag, resolve and record its local model ID, then start the loopback-only
compatibility process in one terminal:

```sh
npm run pilot:ainxt:ollama-profile
```

It listens only on `127.0.0.1:11435`, accepts only
`POST /v1/chat/completions` for the exact `qwen3.5:4b` model, rebuilds the
upstream HTTP headers without forwarding incoming headers such as
`Authorization` or `Cookie`, caps request bodies, and forwards only to Ollama
on `127.0.0.1:11434`. It injects fixed `reasoning_effort: none` and
`temperature: 0` controls because the reviewed AiNxt runtime does not forward
those OpenAI-compatible fields and the model's default thinking mode exceeded
AiNxt's provider timeout in local testing.

The process allowlists the model tag, not its content digest. Before a reviewed
run, the operator must separately resolve and record the local Ollama model
digest. A matching mutable tag alone is not model-byte attestation.

This process is a Parimit-local compatibility component. It is not supplied by
NPCI, AiNxt, or Ollama, and it adds no payment capability. Treat its source
digest and the bundled
[`ollama-qwen3.5-4b.toml`](ollama-qwen3.5-4b.toml) digest as reviewed deployment
inputs. The profile permits only AiNxt's `internal` data class.

From a reviewed AiNxt checkout, layer the repository profile after AiNxt's base
configuration and keep both listeners on loopback:

```sh
export AINXT_TRUSTED_GATEWAY=1
export AINXT_CONTROL_PLANE_SHA='454fb09cf1fff2bedb5aa3f4f1c391e4915f33dd'

./target/release/ainxt-runtimed \
  --config config.toml \
  --config '<path-to-parimit>/integrations/ainxt/ollama-qwen3.5-4b.toml' \
  --check

./target/release/ainxt-runtimed \
  --config config.toml \
  --config '<path-to-parimit>/integrations/ainxt/ollama-qwen3.5-4b.toml'
```

Separately retain a non-secret deployment manifest binding at least the reviewed
AiNxt source commit, AiNxt runtime-binary digest, exact Ollama model digest,
profile digest, and compatibility-process digest. Do not place that manifest's
SHA-256 in `AINXT_CONTROL_PLANE_SHA`: upstream defines the SSE field as the
control-repository commit. The manifest and individual component hashes remain
separate run evidence.

For the repository's local Keycloak profile, do not manually export a token.
Use the canonical combined runner, which obtains and verifies the short-lived
workload token and passes it directly to the adapter in the same process:

```sh
npm run pilot:ainxt:keycloak -- \
  --expected-ainxt-control-plane-sha '<exact-reviewed-control-repo-commit>'
```

It applies Parimit's exact 40-character lowercase control-repository commit
policy, requires the study value to match the reviewed checkout above, and gives
the local model up to 120 seconds, proves the port 8080 listener is
loopback-only, completes the
denied mobility simulation and allowed coffee preflight before any create, then
creates and replays only the allowed coffee proposal. It never begins a human
login or approval flow. See the
[Keycloak pilot instructions](../../deploy/keycloak/README.md#run-the-live-ainxt-proposal-smoke).

The environment-driven CLI below remains available for a separately managed
OIDC deployment whose operator already has a reviewed local secret-injection
mechanism. It is not the recommended Keycloak pilot path.

```sh
export AINXT_URL=http://127.0.0.1:8080
export PARIMIT_URL=http://127.0.0.1:8787
export PARIMIT_AINXT_SCENARIO=coffee_order
export PARIMIT_AINXT_IDEMPOTENCY_KEY='ainxt-demo-2026-09-22-001'
# Have the reviewed process supervisor inject PARIMIT_AGENT_ACCESS_TOKEN only
# into this child process; do not export it into a long-lived shell.
npm run demo:ainxt
```

The CLI submits the same validated draft twice in one process. The expected
result is one synthetic proposal and one Parimit idempotent replay of that same
proposal. The draft cache is deliberately bounded and process-local; after a
restart, only the exact fixed fixture can pass validation, so a valid retry has
the same Parimit fingerprint. Model drift fails before Parimit rather than
changing the proposal. A durable ledger is still required before expanding
beyond closed fixtures. The adapter cannot approve the proposal. Stop if the
result does not remain proposal-only.

If simulation denies the fixture, the adapter makes no create request. Parimit
re-evaluates policy atomically during creation; if policy changes in that small
window, it may retain a non-actionable `POLICY_DENIED` audit record, which the
adapter reports as a denial.

## Future native connector

A later custom AiNxt build may register these same four operations through
`ainxt_connector_http::ConnectorCapability`. Do that only after the current
sidecar passes an external review and the upstream dynamic connector/MCP
lifecycle is stable. Keep Parimit's REST/OIDC boundary runtime-neutral; never
move human approval or evidence-consumer authority into the AiNxt agent.
