# Local Keycloak OIDC pilot

This profile runs the reviewed Parimit alpha with a real OIDC verifier and a
local Keycloak identity provider. It is a controlled technical acceptance
environment for synthetic data. It is not a payment integration, an external
pilot, or a production identity system.

Parimit still cannot execute, dispatch, debit, transfer, or connect to UPI, a
bank, a PSP, or a wallet. Do not enter real account identifiers, UPI handles,
payment credentials, OTPs, PINs, customer data, or production secrets.

## What this profile proves

The stack can demonstrate all of the following on one local machine:

- access tokens are signed by Keycloak and verified against its HTTPS JWKS;
- the token issuer, audience, subject, lifetime, and top-level role claim are
  checked by Parimit;
- agent and evidence-consumer identities use separate workload credentials;
- reviewer and pilot-admin identities require interactive device login and
  are not service accounts;
- every subject maps to exactly one Parimit role;
- proposal, human review, evidence-envelope, one-time-consumption, mock
  observation, restart, and integrity behavior can be exercised without any
  payment rail; and
- both host-published ports remain restricted to loopback.

It does not turn the browser dashboard into an OIDC application. Use the REST
API, the role-shaped TypeScript SDK, or the supplied pilot runner. Parimit does
not implement login, token refresh, user provisioning, or Keycloak
administration.

## Deliberate local-only limits

Keycloak uses its `dev-file` database on a persistent Docker volume. Current
Keycloak guidance says that database is for development only and does not
provide a supported production migration path. There is one Keycloak instance,
one Parimit instance, no external reverse proxy, no high availability, no
external monitoring, and no production backup system.

The local CA is private to this generated environment. Host-side commands use
it explicitly; do not disable TLS verification. The Keycloak container root
filesystem is not marked read-only because its standard image performs runtime
augmentation. Parimit remains read-only except for its dedicated data volume
and temporary filesystem.

The dedicated Compose bridge is required for Docker to publish the two host
loopback ports. It is not an outbound-egress firewall: the containers can make
outbound connections unless the host or container runtime applies a separate
policy. Neither service requires routine Internet access. Use Docker Engine
28.3.3 or newer; earlier releases include known loopback-publication failures.
Do not enable the daemon's `DOCKER_INSECURE_NO_IPTABLES_RAW=1` escape hatch,
which intentionally bypasses Docker's loopback hardening.

Use the separate production-oriented pilot guide before any participant or
network exposure. This profile must never be exposed through a tunnel, public
interface, shared ingress, or port-forward.

## Fixed trust topology

The Keycloak image is pinned to both version 26.7.4 and the reviewed
multi-architecture manifest digest. Upgrade the tag and digest together and
repeat the complete acceptance run.

The host-facing issuer is:

```text
https://localhost:8443/realms/parimit-pilot
```

Tokens acquired from the host contain that exact `iss`. Inside the dedicated
Compose bridge, Parimit fetches the same realm's keys from:

```text
https://keycloak:8443/realms/parimit-pilot/protocol/openid-connect/certs
```

One locally generated server certificate covers `localhost`, `keycloak`, and
`127.0.0.1`. It is supplied to Keycloak in an encrypted PKCS#12 keystore;
Keycloak enables dynamic backchannel URLs, while its fixed public hostname
preserves the exact token issuer. Parimit receives only the public local CA
certificate, never the Keycloak keystore or its password.

Both the public issuer and internal JWKS URL are intentionally part of
Parimit's identity-trust-domain digest. Do not change either value against an
existing Parimit database. Start a fresh Parimit data volume for any identity,
audience, role, token-policy, or endpoint change.

## Identity layout

The realm is `parimit-pilot`, and the only accepted API audience is
`parimit-pilot`. A dedicated client scope emits:

- the exact audience in `aud`; and
- a top-level, multi-valued `roles` claim.

Keycloak's default nested `realm_access.roles` claim is not used by Parimit.
The configured external-to-internal mapping is:

| Keycloak `parimit-pilot` client role | Parimit role | Identity kind |
| --- | --- | --- |
| `parimit-pilot-agent` | `agent` | `parimit-agent-workload` service account |
| `parimit-pilot-reviewer` | `approver` | `pilot-reviewer` human account |
| `parimit-pilot-consumer` | `consumer` | `parimit-consumer-workload` service account |
| `parimit-pilot-admin` | `admin` | `pilot-admin` human account |

The public `parimit-human-cli` client permits only OAuth Device Authorization.
Direct password grants, implicit flow, standard browser flow, and service
accounts are disabled for it. The reviewer and pilot-admin accounts are
distinct, have one role each, and must replace their generated temporary
password and configure TOTP during first login.

Never assign the reviewer or admin role to a service account. Parimit verifies
signed claims but cannot determine whether a token represents a person or a
workload. Giving a workload either role would invalidate the human-review
claim. Likewise, assigning two mapped roles to one subject makes Parimit reject
the token as ambiguous.

The Keycloak bootstrap administrator is separate from `pilot-admin`. It manages
the identity server and should not be used with the Parimit API.

## Generated local material

The checked-in files contain placeholders only. The bootstrap helper creates:

```text
deploy/keycloak/.env.local
deploy/keycloak/runtime/tls/local-ca.pem
deploy/keycloak/runtime/tls/keycloak.p12
deploy/keycloak/runtime/envelope-private-key.pem
deploy/keycloak/runtime/human-logins.txt
deploy/keycloak/runtime/reports/
```

The environment file and `runtime/` directory are ignored by the local
`.gitignore`. The generator must use restrictive permissions and JSON-safe
base64url values for secrets substituted into the realm JSON. Before every
commit, confirm that neither path is staged:

```sh
git status --short -- deploy/keycloak
git check-ignore \
  deploy/keycloak/.env.local \
  deploy/keycloak/runtime/tls/keycloak.p12 \
  deploy/keycloak/runtime/envelope-private-key.pem \
  deploy/keycloak/runtime/human-logins.txt
```

The protected environment contains the Keycloak bootstrap and keystore
passwords, two workload client secrets, two one-time human passwords, Parimit's
receipt key, and the base64-encoded Ed25519 private key. The public CA and
encrypted PKCS#12 file may be mode `0644`; the keystore password and every
other secret remain only in the mode `0600` environment file. The bootstrap
helper must delete any transient unencrypted TLS private key after creating the
keystore. Docker Compose passes some values as container environment variables
because both current applications require it. On a shared host, users able to
inspect Docker can read them. That is another reason this profile is local-only.

Realm import occurs only when `parimit-pilot` does not already exist. Editing
`.env.local` later does not rotate imported client secrets or passwords. Never
delete volumes merely to force re-import if evidence must be retained.

## Prerequisites

- Docker Engine 28.3.3 or newer, or Docker Desktop carrying an equivalent or
  newer engine, with Compose v2;
- OpenSSL, `curl`, and `jq` on the host;
- enough memory for a 1 GiB Keycloak limit plus Parimit; and
- a clean checkout pinned to the reviewed release or pilot commit.

No supported container engine is currently installed automatically by this
profile. Installing or starting one is an explicit operator action.

## Prepare and validate

Run the repository's bootstrap helper from the repository root. It must refuse
to overwrite an existing environment unless the operator explicitly chooses a
new, disposable pilot:

```sh
node --experimental-strip-types scripts/bootstrap-keycloak-pilot.ts
```

Inspect file modes without printing file contents. Do not run `docker compose
config` without `--quiet`: expanded output contains secrets.

```sh
docker compose \
  --project-name parimit-keycloak-pilot \
  --env-file deploy/keycloak/.env.local \
  -f deploy/keycloak/docker-compose.yml \
  config --quiet

npm run check
```

The TLS certificate must include `DNS:localhost`, `DNS:keycloak`, and
`IP:127.0.0.1`. The environment must contain no blank required value. Do not
work around a validation error by weakening TLS, enabling demo headers, or
adding a direct password grant.

## Build and start

```sh
docker compose \
  --project-name parimit-keycloak-pilot \
  --env-file deploy/keycloak/.env.local \
  -f deploy/keycloak/docker-compose.yml \
  pull keycloak

docker compose \
  --project-name parimit-keycloak-pilot \
  --env-file deploy/keycloak/.env.local \
  -f deploy/keycloak/docker-compose.yml \
  build --pull parimit

docker compose \
  --project-name parimit-keycloak-pilot \
  --env-file deploy/keycloak/.env.local \
  -f deploy/keycloak/docker-compose.yml \
  up -d --no-build
```

Keycloak blocks startup until realm import finishes, but Parimit can start
before Keycloak is ready because it retrieves JWKS on the first authenticated
request. The pilot runner must wait for Keycloak discovery and JWKS over TLS
before acquiring tokens.

Check only non-secret state:

```sh
docker compose \
  --project-name parimit-keycloak-pilot \
  --env-file deploy/keycloak/.env.local \
  -f deploy/keycloak/docker-compose.yml \
  ps

curl --fail --silent --show-error \
  --cacert deploy/keycloak/runtime/tls/local-ca.pem \
  https://localhost:8443/realms/parimit-pilot/.well-known/openid-configuration \
  | jq '{issuer, jwks_uri, token_endpoint, device_authorization_endpoint}'

curl --fail --silent --show-error http://127.0.0.1:8787/v1/safety | jq
```

The discovery document and safety endpoint are process signals, not proof of a
successful OIDC or end-to-end authorization flow.

### AiNxt adapter compatibility

The generated pilot policy allowlists the adapter's fixed
`demo-coffee-merchant` fixture. Its INR 499.00 amount is below the pilot's INR
1,000.00 per-proposal ceiling, so it can reach `AWAITING_APPROVAL` after the
adapter's own simulation and validation gates. The `demo-mobility-pass`
fixture remains deliberately outside this profile: INR 1,250.00 exceeds that
ceiling and must be denied. Both identifiers are fictional; never replace them
with a live payee in this local profile.

Choose the policy before the Parimit data volume is first initialized. Policy
configuration is bound into the database recovery root; changing the allowlist
after initialization requires a new disposable pilot recovery set rather than
silently reusing the old volume.

## Run the controlled acceptance

Run the repository's Keycloak pilot helper. It obtains agent and consumer
tokens with their own client credentials, starts interactive device flows for
the reviewer and pilot-admin users, and keeps bearer and refresh tokens only in
memory. It must never print or persist a token.

```sh
node --experimental-strip-types scripts/run-keycloak-pilot.ts
```

For each human device flow, open the exact verification URL displayed by the
runner. Use `pilot-reviewer` for review and `pilot-admin` for the mock
observation step. Complete the forced password change and TOTP enrollment. Do
not reuse the Keycloak bootstrap administrator. Before either approval, the
runner reloads and displays the proposal's immutable fields and policy result.
The named human must enter the exact role-specific confirmation containing the
displayed intent hash; end-of-input or any other text aborts without approval.
The runner refuses a dirty Git worktree, inspects the complete effective Docker
port-binding set, and records a SHA-256 digest of the resolved Compose
configuration so a passing report is tied to the configuration actually run.

The acceptance run must verify at least:

1. Keycloak tokens use RS256, contain a `kid`, have the exact issuer and
   audience, have a bounded `iat`/`exp`, map to one expected role, and carry
   the exact workload `azp` or human `azp` plus `preferred_username`.
2. `/v1/safety` is proposal-only, while missing tokens and spoofed demo headers
   fail on protected routes.
3. The agent discovers its derived actor ID, simulates and creates a synthetic
   proposal, and receives idempotent replay behavior.
4. The human reviewer inspects and gives the first approval; the proposal
   remains `AWAITING_APPROVAL`, and the same reviewer cannot satisfy dual
   control twice.
5. The distinct human pilot-admin inspects the same immutable proposal and
   gives the second approval; only then is the result
   `AUTHORIZED_NO_DISPATCH`, with every execution flag false.
6. The pilot-admin issues and verifies an audience-bound evidence envelope.
7. The consumer can consume it once, gets an idempotent same-operation replay,
   cannot browse proposals, and receives a conflict for a different replay.
8. The human pilot-admin records only a `DEMO_MOCK` observation without
   changing authorization into payment evidence.
9. Audit and envelope integrity pass, including after a restart with the same
   database and keys.
10. Likely execution paths remain absent.

Store only a redacted report at
`deploy/keycloak/runtime/reports/keycloak-pilot-report.json`. It may contain the
release commit, image identifiers, non-secret trust configuration, timestamps,
scenario results, clean-worktree marker, resolved-Compose digest, and derived
trust-domain identifier. It must not contain passwords, client secrets, bearer
or refresh tokens, private keys, TOTP seeds, or the receipt key.

An interactive run is intentionally not a CI gate: the usable profile contains
no machine reviewer or machine admin. CI may validate the checked-in realm and
Compose configuration, but it must not claim that a human approval occurred.
For a noninteractive connectivity check limited to the agent and consumer
workloads, use `--workload-smoke`. It must not approve, issue an envelope, or be
reported as human acceptance. Every run rebuilds and starts the canonical
checked-in Compose profile before verification; there is no reuse-only mode.

## Stop, preserve, and reset

Stop the services without deleting identity or evidence:

```sh
docker compose \
  --project-name parimit-keycloak-pilot \
  --env-file deploy/keycloak/.env.local \
  -f deploy/keycloak/docker-compose.yml \
  stop
```

The Keycloak volume, Parimit volume, `.env.local`, receipt key, envelope key,
and local CA form one local recovery set. Preserve or destroy them according to
the same decision. Container removal does not revoke tokens or credentials.

Deleting either named volume is destructive. Do it only for an explicitly
disposable run after confirming no evidence needs retention. A fresh realm or
Parimit trust configuration requires fresh volumes; never attach an old
Parimit database to a changed issuer, JWKS URL, audience, role map, receipt key,
or signing policy.

## Troubleshooting without weakening controls

- **Parimit returns provider unavailable:** wait for Keycloak, verify the
  internal `keycloak` DNS name, certificate SAN, mounted CA, and HTTPS JWKS URL.
- **Token is invalid:** inspect claims locally without logging the token;
  verify exact issuer, `parimit-pilot` audience, RS256, `kid`, `iat`, `exp`, and
  the top-level `roles` array.
- **Role is unauthorized or ambiguous:** ensure the subject has exactly one of
  the four dedicated `parimit-pilot` client roles. Do not broaden the mapping.
- **Changed secret has no effect:** the realm already exists and startup import
  was skipped. Rotate through Keycloak administration or create a deliberately
  fresh disposable environment; do not silently delete retained evidence.
- **Browser warns about TLS:** trust the generated local CA through the
  operating system's reviewed process. Do not click through warnings or use
  insecure token endpoints.
- **Dashboard has no login:** expected. The browser dashboard is not part of
  this OIDC pilot.

Never resolve a failure by using HTTP, `start-dev`, password grants, demo
headers, an unpinned image, a service-account reviewer, shared human accounts,
long-lived tokens, or disabled certificate verification.
