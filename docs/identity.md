# Identity and authorization

Parimit's external-pilot mode accepts signed OIDC JWT access tokens. It does
not implement an OIDC login page, authorization-code flow, token exchange,
refresh-token store, user directory, or identity-provider administration.
Clients obtain an access token from the pilot's identity provider and present
it as `Authorization: Bearer <token>`.

Local demo headers are a separate trust mode. They are intentionally
spoofable and require `PARIMIT_AUTH_MODE=demo_headers` plus
`PARIMIT_DEMO_MODE=true`. The server must bind to loopback, except for the
explicit `PARIMIT_DEMO_ALLOW_NON_LOOPBACK_HEADERS=true` container escape hatch
used by the local Compose file whose *published host port* remains bound to
loopback. That escape hatch does not make the headers trustworthy. Never
expose demo-header mode through a proxy, tunnel, shared network, or hosted
environment.

## Pilot configuration

Use these environment variables for the external pilot:

| Variable | Required | Meaning |
| --- | --- | --- |
| `PARIMIT_AUTH_MODE=oidc` | yes | Select verified bearer-token identity |
| `PARIMIT_DEMO_MODE=false` | yes | Disable the local demonstration mode |
| `PARIMIT_OIDC_ISSUER` | yes | Exact `iss` value and HTTPS issuer URL |
| `PARIMIT_OIDC_AUDIENCE` | yes | Audience that must appear in `aud` |
| `PARIMIT_OIDC_JWKS_URI` | yes | HTTPS URL for the issuer's signing keys |
| `PARIMIT_OIDC_ROLE_CLAIM` | no | Exact top-level role claim; default `roles` |
| `PARIMIT_OIDC_ROLE_MAPPING` | yes | Non-empty JSON object mapping dedicated provider values to `agent`, `approver`, or `admin` |
| `PARIMIT_OIDC_CLOCK_SKEW_SECONDS` | no | Clock tolerance from 0 to 300 seconds; default 60 |
| `PARIMIT_OIDC_MAX_TOKEN_LIFETIME_SECONDS` | no | Maximum `exp - iat`; default 3,600 seconds and makes `iat` mandatory |
| `PARIMIT_OIDC_REQUIRED_TYP` | no | Optional exact JOSE `typ`, `at+jwt` or `JWT`, when guaranteed by the provider |

The environment-created provider accepts RS256 by default. The underlying
library also supports explicitly allowlisted PS256 and ES256 for custom
embedding, but the alpha.2 server has no environment setting to change the
algorithm allowlist. Do not infer an algorithm from the token header.

Example mapping:

```text
PARIMIT_OIDC_ROLE_CLAIM=roles
PARIMIT_OIDC_ROLE_MAPPING={"parimit-pilot-agent":"agent","parimit-pilot-reviewer":"approver","parimit-pilot-admin":"admin"}
```

Quote or escape the JSON as required by the deployment system. The reference
Compose file reads it as one string.

## Required token claims

The verifier requires:

- a valid signature from exactly one compatible key in the configured JWKS;
- an explicitly allowed algorithm and a non-empty `kid`;
- exact `iss` equality;
- an `aud` string or string array containing the configured audience;
- a non-empty `sub` no longer than 1,024 characters;
- a numeric, unexpired `exp`;
- valid numeric `nbf` when present, an `iat` that is not in the future, and a
  configured maximum issued lifetime (server default: one hour); and
- a role claim that maps to exactly one Parimit role.

Unmapped roles fail closed. A subject whose claims map to more than one
Parimit role also fails closed; do not assign overlapping pilot groups. Token
errors are deliberately generic so the API does not become a key or claim
oracle.

The JWKS URL must use HTTPS. Responses are fetched without redirects, limited
in size, cached, and refreshed after an unknown key identifier subject to a
refresh interval. Ensure the Parimit container can reach only the identity
provider and other explicitly required infrastructure where egress controls
are available. Rehearse signing-key rotation before the pilot.

## Actor identifiers

Parimit does not store the raw OIDC subject in proposal actor fields. It
derives a stable identifier:

```text
oidc:<sha256(issuer + NUL + subject)>
```

This reduces direct identifier disclosure but is pseudonymization, not
anonymization. Anyone with likely issuer/subject pairs can recompute it. Treat
actor IDs and audit data according to the participant's retention and access
policy.

`GET /v1/identity` returns the authenticated `actor_id`, `actor_role`,
authentication method, and issuer. Agent integrations must first fetch that
resource and use the returned `actor_id` as `requested_by.id`. The server
rejects a proposal or simulation that names a different requester.

## Route policy

`GET /v1/safety` and preflight `OPTIONS` are the only unauthenticated API
operations. Every other `/v1` route requires a valid bearer token in OIDC
mode.

| Operation | `agent` | `approver` | `admin` |
| --- | ---: | ---: | ---: |
| Read own identity | yes | yes | yes |
| Simulate/create as self | yes | no | no |
| List/read own proposals and evidence | yes | yes, all | yes, all |
| Cancel | own eligible proposal | no | eligible proposal |
| Approve/reject | no | yes | yes |
| Record a demo mock observation | no | no | yes |

Approver and admin decisions remain subject to the domain rules: the original
requester cannot approve its own proposal, duplicate reviewers do not satisfy
dual control, and terminal or expired proposals cannot be approved.

Authorization is enforced by the server. SDK role-shaped clients reduce
accidental misuse but are not a security boundary.

## Identity-provider setup

Create a dedicated resource/API audience for Parimit that is not reused as an
OIDC client ID or ID-token audience. This exact audience is the mandatory
access-token discriminator. If the provider reliably emits `typ=at+jwt` (or
`typ=JWT` only for access tokens), configure `PARIMIT_OIDC_REQUIRED_TYP` as an
additional check. Use short-lived access tokens intended for that audience;
do not send ID tokens. Create three
non-overlapping provider roles or groups and map each to one Parimit role.

For human reviewer and admin accounts:

- require multi-factor authentication, preferring phishing-resistant methods;
- prohibit shared accounts and service-account credentials;
- keep admin membership smaller than reviewer membership;
- define joiner, mover, leaver, and emergency-revocation procedures; and
- review group membership before the pilot and at its end.

For agent clients, use a dedicated workload identity with only the agent role.
Do not place its credential in prompts, source code, container images, logs, or
the browser. The SDK accepts an access token at runtime but does not acquire or
refresh one.

## Proxy and logging requirements

- Terminate HTTPS before the loopback-only Parimit upstream and redirect or
  reject plaintext external traffic.
- Forward the `Authorization` header unchanged. Never log its value.
- Remove inbound `x-parimit-actor` and `x-parimit-role` headers at the proxy.
  They are irrelevant in OIDC mode and must never become trusted metadata.
- Do not cache API responses. Respect Parimit's `Cache-Control: no-store`.
- Apply conservative body-size, connection, and per-client rate limits. The
  application does not yet provide a distributed rate limiter.
- Keep identity-provider and host clocks synchronized.

## Failure and recovery behavior

- Missing credentials return an authentication error.
- Invalid, expired, wrongly issued, wrongly addressed, or wrongly signed
  tokens return a generic authentication error.
- An unavailable or invalid JWKS endpoint returns a temporary provider error;
  do not bypass verification or fall back to demo headers.
- Unmapped or ambiguous roles return an authorization error.
- A role or ownership mismatch returns an authorization error before the
  domain mutation runs.

If the identity provider is unavailable, pause the pilot. Do not extend token
lifetimes, disable signature checks, reuse another application's audience, or
temporarily enable demo headers.

## Known limits

The alpha has no tenant claim or tenant-aware row boundary, no token
revocation lookup, no end-user session manager, no native step-up challenge,
no browser login, and no provisioning protocol. It relies on token expiry,
identity-provider controls, and a single-tenant deployment. Those limitations
must be resolved before a multi-tenant or production service.
