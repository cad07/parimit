# ADR 0003: Local Keycloak OIDC pilot boundary

- Status: accepted for the local alpha pilot
- Date: 2026-09-20

## Context

Parimit can verify OIDC access tokens, but alpha.3 does not ship an identity
provider or an interactive login flow. Before testing with an organization's
identity provider, contributors need a reproducible way to exercise issuer,
audience, signature, role and subject separation with a real OIDC server.

A convenience stack can easily weaken the boundary it is meant to test. Static
passwords, exported realm secrets, password grants, machine reviewers, mutable
container tags or ports published beyond loopback would make a successful run
misleading. A local identity test must also remain distinct from an external
pilot and from any payment or NPCI integration.

## Decision

Ship an optional local Keycloak profile with these constraints:

- Keycloak and Parimit are reachable from the host only on explicitly bound
  loopback ports. The profile must not be exposed through a tunnel, LAN address,
  reverse proxy or hosted environment.
- Keycloak uses HTTPS. Its local certificate and CA, bootstrap credential,
  workload-client secrets, user passwords, Parimit receipt key, envelope key,
  database and bearer tokens are generated at runtime outside version control.
  The project CA is trusted only by this disposable profile; installing it as a
  system-wide or organization-wide trust root is not part of the design.
- The Keycloak image is pinned to a reviewed version and immutable digest.
  Runtime containers receive no privileged mode, host network namespace or
  Docker socket.
- Parimit starts with `PARIMIT_AUTH_MODE=oidc` and
  `PARIMIT_DEMO_MODE=false`. It validates the exact HTTPS issuer, JWKS endpoint,
  API audience and a top-level multivalued `roles` access-token claim.
- The realm defines exactly four dedicated Parimit role values. A subject that
  receives more than one mapped role remains invalid under Parimit's fail-closed
  mapping.
- Only the agent and relying-party consumer use service accounts. Reviewer and
  pilot-admin identities are separate human users. They authenticate through a
  public device-authorization client, must replace their generated temporary
  passwords and configure TOTP, and must not use direct/password or implicit
  grants.
- The bootstrap Keycloak administrator is identity-provider infrastructure and
  receives no Parimit role. The Parimit admin user is not the Keycloak bootstrap
  administrator.
- Automated CI may validate configuration and may exercise agent and consumer
  workload authentication. It must never approve or reject a proposal, acquire
  a reviewer/admin token, or describe a machine-only run as human acceptance.
- Successful pilot acceptance requires an interactive human reviewer to inspect
  the exact immutable amount, fictional payee alias, purpose, policy result and
  expiry before deciding. A two-person case requires two distinct human OIDC
  subjects. This gate is recorded separately from automated results.

The profile uses only synthetic proposals and fictional aliases. It contains no
payment connector, UPI credential, OTP, PIN, provider callback or execution
route. It is not supplied, endorsed or certified by NPCI, a bank or a PSP.

## Consequences

The profile can establish that Parimit composes with a real OIDC issuer, rejects
demo headers in OIDC mode and keeps workload, reviewer, consumer and operator
identities separate. It also gives contributors a deterministic configuration
to review for accidental secret inclusion and unsafe container exposure.

The local CA and loopback topology do not establish production transport or
identity security. The profile does not test enterprise provisioning,
phishing-resistant authentication, revocation, external ingress, high
availability, monitoring or recovery. Keycloak compromise, local administrator
access or trust in the generated CA can still compromise the local run.

Promotion beyond one workstation requires a new deployment design, an
organization-managed HTTPS and identity boundary, independent security review
and every gate in the external pilot guide. Connecting a payment rail remains a
separate regulated-integration decision governed by ADR 0001 and the real-
integration requirements.
