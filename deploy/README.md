# Single-tenant pilot deployment

This directory provides a conservative deployment path for the proposal-only
alpha.3 pilot. It runs one Parimit container with SQLite and exposes its HTTP
port only on host loopback. An operator-managed reverse proxy must provide the
public HTTPS endpoint.

It is not a production topology. It has no PostgreSQL runtime, multi-tenancy,
high availability, payment connector, background reconciliation, or bundled
monitoring system.

For a self-contained local rehearsal with a pinned Keycloak identity provider,
generated TLS, separate workload and human identities, and an interactive
acceptance runner, use the dedicated
[`keycloak` profile](keycloak/README.md). That profile remains local-only and
does not replace this operator-managed external-pilot topology.

## Prerequisites

- a dedicated host with Docker Engine and Docker Compose v2;
- an encrypted persistent disk and a tested snapshot/restore mechanism;
- a DNS name and a host-level HTTPS reverse proxy (or reviewed private-ingress
  agent terminating on that host);
- a dedicated OIDC API audience, JWKS URL, and non-overlapping agent,
  approver, consumer, and admin roles;
- a secret manager or protected operator-only environment file; and
- outbound HTTPS access to the configured JWKS host.

Pin the checkout to the reviewed release commit. Run the repository test and
boundary suites before building the image. Do not deploy arbitrary default
branch state.

## Configure

From the repository root:

```sh
cp deploy/pilot.env.template deploy/.env.pilot
chmod 600 deploy/.env.pilot
```

Replace every placeholder. Use a unique receipt key, a stable Ed25519 envelope
key, an exact issuer and one consumer audience, a dedicated OIDC audience, and only
fictional payee aliases. `deploy/.env.pilot` is ignored by the
repository's `.env*` rule; confirm it is not staged before every commit.

The application currently accepts both private key materials only through
environment injection. This is less desirable than a managed signer or
file-mounted secret API, so restrict Docker and host access. Never print the
resolved Compose configuration in shared logs because it contains expanded
secrets.

Validate the Compose structure without writing the resolved output to a file:

```sh
docker compose \
  --project-name parimit-pilot \
  --env-file deploy/.env.pilot \
  -f deploy/docker-compose.pilot.yml \
  config --quiet
```

The file intentionally contains no PostgreSQL service. `DATABASE_URL` and
similar values do not enable PostgreSQL; the alpha runtime remains SQLite.

## Build and start

Use a distinct `PARIMIT_IMAGE_TAG` for every reviewed commit, then run:

```sh
docker compose \
  --project-name parimit-pilot \
  --env-file deploy/.env.pilot \
  -f deploy/docker-compose.pilot.yml \
  build --pull parimit

docker compose \
  --project-name parimit-pilot \
  --env-file deploy/.env.pilot \
  -f deploy/docker-compose.pilot.yml \
  up -d --no-build parimit
```

Do not scale the service above one instance. Its SQLite volume and process
model are intended for a single application instance only.

Check container state and the loopback-only process signal:

```sh
docker compose \
  --project-name parimit-pilot \
  --env-file deploy/.env.pilot \
  -f deploy/docker-compose.pilot.yml \
  ps

curl --fail --silent --show-error http://127.0.0.1:8787/v1/safety
```

The safety endpoint does not prove OIDC, SQLite, or end-to-end authorization
health. Complete the validation below before opening ingress.

## Put HTTPS in front

Configure the reverse proxy to send the public pilot hostname to
`http://127.0.0.1:8787`. The Parimit port must remain bound to loopback and
must not be opened in the host firewall or cloud security group.

This reference assumes the proxy is a host process. A proxy in another
container cannot reach the host's loopback through its own `127.0.0.1`. A
containerized-proxy variant must instead place only those two services on a
dedicated internal Docker network and remove Parimit's published port; review
that topology before use.

At minimum, the proxy must:

- serve only HTTPS externally and use the organization's approved TLS policy;
- forward `Authorization` without logging it;
- remove inbound `x-parimit-actor` and `x-parimit-role` headers;
- disable response caching and preserve `Cache-Control: no-store`;
- enforce a request-body limit no larger than Parimit's 1 MiB limit;
- apply conservative connection and per-client rate limits;
- set bounded upstream and client timeouts; and
- emit security logs with tokens and sensitive headers redacted.

Set HSTS only after the hostname and certificate lifecycle are proven. If a
corporate access proxy is used, its identity does not replace Parimit's OIDC
token validation.

## Validate before participant access

Use four distinct, short-lived access tokens—agent, approver, consumer, and
admin. Store them in your shell or
test runner only; do not paste them into documentation or command history.

1. `GET /v1/safety` works without a token and reports `PROPOSAL_ONLY`,
   `moves_money: false`, `connects_to_upi: false`, and no execution routes.
2. Every other `/v1` route rejects a missing token.
3. Demo headers without a bearer token are rejected.
4. `GET /v1/identity` returns the expected single role for each token.
5. An agent can simulate and create only when `requested_by.id` equals its
   returned `actor_id`, and can read only its own proposals.
6. An approver can read and decide but cannot create or attach observations.
7. A reviewer/admin can issue an evidence envelope only after full approval;
   an agent cannot issue one and the signed capability remains evidence-only.
8. A consumer can verify and atomically consume an envelope once, cannot browse
   proposals, and a different replay receives a conflict.
9. Two-person approval requires distinct reviewer identities.
10. A mock observation is labelled `DEMO_MOCK`, never changes the proposal from
   `AUTHORIZED_NO_DISPATCH`, and never claims money moved.
11. Envelope and audit verification remain valid after a restart with the same
    receipt key and verification-key registry.
12. `/v1/pay`, `/v1/execute`, `/v1/intents/{id}/execute`, and similar paths are
    absent.

Run the full sequence in [`../docs/pilot-guide.md`](../docs/pilot-guide.md)
and preserve a redacted result record with the release commit and image tag.

## Backup and restore

Use the host platform's encrypted volume-snapshot mechanism. A valid pilot
backup is a crash-consistent set of the SQLite data, the exact receipt-key
version, and the envelope private/public key material used by that deployment.

The alpha.3 receipt key, tenant, envelope issuer, single audience,
authentication mode, exact identity trust domain, policy-configuration digest,
and envelope lifetime policy are database-bound and cannot be rotated or
retargeted in place. A mismatch, or a missing root beside material v3 history,
makes startup fail closed. OIDC mode also refuses approval history from before
this binding existed. If
the receipt key is lost or compromised, retire that pilot database and create
a fresh deployment; do not delete the old matching recovery set while evidence
retention still applies. Envelope-signing keys may be rotated separately
because historical public keys remain in the protected registry.

For a simple stopped-instance snapshot:

1. Close public ingress.
2. Stop the Parimit service and wait for it to exit cleanly.
3. Snapshot the `parimit-pilot_parimit-pilot-data` Docker volume with the
   platform's approved tooling.
4. Record the release commit, image tag, policy configuration, OIDC issuer and
   audience, envelope key ID, snapshot identifier, and secret versions. Do not
   record secret values.
5. Restart the same image and reopen ingress only after validation.

Test restoration into an isolated host before the pilot. Verify representative
audit trails after restore. Do not treat a copied live `.db` file as a tested
backup, and never restore pilot data into a real payment system.

## Upgrade and rollback

Before an upgrade, close ingress, stop the service, take a snapshot, and retain
the current image. Build the reviewed new commit under a new
`PARIMIT_IMAGE_TAG`; never replace an existing tag.

To roll back:

1. close ingress and stop the current container;
2. restore the pre-upgrade volume snapshot;
3. restore the matching receipt/envelope key versions and policy configuration;
4. set `PARIMIT_IMAGE_TAG` to the retained prior image;
5. start with `up -d --no-build parimit`; and
6. rerun the authentication, authorization, safety, and integrity checks before
   reopening ingress.

Do not run an older binary against a newer or partially migrated database
unless that exact pair was tested. The current SQLite alpha has no general
downgrade or online-migration guarantee.

## Stop and remove

To stop without deleting evidence:

```sh
docker compose \
  --project-name parimit-pilot \
  --env-file deploy/.env.pilot \
  -f deploy/docker-compose.pilot.yml \
  stop parimit
```

Do not add `--volumes` to a removal command unless the retention owner has
approved permanent deletion and a verified snapshot exists. Container removal
does not revoke OIDC credentials; revoke them separately at the identity
provider when the pilot ends.
