# Threat model

## Scope and assumptions

This threat model covers the alpha.3 application: proposal-safe REST and MCP
interfaces, OIDC verification at the REST edge, deterministic policy, human
decisions, signed evidence envelopes, one-time local consumption, local
persistence, audit chaining, the local dashboard, the mock simulator, and the
optional loopback-only Keycloak OIDC pilot profile.

The agent, prompts, tool arguments, browser input, imported context, and all
network clients are untrusted. A human approver may make mistakes or have a
compromised session. The host, process memory, and local administrator are not
assumed secure against a fully privileged attacker. Real payment providers and
payment execution are out of scope because the shipped application has no such
connection. The local Keycloak profile neither uses nor implies an NPCI, bank
or PSP interface, approval, certification or endorsement.

## Assets

- The integrity and immutability of proposal fields.
- Human identity and separation of duties.
- Policy configuration and decisions.
- Idempotency and state-machine correctness.
- Approval receipt and audit-chain integrity.
- Envelope signing keys, audience/tenant binding, expiry and replay state.
- Local-pilot OIDC issuer integrity, TLS CA and human/workload role separation.
- Availability of the approval and reconciliation workflow.
- Any local personal or commercial data entered into a proposal.

## Primary threats and controls

| Threat | Example | Required control |
| --- | --- | --- |
| Prompt or tool injection | Content tells an agent to approve or send money | Agent interface has no approval or execution capability |
| Confused deputy | Agent calls a human/consumer-only route | MCP omits the route; REST verifies OIDC and enforces agent, approver, consumer, and admin roles |
| Intent substitution | Payee or amount changes after approval | Canonical intent digest; mutation invalidates approval |
| Replay | Same request is submitted repeatedly | Scoped idempotency key and stored response |
| Envelope replay | A signed artifact is accepted more than once or by the wrong relying party | Exact audience, short expiry, random nonce, atomic consumption and a recipient replay-ledger requirement |
| Envelope substitution | Valid evidence is used for another tenant, intent or state | Signature covers tenant, exact v3 intent digest, policy, approvers and state version; online verification cross-checks storage and audit |
| Algorithm/key confusion | Artifact supplies its own key or weaker algorithm | Fixed Ed25519 profile, exact protected header, trusted `kid` registry, no `jwk`/`jku`/`x5u`/`x5c` |
| Split-payment evasion | Large amount is divided below a threshold | Velocity and aggregate limits over a defined window |
| Self-approval | Requester counts as approver | Actor separation and distinct-approver constraint |
| Fake dual control | Same identity approves twice | Stable identity, uniqueness check, strong authentication |
| Race / TOCTOU | Cancellation and approval happen concurrently | SQLite write transactions acquire an immediate lock, re-read state inside the transaction, and use conditional transitions; the pilot remains single-instance |
| Audit rewriting | Local event history is edited | Hash chain, verification, and future external anchoring |
| Outcome ambiguity | Timeout is treated as failure then retried | `IN_DOUBT` freezes later observations; authoritative reconciliation is future work |
| SSRF / exfiltration | Policy core calls a URL from proposal text | No network imports or fetch in core; CI scanner |
| Resource exhaustion | Huge body or proposal flood | Body limits, rate limits, quotas, bounded fields |
| Cross-site request forgery | Browser is tricked into approval | Hosted pilot is API/SDK only; any future browser OIDC flow requires audited CSRF/state/nonce controls |
| Cross-site scripting | Purpose text contains markup | Contextual output escaping and restrictive CSP |
| Secret leakage | Receipt or signing key appears in logs or repository | Secret manager and redaction; stop and replace the pilot database if the alpha.3 receipt key is compromised; rotate envelope signing keys independently |
| Local IdP impersonation | A fake loopback service supplies tokens or signing keys | HTTPS issuer and JWKS, profile-scoped generated CA, exact issuer/audience validation, and no plaintext fallback |
| Role-claim confusion | Default realm roles or several Parimit roles reach one token | Dedicated top-level access-token claim, exact four-value mapping, and fail-closed ambiguous-role rejection |
| Machine approval | A CI or workload credential is used as the reviewer | Service accounts only for agent and consumer; reviewer/admin use interactive device authorization; CI never authenticates as either human role or records a decision |
| Local container exposure | Keycloak, Parimit or their administration surface becomes reachable from another host | Fixed host-loopback port bindings; no tunnel, wildcard publish, host network, privileged mode or Docker socket |
| Bootstrap or realm-secret disclosure | Realm export or repository history contains a password, private key or client secret | Minimal declarative realm, runtime-only generation in ignored files, static configuration tests and secret scanning |
| Supply-chain compromise | Dependency install or mutable container tag runs malicious code | Zero runtime dependencies initially; pinned CI actions; Keycloak image pinned by version and digest |

## Abuse cases the intended deployment boundary must prevent

1. An agent-facing capability directly or indirectly approves a proposal.
2. An agent-facing tool dispatches, initiates, pays, or sends funds.
3. A receipt is passed unchanged to a provider as a valid payment command.
4. A proposal retains approval after a security-relevant mutation.
5. An uncertain result triggers an automatic retry.
6. A single identity satisfies a two-person rule.
7. A core policy rule depends on live network state during evaluation.
8. A signed evidence envelope is interpreted as authority to dispatch a payment.
9. Signature verification is presented as replay protection without an atomic
   durable nonce claim.

## Residual risks in the alpha

- OIDC verifies a token, not the real-world judgment or device security of its
  holder. The pilot depends on short-lived tokens, non-overlapping role groups,
  and identity-provider lifecycle controls.
- The optional Keycloak profile proves local OIDC composition only. Its
  generated CA, loopback HTTPS service, local TOTP users and single-host
  container runtime do not represent an organization's production identity or
  transport controls.
- An automated agent/consumer workload smoke test cannot prove human review.
  Acceptance still requires a reviewer to authenticate interactively and inspect
  the exact immutable proposal; dual control requires a second human subject.
- A privileged local administrator can read process memory, runtime secret files,
  the Keycloak store and the Parimit database. The local profile does not defend
  against a fully compromised workstation.
- Local demo headers remain spoofable. Their mode is restricted to loopback or
  an explicit container exception whose host port must remain loopback-only;
  they must never be used for a shared deployment.
- The alpha has no token revocation lookup, native step-up authentication,
  multi-tenant request routing, or browser login flow. Its v3 tenant is a
  single deployment boundary.
- A hash chain without external anchoring can be rewritten by an attacker who
  can rewrite the complete store and keys.
- Process-local or file-backed storage may lose state or mishandle concurrency.
- The browser dashboard is not a hardened privileged-access workstation.
- Stdio MCP has no verified OIDC actor binding in alpha.3 and is therefore
  disabled in OIDC mode; it remains a local demonstration boundary only.
- The mock simulator demonstrates state handling but says nothing about a real
  provider's correctness, availability, or settlement semantics.
- Static boundary scanning supplements review and tests; it is not a formal
  proof or complete data-flow analysis.
- Compact JWS is signed but not encrypted; a holder can read purpose and opaque
  payee metadata.
- SQLite enforces consumption atomically only for one service/database. Two
  offline recipients can both verify the same signature unless they coordinate
  through a durable replay ledger.
- Public keys are retained for verification, but managed/HSM signing, formal
  revocation distribution and external transparency anchoring are not shipped.
  A receipt-key HMAC checkpoint detects a missing key in the current registry,
  but restoring an older internally consistent database/checkpoint snapshot is
  not detectable without that external anchor.
- A database-bound integrity root rejects a mismatched receipt key, tenant,
  envelope issuer, relying-party audience, authentication mode, exact identity
  trust domain, policy-configuration digest, or envelope lifetime policy before
  envelope signing-key registration. A v3 database with material history and a
  missing root fails closed. OIDC mode refuses pre-root approval history whose
  original authentication strength cannot be proven. Alpha.3 does not support
  in-place receipt-key rotation or trust-domain retargeting; the database,
  receipt key, trust configuration and envelope-key history are one recovery
  set. Startup, JWKS publication and key lookup verify every key attestation and
  the complete-registry checkpoint.

Do not reduce these risks by quietly connecting the demo to a live API. Follow
the [real-integration requirements](real-integration-requirements.md) and use a
separate security review.

## Security verification checklist

- Property-test all legal and illegal state transitions.
- Fuzz JSON parsing and canonicalization.
- Test approval invalidation for every bound field.
- Test idempotency under concurrent requests.
- Verify audit chains at startup and before producing a receipt.
- Test authorization independently for every human and agent route.
- Test every envelope claim for signature tamper, wrong issuer/audience/tenant,
  exact-boundary expiry, replay, restart persistence and key rotation.
- Run the boundary scanner, secret scanner, CodeQL, and dependency review.
- Run the Keycloak profile's static configuration contract: immutable image
  digest, loopback-only ports, TLS/CA wiring, OIDC/non-demo mode, restricted
  container privileges, exact claim/audience mapping, disabled direct grants,
  role separation and absence of tracked runtime secrets.
- Keep automated workload smoke results separate from the signed-off interactive
  human acceptance record. Verify two distinct reviewers for the dual-control
  scenario.
- Review logs and errors for proposal data and secret disclosure.
- Revisit this model whenever authority, identity, storage, or adapters change.
