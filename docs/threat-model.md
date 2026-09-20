# Threat model

## Scope and assumptions

This threat model covers the alpha.2 application: proposal-safe REST and MCP
interfaces, OIDC verification at the REST edge, deterministic policy, human
decisions, local persistence, audit chaining, the local dashboard, and the
mock simulator.

The agent, prompts, tool arguments, browser input, imported context, and all
network clients are untrusted. A human approver may make mistakes or have a
compromised session. The host, process memory, and local administrator are not
assumed secure against a fully privileged attacker. Real payment providers and
payment execution are out of scope because the shipped application has no such
connection.

## Assets

- The integrity and immutability of proposal fields.
- Human identity and separation of duties.
- Policy configuration and decisions.
- Idempotency and state-machine correctness.
- Approval receipt and audit-chain integrity.
- Availability of the approval and reconciliation workflow.
- Any local personal or commercial data entered into a proposal.

## Primary threats and controls

| Threat | Example | Required control |
| --- | --- | --- |
| Prompt or tool injection | Content tells an agent to approve or send money | Agent interface has no approval or execution capability |
| Confused deputy | Agent calls a human-only route | MCP omits the route; REST verifies OIDC and enforces agent, approver, and admin roles |
| Intent substitution | Payee or amount changes after approval | Canonical intent digest; mutation invalidates approval |
| Replay | Same request is submitted repeatedly | Scoped idempotency key and stored response |
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
| Secret leakage | Signing key appears in logs or repository | Secret manager, redaction, scanning, rotation |
| Supply-chain compromise | Dependency install runs malicious code | Zero runtime dependencies initially; pinned CI actions |

## Abuse cases the intended deployment boundary must prevent

1. An agent-facing capability directly or indirectly approves a proposal.
2. An agent-facing tool dispatches, initiates, pays, or sends funds.
3. A receipt is passed unchanged to a provider as a valid payment command.
4. A proposal retains approval after a security-relevant mutation.
5. An uncertain result triggers an automatic retry.
6. A single identity satisfies a two-person rule.
7. A core policy rule depends on live network state during evaluation.

## Residual risks in the alpha

- OIDC verifies a token, not the real-world judgment or device security of its
  holder. The pilot depends on short-lived tokens, non-overlapping role groups,
  and identity-provider lifecycle controls.
- Local demo headers remain spoofable. Their mode is restricted to loopback or
  an explicit container exception whose host port must remain loopback-only;
  they must never be used for a shared deployment.
- The alpha has no token revocation lookup, native step-up authentication,
  tenant boundary, or browser login flow.
- A hash chain without external anchoring can be rewritten by an attacker who
  can rewrite the complete store and keys.
- Process-local or file-backed storage may lose state or mishandle concurrency.
- The browser dashboard is not a hardened privileged-access workstation.
- Stdio MCP has no verified OIDC actor binding in alpha.2 and is therefore
  disabled in OIDC mode; it remains a local demonstration boundary only.
- The mock simulator demonstrates state handling but says nothing about a real
  provider's correctness, availability, or settlement semantics.
- Static boundary scanning supplements review and tests; it is not a formal
  proof or complete data-flow analysis.

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
- Run the boundary scanner, secret scanner, CodeQL, and dependency review.
- Review logs and errors for proposal data and secret disclosure.
- Revisit this model whenever authority, identity, storage, or adapters change.
