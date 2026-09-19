# Security policy

Parimit is an alpha safety demonstration. It does not process live
payments and must not be deployed as a payment processor or authorization
service.

## Supported versions

Only the latest commit on the default branch receives security fixes until the
project publishes a stable release.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, or social post.

Use GitHub's **Security → Report a vulnerability** flow to open a private
security advisory with the maintainers. Include:

- the affected commit and configuration;
- prerequisites and a minimal reproduction;
- the safety invariant that is bypassed;
- realistic impact, including whether any external system is involved; and
- a proposed fix, if available.

If private reporting is unavailable, open a public issue containing no exploit
details and ask a maintainer to enable a private channel.

Maintainers should acknowledge complete reports within seven days, provide a
triage decision within fourteen days, and coordinate disclosure after a fix is
available. These are targets, not service-level guarantees.

## Highest-priority findings

- Any agent or MCP path that can approve or execute an operation.
- Approval reuse after amount, currency, payee, purpose, or expiry changes.
- A bypass of idempotency, dual control, policy, or audit verification.
- Any accepted mock observation after an `IN_DOUBT` result.
- Network access introduced into the domain or policy core.
- Authentication or authorization bypass on human-only routes.
- Secret leakage, unsafe defaults, or executable supply-chain compromise.

## Scope clarification

The mock rail never moves money. Do not connect it to a real provider while
testing a report. Any downstream bank, PSP, identity provider, reverse proxy,
or deployment platform is outside this repository's security boundary.
