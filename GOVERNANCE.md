# Governance

Parimit uses a maintainer-led, consensus-seeking governance model.

## Roles

- **Contributors** propose issues, documentation, code, tests, and reviews.
- **Maintainers** review and merge changes, manage releases and security
  reports, and protect the project's safety boundary.

Maintainers are identified through GitHub repository permissions. New
maintainers are nominated by an existing maintainer after sustained,
constructive contributions and are added by consensus of active maintainers.

## Decisions

Routine changes need one approving maintainer and passing required checks.
Security-sensitive changes should receive two independent reviews. Changes to
agent authority, approval semantics, persistence integrity, provider adapters,
cryptography, or the safety boundary require an architecture decision record
and consensus among active maintainers.

If consensus cannot be reached, maintainers pause the change. Safety wins over
feature velocity. A maintainer with a material conflict of interest should
disclose it and recuse themselves from the final decision.

## Releases

Maintainers publish releases from protected commits after tests, the boundary
scanner, security analysis, and documentation checks pass. Until 1.0, APIs may
change between minor releases. Release notes must identify security-boundary
changes explicitly.

## Project scope

The default open-source project remains a proposal, policy, approval, audit,
and simulation system. It is not a payment rail. Any future real-provider
adapter must live behind a separately reviewed, deterministic executor boundary
and may be maintained in a separate repository.

## Amendments

Governance changes use the same architecture-decision process and require
maintainer consensus with at least seven days for public review.
