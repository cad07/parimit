# Contributing

Thank you for helping make agent-initiated payment proposals safer.

## Before opening a change

1. Read the [safety boundary](docs/safety-boundary.md) and
   [threat model](docs/threat-model.md).
2. Search existing issues and pull requests.
3. For a new public interface or a boundary change, open an issue first.
4. Never include real credentials, payment identifiers, personal data, or
   production transaction records in code, fixtures, screenshots, or logs.

## Local development

Use Node.js 24. The project intentionally has no third-party runtime
dependencies.

```sh
npm start
npm run check
```

Every pull request must keep the complete test and boundary gate green. Add tests
for success, rejection, mutation after approval, duplicate submission,
distinct approvers, expiry, and uncertain outcomes when relevant.

## Non-negotiable invariants

- Agent-facing and MCP interfaces are proposal-only.
- Tools named or behaving like `pay`, `send`, `initiate`, `execute`, `approve`,
  `authorize`, `dispatch`, `transfer`, `debit`, or `retry` are prohibited.
- Human decisions are bound to the exact immutable intent.
- Approval receipts are not provider instructions.
- The domain and policy core stays deterministic and network-free.
- `IN_DOUBT` freezes the mock observation stream; every later outcome is
  rejected because the alpha has no reconciliation authority.
- The default build never connects to a real payment rail.

Changes that weaken an invariant require a public architecture decision record,
maintainer consensus, and a major-version review. Maintainers may reject a
change even when its tests pass if the change expands payment authority.

## Pull requests

- Keep each pull request focused.
- Explain the threat-model impact and user-visible behavior.
- Update documentation and `openapi.yaml` with interface changes.
- Add an entry under **Unreleased** in `CHANGELOG.md` for material changes.
- Use clear commits; signing commits is encouraged.
- Confirm that contributed code is yours to license under MIT and record any
  third-party origin in `NOTICE`.

## Developer certificate of origin

By contributing, you certify that you have the right to submit the work under
the project's license. You may state this explicitly with a `Signed-off-by`
line following the [Developer Certificate of Origin](https://developercertificate.org/).

## Conduct and security

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Security reports belong in the private process described in
[SECURITY.md](SECURITY.md), not in ordinary issues.
