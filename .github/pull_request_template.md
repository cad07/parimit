## Summary

Describe the user-visible behavior and why the change is needed.

## Safety impact

- [ ] Agent/MCP authority is unchanged and remains proposal-only.
- [ ] Approval remains bound to the exact immutable intent.
- [ ] No live payment rail, provider credential, or network I/O was added.
- [ ] `IN_DOUBT` cannot be retried automatically.
- [ ] I updated the threat model or decision record if a trust boundary changed.

## Verification

- [ ] `npm test`
- [ ] `npm run check:boundary`
- [ ] Documentation and `openapi.yaml` match interface changes.
- [ ] Fixtures and logs contain no secrets, personal data, or real transactions.

## Provenance

- [ ] I have the right to contribute this work under MIT.
- [ ] I documented any third-party code or assets in `NOTICE`.
