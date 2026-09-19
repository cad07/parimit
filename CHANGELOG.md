# Changelog

All notable changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/) after its first stable
release.

## [Unreleased]

## [0.1.0-alpha.0] - 2026-09-19

### Added

- Adopted the Parimit name: bounded authority for agent payments.
- Proposal-only REST and MCP interfaces.
- Deterministic payment-intent validation and policy evaluation.
- Human approval flow with exact-intent binding and dual-control support.
- Hash-chained audit events and non-dispatchable authorization receipts.
- Versioned v2 intent digests that bind the initial state and stored policy decision,
  with archival read compatibility for existing v1 database rows. Legacy v1 rows
  cannot be mutated, and their authorization state is rejected as untrusted.
- Cross-checks between lifecycle state, valid distinct approvals, policy metadata,
  observations, and hash-linked audit evidence.
- Mock outcome simulator, browser dashboard, tests, and boundary scanner.
- Open-source governance, security, architecture, and integration guidance.
