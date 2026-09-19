# Parimit

**Bounded authority for agent payments.**

Parimit (परिमित, pronounced *puh-REE-mit*) means measured or bounded. It is an
open-source, proposal-only payment-intent governance boundary for AI agents.

> **Alpha safety demo:** Parimit does not connect to UPI, a bank, a PSP,
> or any live payment rail. It cannot move money. Do not treat it as a payment
> processor, authorization system, or compliance certification.

Parimit lets an agent propose a structured payment intent, applies
deterministic policy, asks a human to approve or reject the exact intent, and
keeps a tamper-evident audit history. The included rail is a simulator for
safe demonstrations of success, failure, reversal, and uncertain outcomes.

## The boundary

```text
AI agent                         Human operator
    |                                  |
    | propose / read / cancel own      | approve or reject exact proposal
    v                                  v
+------------------------- Parimit -------------------------+
| validation -> policy -> approval -> HMAC receipt -> audit |
+-----------------------------------------------------------+
                              |
                              v
                     mock simulator only
                        (never money)
```

The MCP surface intentionally exposes no `pay`, `send`, `initiate`, `execute`,
or `approve` capability. The HTTP demo contains a separate dashboard approval
route using clearly labelled, spoofable local headers; it is not a production
identity boundary and must never be exposed as an agent tool. No surface can
dispatch an approval to a payment rail.

## What works in v0.1

- Create a proposal with an agent-scoped idempotency key.
- Validate amount, currency, payee, purpose, and expiry.
- Apply deterministic amount, allowlist, and velocity policies.
- Require one or two distinct human approvals according to policy.
- Cancel or inspect a proposal without moving funds.
- Produce an HMAC-protected, non-dispatchable authorization receipt.
- Append hash-chained audit events.
- Simulate labelled outcomes; recording `IN_DOUBT` freezes the mock observation
  stream and rejects every later mock outcome.
- Use the browser dashboard, REST API, or proposal-only MCP server.
- Run locally with Node.js 24 and no third-party runtime dependencies.

## Quick start

Requirements: [Node.js 24](https://nodejs.org/) and a modern browser.

```sh
git clone https://github.com/cad07/parimit.git
cd parimit
npm start
```

Open <http://localhost:8787>. The application stores demo state locally; it is
not suitable for shared or production deployment.

Run the tests and the safety-boundary scanner:

```sh
npm test
npm run check:boundary
```

Run the MCP server over standard input/output:

```sh
npm run mcp
```

For a containerized demo:

```sh
docker compose up --build
```

## Configuration

The server reads configuration from exported environment variables. The Node
process does not load `.env` automatically; `.env.example` is a reference.
Docker Compose forwards the receipt and policy variables from a local `.env`
file, while keeping its container host, port, database path, and demo mode fixed.

| Variable | Local default | Meaning |
| --- | --- | --- |
| `PARIMIT_HOST` | `127.0.0.1` | Bind address |
| `PARIMIT_PORT` | `8787` | HTTP port |
| `PARIMIT_DB_PATH` | `./data/parimit.db` | Demo SQLite database |
| `PARIMIT_DEMO_MODE` | `true` | This alpha refuses to start when set false |
| `PARIMIT_RECEIPT_KEY` | insecure development value | HMAC key for demo approval receipts |
| `PARIMIT_PER_TX_LIMIT` | `100000` | Per-proposal ceiling in paise (₹1,000.00) |
| `PARIMIT_DAILY_AGENT_LIMIT` | `500000` | Per-agent daily ceiling in paise (₹5,000.00) |
| `PARIMIT_DUAL_APPROVAL_THRESHOLD` | `50000` | Require two people above this demo threshold (₹500.00) |
| `PARIMIT_INTENT_TTL_SECONDS` | `1800` | Default proposal lifetime |
| `PARIMIT_MAX_EXPIRY_SECONDS` | `86400` | Maximum requested lifetime |
| `PARIMIT_BLOCKED_PAYEES` | empty | Comma-separated normalized denylist |
| `PARIMIT_ALLOWED_PAYEES` | unset | Optional comma-separated allowlist |

Use only fictional references. Do not put bank, PSP, UPI, OTP, PIN, or customer
credentials into this application or its environment.

## Safe demo

1. Create a proposal for a small amount and a fictional demo payee.
2. Observe the deterministic policy decision.
3. Open the approval view and approve the exact proposal as a human.
4. Create a ₹600.00 proposal and use two distinct demo approvers.
5. Run the mock simulator and select success, failure, reversal, or
   `IN_DOUBT`.
6. After `IN_DOUBT`, try another mock outcome and confirm that it is rejected
   with `IN_DOUBT_FROZEN`; this alpha has no reconciliation bypass.
7. Inspect the audit chain. Re-submit the same idempotency key to see duplicate
   protection.

Nothing in this flow contacts an external service or moves money.

## Agent interfaces

The REST contract is in [`openapi.yaml`](openapi.yaml). The MCP server is
deliberately narrower and exposes only proposal-safe tools:

- `create_payment_proposal`
- `get_payment_status`
- `cancel_payment_proposal`
- `get_policy_decision`
- `simulate_payment` (mock outcomes only)
- `get_payment_audit`

MCP clients must not be given the human dashboard credentials or direct access
to internal approval routes. See [`docs/safety-boundary.md`](docs/safety-boundary.md).

## Design principles

- **Agents propose; review stays separate.** The MCP surface has no approval
  tool. The local HTTP demo rejects an `agent` role and the requester identifier,
  but its spoofable headers are workflow labels—not human authentication.
- **Approval is not execution.** A receipt describes human authorization but
  is structurally non-dispatchable.
- **Exact-intent binding.** Changing amount, currency, payee, or purpose
  invalidates earlier approvals.
- **Fail closed.** Invalid policy, expired intent, audit mismatch, and uncertain
  state all stop progress.
- **Freeze after uncertainty.** Once `IN_DOUBT` is recorded, all later mock
  observations are rejected. This alpha exposes no reconciliation mechanism.
- **Pure core.** Domain and policy code cannot import network modules.

The repository enforces part of this boundary with
[`scripts/check-boundary.ts`](scripts/check-boundary.ts) in CI.

## Documentation

- [Technical design and implementation status paper](docs/design-paper.md) ([PDF](docs/parimit-design-paper-v0.1.pdf))
- [Architecture](docs/architecture.md)
- [API and MCP usage](docs/api.md)
- [Threat model](docs/threat-model.md)
- [Safety boundary](docs/safety-boundary.md)
- [Safe demo](docs/demo.md)
- [Adapter guide](docs/adapter-guide.md)
- [Requirements for a real payment integration](docs/real-integration-requirements.md)
- [Decision record: proposal-only](docs/decisions/0001-proposal-only.md)

## Relationship to NPCI AiNxt OS

The design was informed by the public, non-dispatchable payment boundary in
NPCI's AiNxt OS, reviewed at commit
[`5b6fbb90eb715384559256f7257e4d661cb1d17b`](https://github.com/NPCI/ainxt-os/tree/5b6fbb90eb715384559256f7257e4d661cb1d17b).
AiNxt's settlement documentation states that its payment core does not perform
I/O or talk to banks. Parimit preserves the same separation in its own
independently written implementation.

No AiNxt source code is copied into this initial release. Parimit is not
affiliated with or endorsed by NPCI, and it must not use NPCI, AiNxt, or UPI
logos. See [`NOTICE`](NOTICE).

## Contributing and security

Contributions are welcome, particularly policy tests, threat-model review,
accessibility improvements, and additional mock scenarios. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) first.

Please do not open public issues for vulnerabilities. Follow
[`SECURITY.md`](SECURITY.md) to report them privately.

## License

MIT. See [`LICENSE`](LICENSE). Product and payment-network names belong to their
respective owners.
