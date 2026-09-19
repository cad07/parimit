# Requirements for a real payment integration

Parimit v0.1 has no real payment integration. Adding one is a regulated,
security-critical product project—not a configuration toggle.

## Required external relationships

- A licensed bank, PSP, or authorized payment aggregator willing to onboard
  the operating entity and intended use case.
- Written confirmation of supported payment flows, consent model, transaction
  limits, dispute duties, data residency, and sandbox/production access.
- Legal advice on applicable RBI, NPCI, consumer-protection, privacy,
  anti-money-laundering, tax, accessibility, and sector-specific obligations.
- Any required provider, sponsor-bank, network, or auditor certification.

Open-source software and an NPCI public repository do not provide rail access,
credentials, sponsorship, certification, or permission to use payment marks.

## Minimum technical architecture

```text
untrusted agent -> proposal plane -> human decision
                                      |
                         short-lived signed authorization
                                      |
                    deterministic executor (separate service)
                                      |
                       licensed bank/PSP provider API
                                      |
                           webhook + reconciliation
```

The executor must not host an LLM, accept natural-language commands, or expose
its provider credential to the agent plane. Use strict schemas, mutual service
authentication, replay protection, transaction-level idempotency, allowlisted
destinations, least-privilege credentials, and hard limits enforced again at
the executor.

## Identity and consent

- Phishing-resistant authentication for approvers where feasible.
- Verified role and tenant membership, short sessions, step-up authentication,
  and clear separation of requester and approver.
- Consent text that shows exact payee, amount, currency, purpose, timing, and
  revocation behavior.
- Accessible review and recovery experiences without dark patterns.
- A defined process for compromised accounts, lost devices, and employee exit.

## Money and state correctness

- Integer minor-unit arithmetic with currency-specific validation.
- Provider-scoped idempotency and immutable end-to-end correlation identifiers.
- Transactional outbox/inbox or equivalent reliable messaging.
- Authenticated webhook verification with replay and ordering protection.
- Explicit `IN_DOUBT`, reversal, refund, and partial-failure handling.
- Independent reconciliation against provider or bank statements.
- No automatic retry when a debit may have succeeded.
- Double-entry accounting or an equivalent auditable ledger where balances or
  obligations are represented.

## Security and operations

- Hardware-backed or managed key storage, rotation, revocation, and audit.
- Encryption in transit and at rest with data classification and retention.
- Threat modelling, penetration testing, secure SDLC, SBOM, signed releases,
  dependency controls, and incident exercises.
- Alerting for velocity, anomalous payees, repeated denials, reconciliation
  drift, webhook failures, and privileged changes.
- Tested backup/restore, disaster recovery, availability objectives, and a
  manual kill switch independent of the agent.
- Privacy impact assessment and procedures for access, deletion, legal hold,
  and breach notification.

## Before the first real transaction

1. Replace demo identity, storage, secrets, and audit mechanisms.
2. Complete architecture and legal reviews with the chosen provider.
3. Map every control to an owner and evidence source.
4. Test in the provider sandbox, then a tightly controlled certification
   environment using no real customer data.
5. Run adversarial agent tests, authorization tests, concurrency tests,
   reconciliation drills, and incident simulations.
6. Obtain all required approvals in writing.
7. Launch with conservative limits, narrow allowlists, manual monitoring, and a
   rehearsed shutdown path.

None of these steps changes the core rule: the AI proposes, while deterministic
systems and accountable humans control any real-world value movement.
