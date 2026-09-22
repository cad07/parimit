import assert from "node:assert/strict";
import test from "node:test";

import {
  AINXT_OS_REVIEWED_COMMIT,
  AINXT_SYNTHETIC_SCENARIOS,
  AINXT_TOOL_NAMES,
  AiNxtAdapterError,
  AiNxtParimitAdapter,
} from "../integrations/ainxt/adapter.ts";

const AINXT_URL = "http://127.0.0.1:8080";
const PARIMIT_URL = "http://127.0.0.1:8787";
const TOKEN = "header.payload.signature";
const ACTOR_ID = `oidc:${"a".repeat(64)}`;
const CONTROL_PLANE_SHA = "pilot-control-plane-2026-09-22";

interface CapturedCall {
  url: string;
  method: string;
  headers: Headers;
  body?: unknown;
}

interface FakeOptions {
  safety?: Record<string, unknown>;
  actorRole?: "agent" | "approver" | "consumer" | "admin";
  authenticationMethod?: "oidc" | "local_demo_headers";
  draftText?: string;
  draftTexts?: string[];
  policyAllowed?: unknown;
  creationDenied?: boolean;
  wrongOwner?: boolean;
  wrongIntentId?: boolean;
  mutateSseFrames?: (frames: Array<Record<string, unknown>>) => Array<Record<string, unknown>>;
}

function safety(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "Parimit",
    version: "0.1.0-alpha.3",
    mode: "PROPOSAL_ONLY",
    moves_money: false,
    connects_to_upi: false,
    live_payment_credentials_accepted: false,
    execution_routes: [],
    ...overrides,
  };
}

function draft(): string {
  return JSON.stringify({
    amount: { currency: "INR", minor: "49900" },
    payee_reference: "demo-coffee-merchant",
    purpose: "Synthetic order DEMO-COFFEE-001",
    on_behalf_of: "demo-customer-1",
    expires_in_seconds: 300,
  });
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function sseResponse(
  session: string,
  turn: string,
  text: string,
  mutate: FakeOptions["mutateSseFrames"],
): Response {
  const envelope = (seq: number, type: string, fields: Record<string, unknown> = {}) => ({
    v: "1.0",
    session_id: session,
    turn_id: turn,
    seq,
    ts: `2026-09-22T00:00:0${seq}Z`,
    control_plane_sha: CONTROL_PLANE_SHA,
    type,
    ...fields,
  });
  const baseFrames = [
    envelope(1, "turn.started"),
    envelope(2, "text.delta", { text }),
    envelope(3, "turn.completed", { outcome: "complete" }),
  ];
  const frames = mutate?.(baseFrames) ?? baseFrames;
  const body = frames
    .map((frame, index) => `id: ${index + 1}\ndata: ${JSON.stringify(frame)}\n\n`)
    .join("");
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/event-stream; charset=utf-8" },
  });
}

function requestBody(init: RequestInit | undefined): unknown {
  if (typeof init?.body !== "string") return undefined;
  return JSON.parse(init.body);
}

function fakeFetch(options: FakeOptions = {}): {
  fetch: typeof fetch;
  calls: CapturedCall[];
} {
  const calls: CapturedCall[] = [];
  let intentReplay = false;
  let draftCall = 0;
  const implementation: typeof fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init.method ?? "GET";
    const headers = new Headers(init.headers);
    const body = requestBody(init);
    calls.push({ url, method, headers, ...(body === undefined ? {} : { body }) });

    if (url === `${PARIMIT_URL}/v1/safety`) {
      return jsonResponse({ data: options.safety ?? safety() });
    }
    if (url === `${PARIMIT_URL}/v1/identity`) {
      return jsonResponse({
        data: {
          actor_id: ACTOR_ID,
          actor_role: options.actorRole ?? "agent",
          authentication_method: options.authenticationMethod ?? "oidc",
          issuer: "https://identity.test.example/realms/parimit",
        },
      });
    }
    if (url === `${AINXT_URL}/v1/chat`) {
      const record = body as Record<string, unknown>;
      const text = options.draftTexts?.[draftCall] ?? options.draftText ?? draft();
      draftCall += 1;
      return sseResponse(
        String(record.session),
        String(record.turn),
        text,
        options.mutateSseFrames,
      );
    }
    if (url === `${PARIMIT_URL}/v1/intents/simulate`) {
      return jsonResponse({
        data: {
          policy: {
            allowed: options.policyAllowed ?? true,
            reasons: options.policyAllowed === false ? ["PAYEE_NOT_ALLOWED"] : [],
            rules_version: "2026-09-19",
            config_digest: "sha256:test",
            required_approvals: 1,
            current_daily_exposure_minor: "0",
            projected_daily_exposure_minor: "49900",
          },
          persisted: false,
          moves_money: false,
        },
      });
    }
    if (url === `${PARIMIT_URL}/v1/intents` && method === "POST") {
      const proposal = body as Record<string, unknown>;
      if (options.creationDenied) {
        return jsonResponse({
          data: {
            id: "intent-denied-1",
            idempotency_key: proposal.idempotency_key,
            requested_by: proposal.requested_by,
            amount: proposal.amount,
            payee_reference: proposal.payee_reference,
            purpose: proposal.purpose,
            initial_status: "POLICY_DENIED",
            status: "POLICY_DENIED",
            policy: { allowed: false, reasons: ["DAILY_LIMIT_EXCEEDED"], rules_version: "2026-09-19" },
          },
        }, 201);
      }
      const response = {
        id: options.wrongIntentId ? "intent-other-1" : "intent-demo-1",
        idempotency_key: proposal.idempotency_key,
        requested_by: options.wrongOwner
          ? { type: "agent", id: `oidc:${"b".repeat(64)}` }
          : proposal.requested_by,
        on_behalf_of: proposal.on_behalf_of,
        amount: proposal.amount,
        payee_reference: proposal.payee_reference,
        purpose: proposal.purpose,
        initial_status: "AWAITING_APPROVAL",
        status: "AWAITING_APPROVAL",
        required_approvals: 1,
        policy: { allowed: true, reasons: [], rules_version: "2026-09-19" },
        ...(intentReplay ? { idempotent_replay: true } : {}),
      };
      const status = intentReplay ? 200 : 201;
      intentReplay = true;
      return jsonResponse({ data: response }, status);
    }
    if (url === `${PARIMIT_URL}/v1/intents/intent-demo-1` && method === "GET") {
      return jsonResponse({
        data: {
          id: options.wrongIntentId ? "intent-other-1" : "intent-demo-1",
          idempotency_key: "ainxt-demo-1",
          requested_by: options.wrongOwner
            ? { type: "agent", id: `oidc:${"b".repeat(64)}` }
            : { type: "agent", id: ACTOR_ID },
          status: "AWAITING_APPROVAL",
        },
      });
    }
    if (url === `${PARIMIT_URL}/v1/intents/intent-demo-1/cancel` && method === "POST") {
      return jsonResponse({
        data: {
          id: options.wrongIntentId ? "intent-other-1" : "intent-demo-1",
          idempotency_key: "ainxt-demo-1",
          requested_by: options.wrongOwner
            ? { type: "agent", id: `oidc:${"b".repeat(64)}` }
            : { type: "agent", id: ACTOR_ID },
          status: "CANCELLED",
        },
      });
    }
    throw new Error(`Unexpected request: ${method} ${url}`);
  };
  return { fetch: implementation, calls };
}

function adapter(implementation: typeof fetch): AiNxtParimitAdapter {
  return new AiNxtParimitAdapter({
    ainxtBaseUrl: AINXT_URL,
    parimitBaseUrl: PARIMIT_URL,
    accessToken: TOKEN,
    fetch: implementation,
  });
}

function parimitCalls(calls: CapturedCall[]): CapturedCall[] {
  return calls.filter((call) => call.url.startsWith(PARIMIT_URL));
}

test("AiNxt adapter exposes exactly four proposal-safe operations", () => {
  assert.equal(AINXT_OS_REVIEWED_COMMIT, "454fb09cf1fff2bedb5aa3f4f1c391e4915f33dd");
  assert.deepEqual(AINXT_SYNTHETIC_SCENARIOS, ["coffee_order", "mobility_pass"]);
  assert.deepEqual(AINXT_TOOL_NAMES, [
    "parimit_simulate_proposal",
    "parimit_create_proposal",
    "parimit_get_proposal",
    "parimit_cancel_proposal",
  ]);
  const forbidden = /(?:^|_)(?:approve|authorise|authorize|debit|dispatch|execute|initiate|pay|retry|send|transfer)(?:_|$)/;
  assert.equal(AINXT_TOOL_NAMES.some((name) => forbidden.test(name)), false);

  const fake = fakeFetch();
  const client = adapter(fake.fetch);
  assert.deepEqual(Object.getOwnPropertyNames(client), ["tools"]);
  assert.deepEqual(
    Object.getOwnPropertyNames(Object.getPrototypeOf(client)).sort(),
    ["cancelProposal", "constructor", "createProposal", "getProposal", "simulateProposal"].sort(),
  );
  assert.equal("parimit" in client, false);
});

test("AiNxt draft creates one self-bound proposal and replay is idempotent", async () => {
  const alternateDraft = JSON.stringify({
    amount: { currency: "INR", minor: "125000" },
    payee_reference: "demo-mobility-pass",
    purpose: "Synthetic pass DEMO-MOBILITY-001",
    on_behalf_of: "demo-customer-1",
    expires_in_seconds: 300,
  });
  const fake = fakeFetch({ draftTexts: [draft(), alternateDraft] });
  const client = adapter(fake.fetch);
  const request = {
    scenario: "coffee_order" as const,
    idempotency_key: "ainxt-demo-1",
  };

  const first = await client.createProposal(request);
  const replay = await client.createProposal(request);

  assert.equal(first.intent.id, "intent-demo-1");
  assert.equal(replay.intent.id, "intent-demo-1");
  assert.equal(replay.intent.idempotent_replay, true);
  assert.equal(first.moves_money, false);
  assert.equal(first.simulation_persisted, false);
  assert.equal(first.proposal_persisted, true);
  assert.equal(first.ainxt.reviewed_source_commit, AINXT_OS_REVIEWED_COMMIT);
  assert.equal(first.ainxt.control_plane_sha, CONTROL_PLANE_SHA);
  assert.throws(() => {
    first.draft.amount.minor = "1";
  }, TypeError);
  assert.throws(() => {
    first.simulation_policy.allowed = false;
  }, TypeError);

  const ainxtCalls = fake.calls.filter((call) => call.url === `${AINXT_URL}/v1/chat`);
  assert.equal(ainxtCalls.length, 1, "one validated draft is reused for same-process replay");
  for (const call of ainxtCalls) {
    assert.equal(call.headers.has("authorization"), false, "Parimit bearer token must not reach AiNxt");
    assert.equal(call.headers.get("x-ainxt-user"), ACTOR_ID);
    assert.equal(call.headers.get("x-ainxt-role"), "user");
    assert.equal(call.headers.get("x-ainxt-department"), "parimit-pilot");
    assert.equal(call.headers.get("x-ainxt-caps"), "chat.send");
    assert.equal(call.headers.get("x-ainxt-clearance"), "internal");
    assert.equal(JSON.stringify(call.body).includes(TOKEN), false);
    assert.deepEqual((call.body as Record<string, unknown>).caps, ["chat.send"]);
    assert.equal((call.body as Record<string, unknown>).data_class, "internal");
  }

  const writes = fake.calls.filter(
    (call) => call.url === `${PARIMIT_URL}/v1/intents` && call.method === "POST",
  );
  assert.equal(writes.length, 2);
  assert.deepEqual(writes[0]!.body, writes[1]!.body);
  assert.equal(
    fake.calls.filter((call) => call.url === `${PARIMIT_URL}/v1/intents/simulate`).length,
    1,
    "an already-created cached draft replays at Parimit before policy can drift",
  );
  const proposal = writes[0]!.body as Record<string, unknown>;
  assert.deepEqual(proposal.requested_by, { type: "agent", id: ACTOR_ID });
  assert.equal(JSON.stringify(proposal).includes(TOKEN), false);

  for (const call of parimitCalls(fake.calls)) {
    assert.equal(call.headers.get("authorization"), `Bearer ${TOKEN}`);
  }
  assert.equal(
    fake.calls.some((call) => /approvals|evidence-envelopes|observations|execute|dispatch/.test(call.url)),
    false,
  );
});

test("AiNxt output is treated as an untrusted draft and fails closed", async () => {
  const fake = fakeFetch({ draftText: "```json\n{}\n```" });
  const client = adapter(fake.fetch);
  await assert.rejects(
    client.createProposal({ scenario: "coffee_order", idempotency_key: "bad-draft-1" }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "AINXT_DRAFT_INVALID",
  );
  assert.equal(
    fake.calls.some((call) => call.url === `${PARIMIT_URL}/v1/intents/simulate`),
    false,
  );
  assert.equal(
    fake.calls.some((call) => call.url === `${PARIMIT_URL}/v1/intents` && call.method === "POST"),
    false,
  );
});

test("AiNxt SSE envelope, ordering, turn binding, completion, and control-plane identity fail closed", async () => {
  const cases: Array<FakeOptions["mutateSseFrames"]> = [
    (frames) => frames.map((frame, index) => index === 1 ? { ...frame, seq: 1 } : frame),
    (frames) => frames.map((frame, index) => index === 1 ? { ...frame, session_id: "other" } : frame),
    (frames) => frames.map((frame, index) => {
      if (index !== 1) return frame;
      const { turn_id: _removed, ...withoutTurn } = frame;
      return withoutTurn;
    }),
    (frames) => frames.map((frame, index) =>
      index === 1 ? { ...frame, control_plane_sha: "changed-mid-turn" } : frame),
    (frames) => frames.map((frame, index) =>
      index === 2 ? { ...frame, outcome: "capped" } : frame),
    (frames) => [
      ...frames,
      { ...frames[1]!, seq: 4, ts: "2026-09-22T00:00:04Z" },
    ],
  ];

  for (const [index, mutateSseFrames] of cases.entries()) {
    const fake = fakeFetch({ mutateSseFrames });
    await assert.rejects(
      adapter(fake.fetch).simulateProposal({
        scenario: "coffee_order",
        idempotency_key: `bad-sse-${index}`,
      }),
      (error: unknown) =>
        error instanceof AiNxtAdapterError && error.code === "AINXT_RESPONSE_REFUSED",
    );
    assert.equal(
      fake.calls.some((call) => call.url === `${PARIMIT_URL}/v1/intents/simulate`),
      false,
    );
  }
});

test("draft schema rejects extra fields and unknown scenarios", async () => {
  const withExtraField = JSON.stringify({ ...JSON.parse(draft()), requester_id: "attacker" });
  const fake = fakeFetch({ draftText: withExtraField });
  await assert.rejects(
    adapter(fake.fetch).simulateProposal({
      scenario: "coffee_order",
      idempotency_key: "extra-field-1",
    }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "AINXT_DRAFT_INVALID",
  );

  const unknown = fakeFetch();
  await assert.rejects(
    adapter(unknown.fetch).simulateProposal({
      scenario: "user-supplied-live-text" as never,
      idempotency_key: "unknown-scenario-1",
    }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "AINXT_DRAFT_INVALID",
  );
  assert.equal(unknown.calls.some((call) => call.url === `${AINXT_URL}/v1/chat`), false);

  const wrongFixture = fakeFetch({
    draftText: JSON.stringify({
      amount: { currency: "INR", minor: "50000" },
      payee_reference: "demo-other-merchant",
      purpose: "Synthetic order DEMO-OTHER-001",
      on_behalf_of: "demo-customer-1",
      expires_in_seconds: 300,
    }),
  });
  await assert.rejects(
    adapter(wrongFixture.fetch).simulateProposal({
      scenario: "coffee_order",
      idempotency_key: "test1",
    }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "AINXT_DRAFT_INVALID",
  );
});

test("unsafe Parimit metadata or a non-agent identity stops before AiNxt", async () => {
  for (const options of [
    { safety: safety({ moves_money: true }) },
    { safety: safety({ connects_to_upi: true }) },
    { safety: safety({ live_payment_credentials_accepted: true }) },
    { safety: safety({ execution_routes: ["/v1/execute"] }) },
    { safety: safety({ mode: "EXECUTION_ENABLED" }) },
    { actorRole: "approver" as const },
    { authenticationMethod: "local_demo_headers" as const },
  ]) {
    const fake = fakeFetch(options);
    const client = adapter(fake.fetch);
    await assert.rejects(
      client.simulateProposal({ scenario: "coffee_order", idempotency_key: "guard-1" }),
      AiNxtAdapterError,
    );
    assert.equal(fake.calls.some((call) => call.url === `${AINXT_URL}/v1/chat`), false);
  }
});

test("simulation policy denial makes no create request", async () => {
  const fake = fakeFetch({ policyAllowed: false });
  const client = adapter(fake.fetch);
  await assert.rejects(
    client.createProposal({ scenario: "coffee_order", idempotency_key: "denied-1" }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "PARIMIT_POLICY_DENIED",
  );
  assert.equal(
    fake.calls.some((call) => call.url === `${PARIMIT_URL}/v1/intents` && call.method === "POST"),
    false,
  );
});

test("malformed policy metadata and an atomic creation-time denial fail closed", async () => {
  const malformed = fakeFetch({ policyAllowed: "false" });
  await assert.rejects(
    adapter(malformed.fetch).createProposal({
      scenario: "coffee_order",
      idempotency_key: "malformed-policy-1",
    }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "PARIMIT_RESPONSE_REFUSED",
  );
  assert.equal(
    malformed.calls.some((call) => call.url === `${PARIMIT_URL}/v1/intents` && call.method === "POST"),
    false,
  );

  const raced = fakeFetch({ creationDenied: true });
  await assert.rejects(
    adapter(raced.fetch).createProposal({
      scenario: "coffee_order",
      idempotency_key: "creation-race-1",
    }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "PARIMIT_POLICY_DENIED",
  );
  assert.equal(
    raced.calls.some((call) => call.url === `${PARIMIT_URL}/v1/intents` && call.method === "POST"),
    true,
    "Parimit may persist a non-actionable denial audit record when policy changes after simulation",
  );
});

test("get and cancel remain agent-owned and do not invoke AiNxt", async () => {
  const fake = fakeFetch();
  const client = adapter(fake.fetch);
  const found = await client.getProposal("intent-demo-1");
  const cancelled = await client.cancelProposal("intent-demo-1");
  assert.equal(found.status, "AWAITING_APPROVAL");
  assert.equal(cancelled.status, "CANCELLED");
  assert.equal(fake.calls.some((call) => call.url === `${AINXT_URL}/v1/chat`), false);
});

test("mismatched owner or intent id is refused", async () => {
  const wrongOwner = fakeFetch({ wrongOwner: true });
  await assert.rejects(
    adapter(wrongOwner.fetch).getProposal("intent-demo-1"),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "PARIMIT_RESPONSE_REFUSED",
  );

  const wrongId = fakeFetch({ wrongIntentId: true });
  await assert.rejects(
    adapter(wrongId.fetch).getProposal("intent-demo-1"),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "PARIMIT_RESPONSE_REFUSED",
  );

  const wrongCreateOwner = fakeFetch({ wrongOwner: true });
  await assert.rejects(
    adapter(wrongCreateOwner.fetch).createProposal({
      scenario: "coffee_order",
      idempotency_key: "wrong-owner-create-1",
    }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "PARIMIT_RESPONSE_REFUSED",
  );
});

test("one idempotency key cannot switch synthetic scenarios", async () => {
  const fake = fakeFetch();
  const client = adapter(fake.fetch);
  await client.simulateProposal({ scenario: "coffee_order", idempotency_key: "stable-key-1" });
  await assert.rejects(
    client.simulateProposal({ scenario: "mobility_pass", idempotency_key: "stable-key-1" }),
    (error: unknown) =>
      error instanceof AiNxtAdapterError && error.code === "AINXT_DRAFT_INVALID",
  );
  assert.equal(
    fake.calls.filter((call) => call.url === `${AINXT_URL}/v1/chat`).length,
    1,
  );
});

test("adapter rejects insecure non-loopback endpoints and malformed tokens", () => {
  assert.throws(
    () =>
      new AiNxtParimitAdapter({
        ainxtBaseUrl: "http://ainxt.example/v1",
        parimitBaseUrl: PARIMIT_URL,
        accessToken: TOKEN,
      }),
    AiNxtAdapterError,
  );
  assert.throws(
    () =>
      new AiNxtParimitAdapter({
        ainxtBaseUrl: AINXT_URL,
        parimitBaseUrl: PARIMIT_URL,
        accessToken: "token with spaces",
      }),
    AiNxtAdapterError,
  );
  assert.throws(
    () =>
      new AiNxtParimitAdapter({
        ainxtBaseUrl: "https://ainxt.example",
        parimitBaseUrl: PARIMIT_URL,
        accessToken: TOKEN,
      }),
    AiNxtAdapterError,
  );
});
