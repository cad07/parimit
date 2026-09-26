import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";

import { createProxyServer } from "../scripts/ollama-openai-nothink-proxy.mjs";

let upstreamServer;
let proxyServer;
let proxyBaseUrl;
const upstreamRequests = [];

function listenLoopback(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(server.address());
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
    server.closeAllConnections?.();
  });
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.once("end", () => resolve(Buffer.concat(chunks)));
    request.once("error", reject);
  });
}

before(async () => {
  upstreamServer = http.createServer(async (request, response) => {
    const body = await readBody(request);
    upstreamRequests.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body,
    });
    response.writeHead(202, { "content-type": "application/x-selftest" });
    response.write("UPSTREAM-");
    response.end("BYTES");
  });

  const upstreamAddress = await listenLoopback(upstreamServer);
  proxyServer = createProxyServer({ upstreamPort: upstreamAddress.port });
  const proxyAddress = await listenLoopback(proxyServer);
  proxyBaseUrl = `http://${proxyAddress.address}:${proxyAddress.port}`;
});

after(async () => {
  await Promise.all([closeServer(proxyServer), closeServer(upstreamServer)]);
});

test("health is loopback-local and does not reach the model upstream", async () => {
  const response = await fetch(`${proxyBaseUrl}/healthz`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok" });
  assert.equal(upstreamRequests.length, 0);
});

test("only the two exact routes and their expected methods are exposed", async () => {
  const unknown = await fetch(`${proxyBaseUrl}/missing`);
  assert.equal(unknown.status, 404);

  const healthWithQuery = await fetch(`${proxyBaseUrl}/healthz?verbose=1`);
  assert.equal(healthWithQuery.status, 404);

  const wrongHealthMethod = await fetch(`${proxyBaseUrl}/healthz`, {
    method: "POST",
  });
  assert.equal(wrongHealthMethod.status, 405);
  assert.equal(wrongHealthMethod.headers.get("allow"), "GET");

  const wrongCompletionMethod = await fetch(
    `${proxyBaseUrl}/v1/chat/completions`,
  );
  assert.equal(wrongCompletionMethod.status, 405);
  assert.equal(wrongCompletionMethod.headers.get("allow"), "POST");
  assert.equal(upstreamRequests.length, 0);
});

test("JSON, model, and request-size guards reject locally", async () => {
  const wrongMediaType = await fetch(
    `${proxyBaseUrl}/v1/chat/completions`,
    { method: "POST", body: "{}" },
  );
  assert.equal(wrongMediaType.status, 415);

  const wrongModel = await fetch(`${proxyBaseUrl}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "another-model" }),
  });
  assert.equal(wrongModel.status, 400);

  const oversized = await fetch(`${proxyBaseUrl}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "qwen3.5:4b",
      padding: "x".repeat(256 * 1024),
    }),
  });
  assert.equal(oversized.status, 413);
  assert.equal(upstreamRequests.length, 0);
});

test("allowed requests get fixed controls and stream only to loopback upstream", async () => {
  const response = await fetch(`${proxyBaseUrl}/v1/chat/completions`, {
    method: "POST",
    headers: {
      authorization: "Bearer must-not-be-forwarded",
      cookie: "must-not-be-forwarded=1",
      "content-type": "application/json",
      "x-must-not-be-forwarded": "sentinel",
    },
    body: JSON.stringify({
      model: "qwen3.5:4b",
      messages: [{ role: "user", content: "self-test sentinel" }],
      reasoning_effort: "high",
      stream: true,
      temperature: 0.9,
    }),
  });

  assert.equal(response.status, 202);
  assert.equal(response.headers.get("content-type"), "application/x-selftest");
  assert.equal(await response.text(), "UPSTREAM-BYTES");
  assert.equal(upstreamRequests.length, 1);

  const [upstreamRequest] = upstreamRequests;
  assert.equal(upstreamRequest.method, "POST");
  assert.equal(upstreamRequest.url, "/v1/chat/completions");
  assert.equal(upstreamRequest.headers.authorization, undefined);
  assert.equal(upstreamRequest.headers.cookie, undefined);
  assert.equal(upstreamRequest.headers["x-must-not-be-forwarded"], undefined);
  assert.equal(upstreamRequest.headers["content-type"], "application/json");

  const forwardedBody = JSON.parse(upstreamRequest.body.toString("utf8"));
  assert.equal(forwardedBody.model, "qwen3.5:4b");
  assert.equal(forwardedBody.reasoning_effort, "none");
  assert.equal(forwardedBody.temperature, 0);
  assert.equal(forwardedBody.stream, true);
  assert.deepEqual(forwardedBody.messages, [
    { role: "user", content: "self-test sentinel" },
  ]);
});

test("factory only accepts valid loopback upstream ports", () => {
  assert.throws(
    () => createProxyServer({ upstreamPort: 0 }),
    /upstreamPort must be an integer/,
  );
  assert.throws(
    () => createProxyServer({ upstreamPort: "11434" }),
    /upstreamPort must be an integer/,
  );
  assert.throws(
    () => createProxyServer({ upstreamPort: 65_536 }),
    /upstreamPort must be an integer/,
  );
});
