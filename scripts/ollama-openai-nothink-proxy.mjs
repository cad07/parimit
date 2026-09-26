import http from "node:http";
import { pathToFileURL } from "node:url";

const LISTEN_HOST = "127.0.0.1";
const LISTEN_PORT = 11435;
const UPSTREAM_HOST = "127.0.0.1";
const UPSTREAM_PORT = 11434;
const UPSTREAM_PATH = "/v1/chat/completions";
const ALLOWED_MODEL = "qwen3.5:4b";
const MAX_BODY_BYTES = 256 * 1024;
const BODY_TIMEOUT_MS = 15_000;
const UPSTREAM_TIMEOUT_MS = 180_000;

// Local compatibility profile: the pinned AiNxt build cannot forward reasoning
// controls, so this loopback-only shim injects the fixed controls before Ollama.

class RequestError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

function sendJson(response, statusCode, value, { close = false } = {}) {
  if (response.destroyed || response.headersSent) return;

  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(statusCode, {
    "cache-control": "no-store",
    connection: close ? "close" : "keep-alive",
    "content-length": String(body.length),
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const contentType = request.headers["content-type"];
    const mediaType =
      typeof contentType === "string"
        ? contentType.split(";", 1)[0].trim().toLowerCase()
        : "";
    if (mediaType !== "application/json") {
      reject(new RequestError(415, "content-type must be application/json"));
      request.resume();
      return;
    }

    const contentEncoding = request.headers["content-encoding"];
    if (
      contentEncoding !== undefined &&
      String(contentEncoding).trim().toLowerCase() !== "identity"
    ) {
      reject(new RequestError(415, "content-encoding is not supported"));
      request.resume();
      return;
    }

    const contentLength = request.headers["content-length"];
    if (contentLength !== undefined) {
      const declaredBytes = Number(contentLength);
      if (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0) {
        reject(new RequestError(400, "invalid content-length"));
        request.resume();
        return;
      }
      if (declaredBytes > MAX_BODY_BYTES) {
        reject(new RequestError(413, "request body is too large"));
        request.resume();
        return;
      }
    }

    let settled = false;
    let receivedBytes = 0;
    const chunks = [];
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      reject(new RequestError(408, "request body timed out"));
      request.resume();
    }, BODY_TIMEOUT_MS);
    timeout.unref();

    request.on("data", (chunk) => {
      if (settled) return;
      receivedBytes += chunk.length;
      if (receivedBytes > MAX_BODY_BYTES) {
        settled = true;
        clearTimeout(timeout);
        chunks.length = 0;
        reject(new RequestError(413, "request body is too large"));
        return;
      }
      chunks.push(chunk);
    });

    request.once("end", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);

      try {
        const value = JSON.parse(
          Buffer.concat(chunks, receivedBytes).toString("utf8"),
        );
        if (value === null || typeof value !== "object" || Array.isArray(value)) {
          throw new RequestError(400, "JSON body must be an object");
        }
        resolve(value);
      } catch (error) {
        if (error instanceof RequestError) reject(error);
        else reject(new RequestError(400, "request body is not valid JSON"));
      }
    });

    request.once("aborted", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      chunks.length = 0;
      reject(new RequestError(400, "request was aborted"));
    });

    request.once("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      chunks.length = 0;
      reject(new RequestError(400, "request could not be read"));
    });
  });
}

function forwardToOllama(request, response, body, upstreamPort) {
  const encodedBody = Buffer.from(JSON.stringify(body));
  const upstreamRequest = http.request(
    {
      host: UPSTREAM_HOST,
      port: upstreamPort,
      path: UPSTREAM_PATH,
      method: "POST",
      headers: {
        accept: "application/json",
        "content-length": String(encodedBody.length),
        "content-type": "application/json",
      },
    },
    (upstreamResponse) => {
      if (response.destroyed) {
        upstreamResponse.destroy();
        return;
      }

      const upstreamContentType = upstreamResponse.headers["content-type"];
      const contentType =
        typeof upstreamContentType === "string"
          ? upstreamContentType
          : "application/octet-stream";

      response.writeHead(upstreamResponse.statusCode ?? 502, {
        "cache-control": "no-store",
        "content-type": contentType,
        "x-content-type-options": "nosniff",
      });

      upstreamResponse.once("error", () => {
        response.destroy();
      });
      upstreamResponse.pipe(response);
    },
  );

  const stopUpstream = () => {
    if (!upstreamRequest.destroyed) upstreamRequest.destroy();
  };
  request.once("aborted", stopUpstream);
  response.once("close", () => {
    if (!response.writableEnded) stopUpstream();
  });

  upstreamRequest.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    upstreamRequest.destroy(new Error("upstream timeout"));
  });
  upstreamRequest.once("error", () => {
    if (response.destroyed || response.writableEnded) return;
    if (response.headersSent) response.destroy();
    else sendJson(response, 502, { error: "local model service unavailable" });
  });
  upstreamRequest.end(encodedBody);
}

export function createProxyServer({ upstreamPort = UPSTREAM_PORT } = {}) {
  if (
    !Number.isInteger(upstreamPort) ||
    upstreamPort < 1 ||
    upstreamPort > 65_535
  ) {
    throw new TypeError("upstreamPort must be an integer from 1 through 65535");
  }

  const server = http.createServer(async (request, response) => {
    response.on("error", () => {});

    if (request.method === "GET" && request.url === "/healthz") {
      sendJson(response, 200, { status: "ok" });
      return;
    }

    if (
      request.url === "/healthz" ||
      request.url === "/v1/chat/completions"
    ) {
      if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
        response.setHeader(
          "allow",
          request.url === "/healthz" ? "GET" : "POST",
        );
        sendJson(response, 405, { error: "method not allowed" });
        request.resume();
        return;
      }
    } else {
      sendJson(response, 404, { error: "not found" });
      request.resume();
      return;
    }

    try {
      const body = await readJsonBody(request);
      if (body.model !== ALLOWED_MODEL) {
        sendJson(response, 400, { error: "model is not allowed" });
        return;
      }

      forwardToOllama(
        request,
        response,
        {
          ...body,
          model: ALLOWED_MODEL,
          reasoning_effort: "none",
          temperature: 0,
        },
        upstreamPort,
      );
    } catch (error) {
      if (response.destroyed || response.writableEnded) return;
      const statusCode = error instanceof RequestError ? error.statusCode : 500;
      const message =
        error instanceof RequestError ? error.message : "internal proxy error";
      sendJson(
        response,
        statusCode,
        { error: message },
        { close: statusCode === 413 },
      );
    }
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 32;
  server.maxRequestsPerSocket = 100;
  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const server = createProxyServer();
  server.listen(LISTEN_PORT, LISTEN_HOST);
}
