import { createReadStream, existsSync, statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";

import { asParimitError, ParimitError } from "./errors.ts";
import type { ParimitService } from "./service.ts";
import { INTENT_STATUSES, type ActorRole, type IntentStatus } from "./types.ts";

const JSON_LIMIT_BYTES = 1_048_576;
export const DEMO_AUTH_WARNING =
  "Demo identity headers are spoofable. Replace x-parimit-actor/x-parimit-role with verified OIDC/WebAuthn identities before real deployment.";

const MIME_TYPES: Readonly<Record<string, string>> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
};

function sendJson(response: ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += data.length;
    if (length > JSON_LIMIT_BYTES) {
      throw new ParimitError("BODY_TOO_LARGE", "JSON request body exceeds 1 MiB", 413);
    }
    chunks.push(data);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new ParimitError("INVALID_JSON", "Request body must contain valid JSON", 400);
  }
}

function requireDemoActor(request: IncomingMessage): { actorId: string; actorRole: ActorRole } {
  const actor = request.headers["x-parimit-actor"];
  const role = request.headers["x-parimit-role"];
  if (typeof actor !== "string" || typeof role !== "string") {
    throw new ParimitError(
      "DEMO_AUTH_REQUIRED",
      "x-parimit-actor and x-parimit-role headers are required for this demo action",
      401,
    );
  }
  return { actorId: actor, actorRole: role.toLocaleLowerCase("en-US") as ActorRole };
}

function serveStatic(publicDirectory: string, pathname: string, response: ServerResponse): boolean {
  const root = resolve(publicDirectory);
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    throw new ParimitError("INVALID_PATH", "Malformed URL path", 400);
  }
  const requested = decoded === "/" ? "index.html" : decoded.replace(/^\/+/, "");
  const normalized = normalize(requested);
  const candidate = resolve(join(root, normalized));
  if (candidate !== root && !candidate.startsWith(`${root}${sep}`)) return false;
  if (!existsSync(candidate) || !statSync(candidate).isFile()) return false;
  const stat = statSync(candidate);
  response.writeHead(200, {
    "content-type": MIME_TYPES[extname(candidate).toLocaleLowerCase("en-US")] ?? "application/octet-stream",
    "content-length": stat.size,
    "x-content-type-options": "nosniff",
    "content-security-policy":
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
  });
  createReadStream(candidate).pipe(response);
  return true;
}

function parseIntentPath(pathname: string): { id: string; action?: string } | null {
  const match = pathname.match(/^\/v1\/intents\/([^/]+)(?:\/(cancel|approvals|audit|audit\/verify))?$/);
  if (!match) return null;
  try {
    return { id: decodeURIComponent(match[1]!), ...(match[2] ? { action: match[2] } : {}) };
  } catch {
    throw new ParimitError("INVALID_PATH", "Malformed proposal identifier", 400);
  }
}

export interface HttpHandlerOptions {
  publicDirectory?: string;
}

export function createHttpHandler(service: ParimitService, options: HttpHandlerOptions = {}) {
  return async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    try {
      const method = request.method ?? "GET";
      const url = new URL(request.url ?? "/", "http://localhost");
      const pathname = url.pathname;

      if (method === "OPTIONS") {
        response.writeHead(204, {
          allow: "GET, POST, OPTIONS",
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "content-type, x-parimit-actor, x-parimit-role",
        });
        response.end();
        return;
      }

      if (method === "GET" && pathname === "/v1/safety") {
        sendJson(response, 200, { data: service.safetyMetadata() });
        return;
      }

      if (pathname === "/v1/intents" && method === "POST") {
        const intent = service.createIntent(await readJson(request));
        sendJson(response, intent.idempotent_replay ? 200 : 201, { data: intent });
        return;
      }

      if (pathname === "/v1/intents" && method === "GET") {
        const rawStatus = url.searchParams.get("status");
        let status: IntentStatus | undefined;
        if (rawStatus !== null) {
          if (!INTENT_STATUSES.includes(rawStatus as IntentStatus)) {
            throw new ParimitError("VALIDATION_ERROR", "Unknown intent status filter", 400);
          }
          status = rawStatus as IntentStatus;
        }
        const limitValue = url.searchParams.get("limit");
        const limit = limitValue === null ? undefined : Number(limitValue);
        if (limit !== undefined && (!Number.isInteger(limit) || limit <= 0 || limit > 200)) {
          throw new ParimitError("VALIDATION_ERROR", "limit must be an integer from 1 to 200", 400);
        }
        const intents = service.listIntents({
          ...(url.searchParams.get("agent_id")
            ? { agentId: url.searchParams.get("agent_id") as string }
            : {}),
          ...(status ? { status } : {}),
          ...(limit ? { limit } : {}),
        });
        sendJson(response, 200, { data: intents });
        return;
      }

      if (pathname === "/v1/intents/simulate" && method === "POST") {
        sendJson(response, 200, {
          data: {
            policy: service.evaluatePolicy(await readJson(request)),
            persisted: false,
            moves_money: false,
          },
        });
        return;
      }

      const demoObservation = pathname.match(/^\/v1\/demo\/intents\/([^/]+)\/observations$/);
      if (demoObservation && method === "POST") {
        const body = await readJson(request);
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
          throw new ParimitError("VALIDATION_ERROR", "Request body must be a JSON object", 400);
        }
        const record = body as Record<string, unknown>;
        const intent = service.recordMockObservation(
          decodeURIComponent(demoObservation[1]!),
          record.status,
          record.provider_reference,
        );
        sendJson(response, 200, {
          data: intent,
          warning: "Demo-only observation: no payment was sent and no funds moved.",
        });
        return;
      }

      const intentPath = parseIntentPath(pathname);
      if (intentPath && method === "GET" && intentPath.action === undefined) {
        sendJson(response, 200, { data: service.getIntent(intentPath.id) });
        return;
      }
      if (intentPath && method === "POST" && intentPath.action === "cancel") {
        const actor = requireDemoActor(request);
        const intent = service.cancelIntent(intentPath.id, actor.actorId, actor.actorRole);
        sendJson(response, 200, { data: intent, warning: DEMO_AUTH_WARNING });
        return;
      }
      if (intentPath && method === "POST" && intentPath.action === "approvals") {
        const actor = requireDemoActor(request);
        const body = await readJson(request);
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
          throw new ParimitError("VALIDATION_ERROR", "Request body must be a JSON object", 400);
        }
        const intent = service.approveIntent(
          intentPath.id,
          actor.actorId,
          actor.actorRole,
          (body as Record<string, unknown>).decision,
        );
        sendJson(response, 200, { data: intent, warning: DEMO_AUTH_WARNING });
        return;
      }
      if (intentPath && method === "GET" && intentPath.action === "audit") {
        sendJson(response, 200, { data: service.getAudit(intentPath.id) });
        return;
      }
      if (intentPath && method === "GET" && intentPath.action === "audit/verify") {
        sendJson(response, 200, { data: service.verifyIntegrity(intentPath.id) });
        return;
      }

      if (method === "GET" && options.publicDirectory && serveStatic(options.publicDirectory, pathname, response)) {
        return;
      }
      sendJson(response, 404, {
        error: { code: "NOT_FOUND", message: "Route not found. This service has no payment execution routes." },
      });
    } catch (error) {
      const parimitError = asParimitError(error);
      sendJson(response, parimitError.statusCode, {
        error: {
          code: parimitError.code,
          message: parimitError.message,
          ...(parimitError.details === undefined ? {} : { details: parimitError.details }),
        },
      });
    }
  };
}
