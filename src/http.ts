import { createReadStream, existsSync, statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";

import type { AuthenticatedActor, IdentityProvider } from "./auth.ts";
import { asParimitError, ParimitError } from "./errors.ts";
import type { ParimitService } from "./service.ts";
import { INTENT_STATUSES, type IntentStatus } from "./types.ts";

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

function requireJsonObject(
  value: unknown,
  allowedProperties: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ParimitError("VALIDATION_ERROR", "Request body must be a JSON object", 400);
  }
  const unknownProperties = Object.keys(value).filter(
    (property) => !allowedProperties.includes(property),
  );
  if (unknownProperties.length > 0) {
    throw new ParimitError(
      "VALIDATION_ERROR",
      `Request body contains unknown properties: ${unknownProperties.sort().join(", ")}`,
      400,
    );
  }
  return value as Record<string, unknown>;
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

function decodePathSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new ParimitError("INVALID_PATH", "Malformed proposal identifier", 400);
  }
}

function parseIntentPath(pathname: string): { id: string; action?: string } | null {
  const match = pathname.match(/^\/v1\/intents\/([^/]+)(?:\/(cancel|approvals|audit|audit\/verify))?$/);
  if (!match) return null;
  return { id: decodePathSegment(match[1]!), ...(match[2] ? { action: match[2] } : {}) };
}

export interface HttpHandlerOptions {
  publicDirectory?: string;
  identityProvider?: IdentityProvider;
}

export function createHttpHandler(service: ParimitService, options: HttpHandlerOptions = {}) {
  if (options.identityProvider === undefined) {
    throw new ParimitError(
      "INVALID_AUTH_CONFIGURATION",
      "HTTP handlers require an explicit identity provider bound to the server's trust mode",
      500,
    );
  }
  const expectedAuthenticationMethod =
    service.authenticationMode === "oidc" ? "oidc" : "local_demo_headers";
  if (
    options.identityProvider !== undefined &&
    options.identityProvider.authenticationMethod !== expectedAuthenticationMethod
  ) {
    throw new ParimitError(
      "INVALID_AUTH_CONFIGURATION",
      "HTTP identity provider mode must match the service authentication mode",
      500,
    );
  }
  const identityProvider = options.identityProvider;

  const authenticate = async (request: IncomingMessage): Promise<AuthenticatedActor> => {
    const actor = await identityProvider.authenticate(request.headers);
    if (
      typeof actor.actorId !== "string" ||
      actor.actorId.length === 0 ||
      actor.actorId.length > 128 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$/.test(actor.actorId) ||
      (actor.actorRole !== "agent" &&
        actor.actorRole !== "approver" &&
        actor.actorRole !== "admin") ||
      typeof actor.subject !== "string" ||
      actor.subject.length === 0 ||
      actor.authenticationMethod !== expectedAuthenticationMethod
    ) {
      throw new ParimitError(
        "INVALID_IDENTITY_PROVIDER_RESULT",
        "Identity provider returned an invalid authenticated actor",
        500,
      );
    }
    return actor;
  };

  const requireRole = (
    actor: AuthenticatedActor,
    allowed: readonly AuthenticatedActor["actorRole"][],
  ): void => {
    if (!allowed.includes(actor.actorRole)) {
      throw new ParimitError(
        "FORBIDDEN",
        `This action requires one of these roles: ${allowed.join(", ")}`,
        403,
      );
    }
  };

  const authorizeIntentRead = (actor: AuthenticatedActor, intentId: string): void => {
    if (actor.actorRole === "agent") {
      service.assertIntentOwnedByAgent(intentId, actor.actorId);
    }
  };

  const authenticatedProposal = (
    value: unknown,
    actor: AuthenticatedActor,
  ): Record<string, unknown> => {
    requireRole(actor, ["agent"]);
    const body = requireJsonObject(value, [
      "idempotency_key",
      "requested_by",
      "on_behalf_of",
      "amount",
      "payee_reference",
      "purpose",
      "expires_in_seconds",
    ]);
    const requestedBy = requireJsonObject(body.requested_by, ["type", "id"]);
    if (requestedBy.type !== "agent" || requestedBy.id !== actor.actorId) {
      throw new ParimitError(
        "ACTOR_IDENTITY_MISMATCH",
        "requested_by.id must match the authenticated agent identity",
        403,
      );
    }
    return body;
  };

  const demoWarning = (actor: AuthenticatedActor): Record<string, string> =>
    actor.authenticationMethod === "local_demo_headers" ? { warning: DEMO_AUTH_WARNING } : {};

  return async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    try {
      const method = request.method ?? "GET";
      const url = new URL(request.url ?? "/", "http://localhost");
      const pathname = url.pathname;

      if (method === "OPTIONS") {
        response.writeHead(204, {
          allow: "GET, POST, OPTIONS",
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers":
            "authorization, content-type, x-parimit-actor, x-parimit-role",
        });
        response.end();
        return;
      }

      if (method === "GET" && pathname === "/v1/safety") {
        sendJson(response, 200, { data: service.safetyMetadata() });
        return;
      }

      if (method === "GET" && pathname === "/v1/identity") {
        const actor = await authenticate(request);
        sendJson(response, 200, {
          data: {
            actor_id: actor.actorId,
            actor_role: actor.actorRole,
            authentication_method: actor.authenticationMethod,
            ...(actor.issuer === undefined ? {} : { issuer: actor.issuer }),
          },
          ...demoWarning(actor),
        });
        return;
      }

      if (pathname === "/v1/intents" && method === "POST") {
        const actor = await authenticate(request);
        const intent = service.createIntent(authenticatedProposal(await readJson(request), actor));
        sendJson(response, intent.idempotent_replay ? 200 : 201, { data: intent });
        return;
      }

      if (pathname === "/v1/intents" && method === "GET") {
        const actor = await authenticate(request);
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
        const agentId = url.searchParams.get("agent_id");
        if (agentId !== null && (agentId.length === 0 || agentId.length > 128)) {
          throw new ParimitError(
            "VALIDATION_ERROR",
            "agent_id must be a non-empty string of at most 128 characters",
            400,
          );
        }
        if (actor.actorRole === "agent" && agentId !== null && agentId !== actor.actorId) {
          throw new ParimitError("FORBIDDEN", "Agents may list only their own proposals", 403);
        }
        const intents = service.listIntents({
          ...(actor.actorRole === "agent"
            ? { agentId: actor.actorId }
            : agentId === null
              ? {}
              : { agentId }),
          ...(status ? { status } : {}),
          ...(limit ? { limit } : {}),
        });
        sendJson(response, 200, { data: intents });
        return;
      }

      if (pathname === "/v1/intents/simulate" && method === "POST") {
        const actor = await authenticate(request);
        sendJson(response, 200, {
          data: {
            policy: service.evaluatePolicy(
              authenticatedProposal(await readJson(request), actor),
            ),
            persisted: false,
            moves_money: false,
          },
        });
        return;
      }

      const demoObservation = pathname.match(/^\/v1\/demo\/intents\/([^/]+)\/observations$/);
      if (demoObservation && method === "POST") {
        const actor = await authenticate(request);
        requireRole(actor, ["admin"]);
        const record = requireJsonObject(await readJson(request), ["status", "provider_reference"]);
        const intent = service.recordMockObservation(
          decodePathSegment(demoObservation[1]!),
          record.status,
          record.provider_reference,
          actor.actorId,
        );
        sendJson(response, 200, {
          data: intent,
          warning: "Demo-only observation: no payment was sent and no funds moved.",
        });
        return;
      }

      const intentPath = parseIntentPath(pathname);
      if (intentPath && method === "GET" && intentPath.action === undefined) {
        const actor = await authenticate(request);
        authorizeIntentRead(actor, intentPath.id);
        const intent = service.getIntent(intentPath.id);
        sendJson(response, 200, { data: intent });
        return;
      }
      if (intentPath && method === "POST" && intentPath.action === "cancel") {
        const actor = await authenticate(request);
        const intent = service.cancelIntent(intentPath.id, actor.actorId, actor.actorRole);
        sendJson(response, 200, { data: intent, ...demoWarning(actor) });
        return;
      }
      if (intentPath && method === "POST" && intentPath.action === "approvals") {
        const actor = await authenticate(request);
        requireRole(actor, ["approver", "admin"]);
        const body = requireJsonObject(await readJson(request), ["decision"]);
        const intent = service.approveIntent(
          intentPath.id,
          actor.actorId,
          actor.actorRole,
          body.decision,
        );
        sendJson(response, 200, { data: intent, ...demoWarning(actor) });
        return;
      }
      if (intentPath && method === "GET" && intentPath.action === "audit") {
        const actor = await authenticate(request);
        authorizeIntentRead(actor, intentPath.id);
        sendJson(response, 200, { data: service.getAudit(intentPath.id) });
        return;
      }
      if (intentPath && method === "GET" && intentPath.action === "audit/verify") {
        const actor = await authenticate(request);
        authorizeIntentRead(actor, intentPath.id);
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
