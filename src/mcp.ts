import { createInterface } from "node:readline";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { asParimitError, ParimitError } from "./errors.ts";
import { createServiceFromEnvironment, type ParimitService } from "./service.ts";

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
}

interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

const proposalProperties = {
  idempotency_key: { type: "string", minLength: 1, maxLength: 128 },
  requested_by: {
    type: "object",
    additionalProperties: false,
    required: ["type", "id"],
    properties: {
      type: { type: "string", const: "agent" },
      id: { type: "string", minLength: 1, maxLength: 128 },
    },
  },
  on_behalf_of: { type: "string", minLength: 1, maxLength: 128 },
  amount: {
    type: "object",
    additionalProperties: false,
    required: ["currency", "minor"],
    properties: {
      currency: { type: "string", const: "INR" },
      minor: {
        type: "string",
        pattern: "^[1-9][0-9]*$",
        description: "Positive INR minor units (paise) as a decimal string.",
      },
    },
  },
  payee_reference: {
    type: "string",
    minLength: 6,
    maxLength: 64,
    pattern: "^[A-Za-z][A-Za-z0-9:_-]{5,63}$",
    description: "Opaque internal alias only; never a VPA, phone number, bank account, or card identifier.",
  },
  purpose: { type: "string", minLength: 1, maxLength: 500 },
  expires_in_seconds: { type: "integer", minimum: 1, maximum: 86400 },
};

const proposalSchema = {
  type: "object",
  additionalProperties: false,
  required: ["idempotency_key", "requested_by", "amount", "payee_reference", "purpose"],
  properties: proposalProperties,
};

export const MCP_TOOLS: readonly McpTool[] = [
  {
    name: "create_payment_proposal",
    description:
      "Create a proposal-only INR payment intent. This never sends, executes, reserves, or moves money; human approval is separate and unavailable to agents.",
    inputSchema: proposalSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "get_payment_status",
    description: "Read proposal, human-approval, and mock observation status. It does not query UPI or a bank.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["intent_id"],
      properties: { intent_id: { type: "string", format: "uuid" } },
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "cancel_payment_proposal",
    description: "Cancel the requesting agent's own proposal before approval. No payment cancellation is attempted.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["intent_id", "requested_by"],
      properties: {
        intent_id: { type: "string", format: "uuid" },
        requested_by: proposalProperties.requested_by,
      },
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "get_policy_decision",
    description: "Evaluate a proposal against limits and allow/block lists without persisting it or moving money.",
    inputSchema: proposalSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "simulate_payment",
    description:
      "Attach a DEMO_MOCK observation to a fully human-authorized proposal. After IN_DOUBT, every later mock observation is rejected because this alpha has no reconciliation mechanism. This local simulator has no payment rail and never moves funds.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["intent_id", "status"],
      properties: {
        intent_id: { type: "string", format: "uuid" },
        status: {
          type: "string",
          enum: ["UNKNOWN", "PENDING", "SUCCEEDED", "FAILED", "REVERSED", "DISPUTED", "IN_DOUBT"],
        },
        provider_reference: { type: "string", minLength: 1, maxLength: 200 },
      },
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "get_payment_audit",
    description: "Read hash-chained audit evidence and its integrity report for one proposal.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["intent_id"],
      properties: { intent_id: { type: "string", format: "uuid" } },
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
] as const;

function argumentRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ParimitError("VALIDATION_ERROR", "Tool arguments must be a JSON object", 400);
  }
  return value as Record<string, unknown>;
}

function requiredString(record: Record<string, unknown>, key: string): string {
  if (typeof record[key] !== "string" || record[key] === "") {
    throw new ParimitError("VALIDATION_ERROR", `${key} must be a non-empty string`, 400);
  }
  return record[key] as string;
}

export function callMcpTool(service: ParimitService, name: string, value: unknown): unknown {
  if (service.authenticationMode === "oidc") {
    throw new ParimitError(
      "MCP_IDENTITY_UNSUPPORTED",
      "The local MCP transport has no verified OIDC actor binding and is disabled in OIDC mode",
      403,
    );
  }
  const args = argumentRecord(value);
  switch (name) {
    case "create_payment_proposal":
      return service.createIntent(args);
    case "get_payment_status":
      return service.getIntent(requiredString(args, "intent_id"));
    case "cancel_payment_proposal": {
      const requestedBy = argumentRecord(args.requested_by);
      if (requestedBy.type !== "agent") {
        throw new ParimitError("VALIDATION_ERROR", "requested_by.type must be 'agent'", 400);
      }
      return service.cancelIntent(
        requiredString(args, "intent_id"),
        requiredString(requestedBy, "id"),
        "agent",
      );
    }
    case "get_policy_decision":
      return { policy: service.evaluatePolicy(args), persisted: false, moves_money: false };
    case "simulate_payment":
      return service.recordMockObservation(
        requiredString(args, "intent_id"),
        args.status,
        args.provider_reference,
        "mcp-demo-mock-rail",
      );
    case "get_payment_audit": {
      const id = requiredString(args, "intent_id");
      return { events: service.getAudit(id), integrity: service.verifyIntegrity(id) };
    }
    default:
      throw new ParimitError("METHOD_NOT_FOUND", `Unknown tool: ${name}`, 404);
  }
}

function toolResult(value: unknown): Record<string, unknown> {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: { data: value },
    isError: false,
  };
}

function toolError(error: unknown): Record<string, unknown> {
  const known = asParimitError(error);
  const value = {
    error: {
      code: known.code,
      message: known.message,
      ...(known.details === undefined ? {} : { details: known.details }),
    },
  };
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value,
    isError: true,
  };
}

export async function handleMcpRequest(
  service: ParimitService,
  request: JsonRpcRequest,
): Promise<Record<string, unknown> | null> {
  if (request.method?.startsWith("notifications/")) return null;
  const id = request.id ?? null;
  if (request.jsonrpc !== "2.0" || typeof request.method !== "string") {
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid JSON-RPC request" } };
  }
  if (request.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "parimit", version: "0.1.0-alpha.3" },
        instructions:
          "Proposal-only safety server. It cannot approve proposals, reach payment rails, or move money.",
      },
    };
  }
  if (request.method === "ping") return { jsonrpc: "2.0", id, result: {} };
  if (request.method === "tools/list") {
    return { jsonrpc: "2.0", id, result: { tools: MCP_TOOLS } };
  }
  if (request.method === "tools/call") {
    const params = argumentRecord(request.params);
    const name = requiredString(params, "name");
    try {
      return {
        jsonrpc: "2.0",
        id,
        result: toolResult(callMcpTool(service, name, params.arguments ?? {})),
      };
    } catch (error) {
      return { jsonrpc: "2.0", id, result: toolError(error) };
    }
  }
  return { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } };
}

export function startMcpServer(environment: Record<string, string | undefined> = process.env): ParimitService {
  if (environment.PARIMIT_AUTH_MODE === "oidc") {
    throw new ParimitError(
      "MCP_IDENTITY_UNSUPPORTED",
      "The local MCP transport has no verified OIDC actor binding and is disabled in OIDC mode",
      500,
    );
  }
  const service = createServiceFromEnvironment(environment);
  const lines = createInterface({ input: process.stdin, terminal: false, crlfDelay: Infinity });
  lines.on("line", async (line) => {
    if (line.trim() === "") return;
    let request: JsonRpcRequest;
    try {
      request = JSON.parse(line) as JsonRpcRequest;
    } catch {
      process.stdout.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } })}\n`,
      );
      return;
    }
    const response = await handleMcpRequest(service, request);
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  });
  lines.on("close", () => service.close());
  return service;
}

const entrypoint = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === entrypoint) startMcpServer();
