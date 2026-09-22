#!/usr/bin/env node

/**
 * A deliberately small, dependency-free safety lint.
 *
 * It guards two architectural tripwires:
 *   1. agent/MCP tool declarations must not expose authority-bearing verbs;
 *   2. deterministic core modules must not import or invoke network clients.
 *
 * This supplements review and tests. It is not a formal capability analysis.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { basename, extname, relative, sep } from "node:path";

const repositoryRoot = new URL("../", import.meta.url);
const sourceRoot = new URL("../src/", import.meta.url);
const integrationRoot = new URL("../integrations/", import.meta.url);

const forbiddenToolTokens = new Set([
  "approve",
  "authorise",
  "authorize",
  "debit",
  "dispatch",
  "execute",
  "initiate",
  "pay",
  "retry",
  "send",
  "transfer",
]);

const forbiddenNetworkModules = new Set([
  "http",
  "https",
  "http2",
  "net",
  "tls",
  "dgram",
  "dns",
  "undici",
  "node-fetch",
  "axios",
  "got",
  "superagent",
  "ky",
  "ws",
]);

// These files form the HTTP/identity edge. Everything else in src/ must remain
// network-free, including domain/storage contracts and the MCP process. auth.ts
// may fetch the operator-configured OIDC JWKS; it never receives proposal URLs.
const localHttpEdgeBasenames = new Set(["auth.ts", "http.ts", "server.ts"]);

// `chat.send` is AiNxt's mandatory capability for its chat transport, not a
// Parimit action or payment-dispatch tool. Keep the exception exact and scoped
// to the reviewed edge adapter so the authority-token rule stays fail-closed.
const reviewedExternalCapabilities = new Map([
  ["integrations/ainxt/adapter.ts", new Set(["chat.send"])],
]);

async function walk(directory: URL): Promise<URL[]> {
  const files: URL[] = [];

  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const child = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directory);
    if (entry.isDirectory()) files.push(...(await walk(child)));
    else if (entry.isFile() && [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"].includes(extname(entry.name))) {
      files.push(child);
    }
  }

  return files;
}

function repoPath(file: URL): string {
  const rootPath = decodeURIComponent(repositoryRoot.pathname);
  const filePath = decodeURIComponent(file.pathname);
  return relative(rootPath, filePath).split(sep).join("/");
}

function withoutComments(source: string): string {
  // Keep quoted strings because tool names and import specifiers live there.
  // Removing comments avoids findings caused by boundary documentation.
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:\\])\/\/.*$/gm, "$1");
}

function isAgentSurface(path: string): boolean {
  if (path.toLowerCase().startsWith("integrations/ainxt/")) return true;
  const file = basename(path).toLowerCase();
  return /(^|[._-])(mcp|agent|tools?)([._-]|$)/.test(file) ||
    path.toLowerCase().split("/").some((part) => ["mcp", "agent", "agents", "tool", "tools"].includes(part));
}

function mustRemainNetworkFree(path: string): boolean {
  const normalized = path.toLowerCase();
  return normalized.startsWith("src/") && !localHttpEdgeBasenames.has(basename(normalized));
}

function toolNames(source: string): Set<string> {
  const names = new Set<string>();
  const patterns = [
    /\bname\s*:\s*["'`]([a-z][a-z0-9_.:-]*)["'`]/gi,
    /\b(?:registerTool|register_tool|tool)\s*\(\s*["'`]([a-z][a-z0-9_.:-]*)["'`]/gi,
    /["'`]([a-z][a-z0-9]*(?:[_.:-][a-z0-9]+)+)["'`]/g,
    /["'`](approve|authorise|authorize|debit|dispatch|execute|initiate|pay|retry|send|transfer)["'`]/g,
  ];

  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) names.add(match[1]);
  }
  return names;
}

function forbiddenToolToken(name: string): string | undefined {
  const tokens = name.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return tokens.find((token) => forbiddenToolTokens.has(token));
}

function importedModules(source: string): Set<string> {
  const modules = new Set<string>();
  const patterns = [
    /\b(?:import|export)\s+(?:type\s+)?[^;]*?\s+from\s+["'`]([^"'`]+)["'`]/g,
    /\bimport\s*["'`]([^"'`]+)["'`]/g,
    /\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g,
    /\brequire\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g,
  ];

  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) modules.add(match[1]);
  }
  return modules;
}

function networkModule(specifier: string): string | undefined {
  const normalized = specifier.replace(/^node:/, "").split("/")[0];
  return forbiddenNetworkModules.has(normalized) ? specifier : undefined;
}

const violations: string[] = [];

let files: URL[];
try {
  await stat(sourceRoot);
  files = await walk(sourceRoot);
  try {
    await stat(integrationRoot);
    files.push(...(await walk(integrationRoot)));
  } catch {
    // Integrations are optional, but every present integration is scanned.
  }
} catch {
  console.error("Boundary check failed: src/ was not found.");
  process.exit(1);
}

for (const file of files) {
  const path = repoPath(file);
  const source = withoutComments(await readFile(file, "utf8"));

  if (isAgentSurface(path)) {
    for (const name of toolNames(source)) {
      if (reviewedExternalCapabilities.get(path)?.has(name)) continue;
      const token = forbiddenToolToken(name);
      if (token) {
        violations.push(`${path}: agent/MCP tool '${name}' contains forbidden authority token '${token}'`);
      }
    }
  }

  if (mustRemainNetworkFree(path)) {
    for (const specifier of importedModules(source)) {
      const forbidden = networkModule(specifier);
      if (forbidden) {
        violations.push(`${path}: network-free runtime imports network module '${forbidden}'`);
      }
    }

    const runtimeClients = [
      [/(^|[^.\w])fetch\s*\(/m, "fetch"],
      [/\bnew\s+WebSocket\s*\(/m, "WebSocket"],
      [/\bnew\s+EventSource\s*\(/m, "EventSource"],
    ] as const;
    for (const [pattern, name] of runtimeClients) {
      if (pattern.test(source)) {
        violations.push(`${path}: network-free runtime invokes network client '${name}'`);
      }
    }
  }
}

if (violations.length > 0) {
  console.error("Safety-boundary violations detected:\n");
  for (const violation of violations) console.error(`  - ${violation}`);
  console.error("\nSee docs/safety-boundary.md. Do not suppress a finding without security review.");
  process.exit(1);
}

console.log(`Boundary check passed (${files.length} source and integration files scanned).`);
