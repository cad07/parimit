#!/usr/bin/env node

import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import * as http from "node:http";
import * as https from "node:https";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonObject = { [key: string]: JsonValue };

interface Options {
  workloadSmoke: boolean;
  composeFile: string;
  environmentFile: string;
  reportFile: string;
}

interface HttpResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: JsonValue | undefined;
}

interface AccessIdentity {
  actorId: string;
  role: "agent" | "approver" | "consumer" | "admin";
}

interface CheckRecord {
  name: string;
  status: "PASS" | "FAIL";
  detail?: JsonValue;
}

interface HumanReviewSnapshot {
  id: string;
  currency: string;
  amountMinor: string;
  payeeReference: string;
  purpose: string;
  policyAllowed: boolean;
  policyReasons: string[];
  policyRulesVersion: string;
  policyConfigDigest: string;
  requiredApprovals: number;
  expiresAt: string;
  intentHash: string;
}

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..");
const deploymentDirectory = join(repositoryRoot, "deploy", "keycloak");
const runtimeDirectory = join(deploymentDirectory, "runtime");
const reportsDirectory = join(runtimeDirectory, "reports");
const defaultEnvironmentFile = join(deploymentDirectory, ".env.local");
const defaultComposeFile = join(deploymentDirectory, "docker-compose.yml");
const defaultReportFile = join(reportsDirectory, "keycloak-pilot-report.json");
const caCertificateFile = join(runtimeDirectory, "tls", "local-ca.pem");
const humanLoginFile = join(runtimeDirectory, "human-logins.txt");

const keycloakBaseUrl = "https://localhost:8443";
const issuer = `${keycloakBaseUrl}/realms/parimit-pilot`;
const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
const tokenUrl = `${issuer}/protocol/openid-connect/token`;
const deviceAuthorizationUrl = `${issuer}/protocol/openid-connect/auth/device`;
const expectedAudience = "parimit-pilot";
const requestedScope = "openid parimit-api-access";
const humanClientId = "parimit-human-cli";
const parimitBaseUrl = "http://127.0.0.1:8787";

const recognizedRoles = new Map<string, AccessIdentity["role"]>([
  ["parimit-pilot-agent", "agent"],
  ["parimit-pilot-reviewer", "approver"],
  ["parimit-pilot-consumer", "consumer"],
  ["parimit-pilot-admin", "admin"],
]);

class PilotFailure extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PilotFailure";
    this.code = code;
  }
}

function usage(): string {
  return `Usage: node --experimental-strip-types scripts/run-keycloak-pilot.ts [options]

Default: start the local stack, require two interactive human device logins, and
run the complete fictional acceptance flow.

  --workload-smoke       Non-interactive agent/consumer authentication smoke only.
                         It never approves and is not human E2E acceptance.
  --report PATH          Override the redacted JSON report path.
  --help                 Show this help text.
`;
}

function requireArgument(arguments_: readonly string[], index: number, option: string): string {
  const value = arguments_[index + 1];
  if (!value || value.startsWith("--")) throw new PilotFailure("INVALID_ARGUMENT", `${option} requires a path`);
  return value;
}

function parseArguments(arguments_: readonly string[]): Options {
  const options: Options = {
    workloadSmoke: false,
    composeFile: defaultComposeFile,
    environmentFile: defaultEnvironmentFile,
    reportFile: defaultReportFile,
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index]!;
    if (argument === "--workload-smoke") {
      options.workloadSmoke = true;
    } else if (argument === "--report") {
      options.reportFile = resolve(repositoryRoot, requireArgument(arguments_, index, argument));
      index += 1;
    } else if (argument === "--help" || argument === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    } else {
      throw new PilotFailure("INVALID_ARGUMENT", `Unknown argument: ${argument}`);
    }
  }
  assertManagedReportPath(options.reportFile);
  return options;
}

function assertManagedReportPath(path: string): void {
  const reportRelativePath = relative(reportsDirectory, path);
  if (
    dirname(path) !== reportsDirectory ||
    reportRelativePath.length === 0 ||
    reportRelativePath === ".." ||
    reportRelativePath.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(reportRelativePath)
  ) {
    throw new PilotFailure(
      "UNSAFE_REPORT_PATH",
      "The redacted report must be a direct child of deploy/keycloak/runtime/reports",
    );
  }
}

async function readEnvironment(path: string): Promise<Map<string, string>> {
  const contents = await readFile(path, "utf8");
  const values = new Map<string, string>();
  for (const [index, rawLine] of contents.split(/\r?\n/u).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = rawLine.indexOf("=");
    if (separator < 1) {
      throw new PilotFailure("INVALID_ENVIRONMENT", `Invalid environment line ${index + 1}`);
    }
    const name = rawLine.slice(0, separator).trim();
    let value = rawLine.slice(separator + 1).trim();
    if (!/^[A-Z][A-Z0-9_]*$/u.test(name)) {
      throw new PilotFailure("INVALID_ENVIRONMENT", `Invalid environment name on line ${index + 1}`);
    }
    if (values.has(name)) {
      throw new PilotFailure("INVALID_ENVIRONMENT", `Duplicate environment name ${name}`);
    }
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    values.set(name, value);
  }
  return values;
}

function requiredEnvironment(values: ReadonlyMap<string, string>, name: string): string {
  const value = values.get(name);
  if (!value) throw new PilotFailure("MISSING_ENVIRONMENT", `Required environment value ${name} is missing`);
  return value;
}

function form(values: Readonly<Record<string, string>>): Buffer {
  return Buffer.from(new URLSearchParams(values).toString(), "utf8");
}

async function request(
  urlText: string,
  options: {
    method?: string;
    headers?: Readonly<Record<string, string>>;
    body?: Buffer | string;
    ca?: Buffer;
    timeoutMilliseconds?: number;
  } = {},
): Promise<HttpResult> {
  const url = new URL(urlText);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new PilotFailure("INVALID_URL", "Only HTTP(S) URLs are supported");
  }
  const body = options.body === undefined ? undefined : Buffer.from(options.body);
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (body && headers["content-length"] === undefined) headers["content-length"] = String(body.length);
  const transport = url.protocol === "https:" ? https : http;

  return await new Promise<HttpResult>((resolvePromise, rejectPromise) => {
    const outgoing = transport.request(
      url,
      {
        method: options.method ?? "GET",
        headers,
        timeout: options.timeoutMilliseconds ?? 10_000,
        ...(url.protocol === "https:"
          ? { ca: options.ca, rejectUnauthorized: true, minVersion: "TLSv1.2" as const }
          : {}),
      },
      (incoming) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let responseFailed = false;
        incoming.once("error", rejectPromise);
        incoming.on("data", (chunk: Buffer) => {
          if (responseFailed) return;
          size += chunk.length;
          if (size > 2 * 1024 * 1024) {
            responseFailed = true;
            rejectPromise(new PilotFailure("RESPONSE_TOO_LARGE", "HTTP response exceeded 2 MiB"));
            incoming.destroy();
            return;
          }
          chunks.push(chunk);
        });
        incoming.on("end", () => {
          if (responseFailed) return;
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: JsonValue | undefined;
          if (text.length > 0) {
            try {
              parsed = JSON.parse(text) as JsonValue;
            } catch {
              rejectPromise(
                new PilotFailure(
                  "NON_JSON_RESPONSE",
                  `Received non-JSON response from ${url.pathname} (HTTP ${incoming.statusCode ?? 0})`,
                ),
              );
              return;
            }
          }
          resolvePromise({ status: incoming.statusCode ?? 0, headers: incoming.headers, body: parsed });
        });
      },
    );
    outgoing.on("timeout", () => outgoing.destroy(new PilotFailure("HTTP_TIMEOUT", `Timed out calling ${url.pathname}`)));
    outgoing.on("error", rejectPromise);
    if (body) outgoing.write(body);
    outgoing.end();
  });
}

function object(value: JsonValue | undefined, context: string): JsonObject {
  if (value === undefined || value === null || Array.isArray(value) || typeof value !== "object") {
    throw new PilotFailure("INVALID_RESPONSE", `${context} did not return a JSON object`);
  }
  return value;
}

function array(value: JsonValue | undefined, context: string): JsonValue[] {
  if (!Array.isArray(value)) throw new PilotFailure("INVALID_RESPONSE", `${context} did not return an array`);
  return value;
}

function dataObject(result: HttpResult, context: string): JsonObject {
  return object(object(result.body, context).data, `${context}.data`);
}

function errorCode(result: HttpResult): string | undefined {
  try {
    const body = object(result.body, "error response");
    return String(object(body.error, "error response.error").code ?? "");
  } catch {
    return undefined;
  }
}

function expectStatus(result: HttpResult, expected: number | readonly number[], context: string): void {
  const accepted = Array.isArray(expected) ? expected : [expected];
  if (!accepted.includes(result.status)) {
    const code = errorCode(result);
    throw new PilotFailure(
      "UNEXPECTED_HTTP_STATUS",
      `${context} returned HTTP ${result.status}${code ? ` (${code})` : ""}; expected ${accepted.join(" or ")}`,
    );
  }
}

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new PilotFailure("ASSERTION_FAILED", message);
}

function authorizationHeaders(accessToken: string, json = false): Record<string, string> {
  return {
    authorization: `Bearer ${accessToken}`,
    ...(json ? { "content-type": "application/json" } : {}),
  };
}

function decodeJwtPart(part: string, context: string): JsonObject {
  try {
    return object(JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as JsonValue, context);
  } catch {
    throw new PilotFailure("INVALID_ACCESS_TOKEN", `Access token has an invalid ${context}`);
  }
}

function mappedTokenRoles(claims: JsonObject): AccessIdentity["role"][] {
  if (!Array.isArray(claims.roles)) return [];
  return claims.roles
    .filter((role): role is string => typeof role === "string")
    .map((role) => recognizedRoles.get(role))
    .filter((role): role is AccessIdentity["role"] => role !== undefined);
}

function verifyAccessToken(
  accessToken: string,
  jwks: JsonObject,
  expectedRole: AccessIdentity["role"],
  requiredType: string | undefined,
  expectedAuthorizedParty: string,
  expectedUsername?: string,
): { subjectFingerprint: string; keyId: string; expiresAt: string } {
  const parts = accessToken.split(".");
  if (parts.length !== 3) throw new PilotFailure("INVALID_ACCESS_TOKEN", "Access token is not a compact JWT");
  const [encodedHeader, encodedClaims, encodedSignature] = parts as [string, string, string];
  const header = decodeJwtPart(encodedHeader, "JOSE header");
  const claims = decodeJwtPart(encodedClaims, "claim set");
  expect(header.alg === "RS256", "Keycloak access token must use RS256");
  expect(typeof header.kid === "string" && header.kid.length > 0, "Access token must carry a key id");
  if (requiredType) expect(header.typ === requiredType, `Access token typ must be ${requiredType}`);

  const keys = array(jwks.keys, "JWKS keys").filter(
    (entry): entry is JsonObject =>
      entry !== null && !Array.isArray(entry) && typeof entry === "object" && entry.kid === header.kid,
  );
  expect(keys.length === 1, "JWKS must contain exactly one matching access-token key");
  const key = keys[0]!;
  expect(key.kty === "RSA", "Matching Keycloak signing key must be RSA");
  const verified = verifySignature(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedClaims}`, "ascii"),
    createPublicKey({ key: key as JsonWebKey, format: "jwk" }),
    Buffer.from(encodedSignature, "base64url"),
  );
  expect(verified, "Keycloak access-token signature is invalid");

  expect(claims.iss === issuer, "Access-token issuer mismatch");
  expect(claims.azp === expectedAuthorizedParty, "Access-token authorized party mismatch");
  if (expectedUsername !== undefined) {
    expect(claims.preferred_username === expectedUsername, "Access-token username mismatch");
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  expect(audiences.includes(expectedAudience), "Access token is missing the Parimit API audience");
  expect(typeof claims.sub === "string" && claims.sub.length > 0, "Access token subject is missing");
  expect(typeof claims.iat === "number" && Number.isInteger(claims.iat), "Access token iat is missing");
  expect(typeof claims.exp === "number" && Number.isInteger(claims.exp), "Access token exp is missing");
  const now = Math.floor(Date.now() / 1_000);
  expect((claims.exp as number) > now, "Access token is expired");
  expect((claims.iat as number) <= now + 60, "Access token was issued in the future");
  expect((claims.exp as number) - (claims.iat as number) <= 3_600, "Access-token lifetime exceeds one hour");
  const roles = mappedTokenRoles(claims);
  expect(roles.length === 1 && roles[0] === expectedRole, `Access token must map only to ${expectedRole}`);

  return {
    subjectFingerprint: createHash("sha256").update(String(claims.sub)).digest("hex").slice(0, 16),
    keyId: String(header.kid),
    expiresAt: new Date((claims.exp as number) * 1_000).toISOString(),
  };
}

function composeArguments(options: Options, command: readonly string[]): string[] {
  return [
    "compose",
    "--project-name",
    "parimit-keycloak-pilot",
    "--env-file",
    options.environmentFile,
    "-f",
    options.composeFile,
    ...command,
  ];
}

function runCompose(options: Options, command: readonly string[]): void {
  const result = spawnSync("docker", composeArguments(options, command), {
    cwd: repositoryRoot,
    stdio: "inherit",
  });
  if (result.error) throw new PilotFailure("DOCKER_UNAVAILABLE", `Docker is unavailable: ${result.error.message}`);
  if (result.status !== 0) throw new PilotFailure("COMPOSE_FAILED", `Docker Compose command failed with status ${result.status}`);
}

function captureDocker(arguments_: readonly string[], failureCode: string): string {
  const result = spawnSync("docker", arguments_, {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw new PilotFailure("DOCKER_UNAVAILABLE", `Docker is unavailable: ${result.error.message}`);
  if (result.status !== 0) {
    throw new PilotFailure(failureCode, `Docker command failed with status ${result.status}`);
  }
  return String(result.stdout).trim();
}

function dockerServerVersion(): string {
  const version = captureDocker(["version", "--format", "{{.Server.Version}}"], "DOCKER_VERSION_FAILED");
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)(?:[.+-]|$)/u);
  if (!match) throw new PilotFailure("DOCKER_VERSION_INVALID", "Docker returned an unrecognized server version");
  const observed = [Number(match[1]), Number(match[2]), Number(match[3])] as const;
  const isSecure =
    observed[0] > 28 ||
    (observed[0] === 28 &&
      (observed[1] > 3 || (observed[1] === 3 && observed[2] >= 3)));
  if (!isSecure) {
    throw new PilotFailure(
      "DOCKER_VERSION_UNSAFE",
      "Docker Engine 28.3.3 or newer is required for secure loopback-only port publishing",
    );
  }
  return version;
}

function composeConfigurationDigest(options: Options): string {
  const configuration = captureDocker(
    composeArguments(options, ["config", "--format", "json"]),
    "COMPOSE_CONFIG_FAILED",
  );
  return createHash("sha256").update(configuration, "utf8").digest("hex");
}

function publishedPortBindings(options: Options, service: string): string[] {
  const containerIds = captureDocker(
    composeArguments(options, ["ps", "--quiet", service]),
    "COMPOSE_CONTAINER_LOOKUP_FAILED",
  )
    .split(/\r?\n/u)
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  if (containerIds.length !== 1 || !/^[a-f0-9]{12,64}$/iu.test(containerIds[0]!)) {
    throw new PilotFailure(
      "COMPOSE_CONTAINER_LOOKUP_FAILED",
      `Expected exactly one running ${service} container`,
    );
  }

  const rawPorts = captureDocker(
    ["inspect", "--format", "{{json .NetworkSettings.Ports}}", containerIds[0]!],
    "DOCKER_INSPECT_FAILED",
  );
  let parsed: JsonValue;
  try {
    parsed = JSON.parse(rawPorts) as JsonValue;
  } catch {
    throw new PilotFailure("DOCKER_INSPECT_INVALID", `Docker returned invalid port data for ${service}`);
  }

  const ports = object(parsed, `${service} effective port bindings`);
  const published: string[] = [];
  for (const [containerPort, value] of Object.entries(ports)) {
    if (value === null) continue;
    const bindings = array(value, `${service} bindings for ${containerPort}`);
    for (const [index, candidate] of bindings.entries()) {
      const binding = object(candidate, `${service} binding ${containerPort}[${index}]`);
      expect(typeof binding.HostIp === "string", `${service} binding HostIp is missing`);
      expect(typeof binding.HostPort === "string", `${service} binding HostPort is missing`);
      published.push(`${containerPort}->${binding.HostIp}:${binding.HostPort}`);
    }
  }
  return published.sort();
}

function runningPilotServices(): string[] {
  return captureDocker(
    [
      "ps",
      "--filter",
      "label=com.docker.compose.project=parimit-keycloak-pilot",
      "--filter",
      "status=running",
      "--format",
      "{{.Label \"com.docker.compose.service\"}}",
    ],
    "COMPOSE_SERVICE_INSPECTION_FAILED",
  )
    .split(/\r?\n/u)
    .map((service) => service.trim())
    .filter((service) => service.length > 0)
    .sort();
}

async function sleep(milliseconds: number): Promise<void> {
  await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function describeError(error: unknown, fallback: string): string {
  if (error instanceof AggregateError) {
    const nested = error.errors
      .map((candidate: unknown) => describeError(candidate, ""))
      .filter((message: string) => message.length > 0);
    if (nested.length > 0) return nested.join("; ");
  }
  if (error instanceof Error) {
    const message = error.message.trim();
    if (message.length > 0) return message;
    if (error.name.trim().length > 0) return error.name;
  }
  return fallback;
}

async function waitForJson(
  name: string,
  url: string,
  ca: Buffer | undefined,
  attempts = 60,
): Promise<HttpResult> {
  let lastFailure = "not ready";
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const result = await request(url, { ca, timeoutMilliseconds: 3_000 });
      if (result.status >= 200 && result.status < 300) return result;
      lastFailure = `HTTP ${result.status}`;
    } catch (error) {
      lastFailure = describeError(error, "connection failed");
    }
    if (attempt < attempts) await sleep(2_000);
  }
  throw new PilotFailure("SERVICE_NOT_READY", `${name} did not become ready: ${lastFailure}`);
}

async function clientCredentialsToken(
  clientId: string,
  clientSecret: string,
  ca: Buffer,
): Promise<string> {
  const credentials = Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64");
  const body = form({ grant_type: "client_credentials", scope: requestedScope });
  const result = await request(tokenUrl, {
    method: "POST",
    ca,
    headers: {
      authorization: `Basic ${credentials}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  expectStatus(result, 200, `${clientId} client-credentials token request`);
  const response = object(result.body, "token response");
  expect(typeof response.access_token === "string" && response.access_token.length > 0, "Token response omitted access_token");
  return response.access_token;
}

async function deviceAuthorizationToken(
  label: "reviewer" | "admin",
  expectedUsername: string,
  ca: Buffer,
): Promise<string> {
  const deviceResponse = await request(deviceAuthorizationUrl, {
    method: "POST",
    ca,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ client_id: humanClientId, scope: requestedScope }),
  });
  expectStatus(deviceResponse, 200, `${label} device authorization request`);
  const device = object(deviceResponse.body, "device authorization response");
  expect(typeof device.device_code === "string", "Device response omitted device_code");
  expect(typeof device.user_code === "string", "Device response omitted user_code");
  expect(typeof device.verification_uri === "string", "Device response omitted verification_uri");
  const verificationUrl =
    typeof device.verification_uri_complete === "string"
      ? device.verification_uri_complete
      : device.verification_uri;
  const expiresIn = typeof device.expires_in === "number" ? device.expires_in : 600;
  let intervalSeconds = typeof device.interval === "number" ? Math.max(1, device.interval) : 5;

  process.stdout.write(
    [
      "",
      `${label === "reviewer" ? "Reviewer" : "Admin"} human sign-in is required.`,
      `Open: ${verificationUrl}`,
      `User code: ${device.user_code}`,
      `Sign in specifically as: ${expectedUsername}`,
      `Credentials are stored in: ${relative(repositoryRoot, humanLoginFile)}`,
      label === "admin"
        ? "Use a private browser window or sign out first so the reviewer session is not reused."
        : "The runner is waiting for browser authorization; no password is sent to this script.",
      "",
    ].join("\n"),
  );

  const deadline = Date.now() + expiresIn * 1_000;
  while (Date.now() < deadline) {
    await sleep(intervalSeconds * 1_000);
    const tokenResponse = await request(tokenUrl, {
      method: "POST",
      ca,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        client_id: humanClientId,
        device_code: String(device.device_code),
      }),
    });
    if (tokenResponse.status === 200) {
      const token = object(tokenResponse.body, "device token response");
      expect(typeof token.access_token === "string", "Device token response omitted access_token");
      return token.access_token;
    }
    const pending = object(tokenResponse.body, "device token pending response");
    if (pending.error === "authorization_pending") continue;
    if (pending.error === "slow_down") {
      intervalSeconds += 5;
      continue;
    }
    if (pending.error === "access_denied") {
      throw new PilotFailure("DEVICE_ACCESS_DENIED", `${label} denied the device authorization request`);
    }
    if (pending.error === "expired_token") break;
    throw new PilotFailure("DEVICE_AUTHORIZATION_FAILED", `${label} device authorization failed`);
  }
  throw new PilotFailure("DEVICE_AUTHORIZATION_EXPIRED", `${label} device authorization expired`);
}

async function parimit(
  path: string,
  options: {
    method?: string;
    accessToken?: string;
    body?: JsonValue;
    headers?: Readonly<Record<string, string>>;
  } = {},
): Promise<HttpResult> {
  const body = options.body === undefined ? undefined : JSON.stringify(options.body);
  return await request(`${parimitBaseUrl}${path}`, {
    method: options.method ?? "GET",
    headers: {
      ...(options.accessToken ? authorizationHeaders(options.accessToken, body !== undefined) : {}),
      ...(body !== undefined && !options.accessToken ? { "content-type": "application/json" } : {}),
      ...(options.headers ?? {}),
    },
    body,
  });
}

async function parimitIdentity(
  accessToken: string,
  expectedRole: AccessIdentity["role"],
): Promise<AccessIdentity> {
  const result = await parimit("/v1/identity", { accessToken });
  expectStatus(result, 200, `${expectedRole} Parimit identity`);
  const identity = dataObject(result, "Parimit identity");
  expect(identity.actor_role === expectedRole, `Parimit identity role must be ${expectedRole}`);
  expect(typeof identity.actor_id === "string" && /^oidc:[a-f0-9]{64}$/u.test(identity.actor_id), "Parimit returned an invalid actor id");
  expect(identity.authentication_method === "oidc", "Parimit identity must be OIDC-authenticated");
  expect(identity.issuer === issuer, "Parimit identity issuer mismatch");
  return { actorId: identity.actor_id, role: expectedRole };
}

function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 16);
}

function humanReviewSnapshot(intent: JsonObject): HumanReviewSnapshot {
  const amount = object(intent.amount, "proposal amount");
  const policy = object(intent.policy, "proposal policy");
  const reasons = array(policy.reasons, "proposal policy reasons");
  expect(amount.currency === "INR", "Proposal review currency must be INR");
  expect(typeof amount.minor === "string" && /^\d+$/u.test(amount.minor), "Proposal review amount is invalid");
  expect(typeof intent.id === "string" && intent.id.length > 0, "Proposal review id is missing");
  expect(typeof intent.payee_reference === "string" && intent.payee_reference.length > 0, "Proposal review payee is missing");
  expect(typeof intent.purpose === "string" && intent.purpose.length > 0, "Proposal review purpose is missing");
  expect(typeof policy.allowed === "boolean", "Proposal review policy result is missing");
  expect(reasons.every((reason) => typeof reason === "string"), "Proposal review policy reasons are invalid");
  expect(typeof policy.rules_version === "string" && policy.rules_version.length > 0, "Proposal review policy version is missing");
  expect(
    typeof policy.config_digest === "string" && /^[a-f0-9]{64}$/u.test(policy.config_digest),
    "Proposal review policy digest is invalid",
  );
  expect(
    intent.required_approvals === 1 || intent.required_approvals === 2,
    "Proposal review approval threshold is invalid",
  );
  expect(typeof intent.expires_at === "string" && !Number.isNaN(Date.parse(intent.expires_at)), "Proposal review expiry is invalid");
  expect(typeof intent.intent_hash === "string" && /^[a-f0-9]{64}$/u.test(intent.intent_hash), "Proposal review hash is invalid");

  return {
    id: intent.id,
    currency: amount.currency,
    amountMinor: amount.minor,
    payeeReference: intent.payee_reference,
    purpose: intent.purpose,
    policyAllowed: policy.allowed,
    policyReasons: reasons as string[],
    policyRulesVersion: policy.rules_version,
    policyConfigDigest: policy.config_digest,
    requiredApprovals: intent.required_approvals,
    expiresAt: intent.expires_at,
    intentHash: intent.intent_hash,
  };
}

function assertSameImmutableReview(
  current: HumanReviewSnapshot,
  expected: HumanReviewSnapshot,
): void {
  expect(
    JSON.stringify(current) === JSON.stringify(expected),
    "Proposal changed between creation and human review",
  );
}

function formattedInrMinor(minor: string): string {
  const padded = minor.padStart(3, "0");
  return `${padded.slice(0, -2)}.${padded.slice(-2)}`;
}

async function requireTypedHumanApproval(
  label: "reviewer" | "admin",
  username: string,
  review: HumanReviewSnapshot,
  approvalCount: number,
): Promise<void> {
  const confirmation = `APPROVE ${label.toUpperCase()} ${review.intentHash}`;
  process.stdout.write(
    [
      "",
      `HUMAN DECISION REQUIRED — ${label.toUpperCase()} (${username})`,
      "Review this exact immutable fictional proposal. No payment will be sent.",
      `Intent: ${review.id}`,
      `Amount: ${review.currency} ${review.amountMinor} minor units (INR ${formattedInrMinor(review.amountMinor)})`,
      `Fictional payee: ${review.payeeReference}`,
      `Purpose: ${review.purpose}`,
      `Policy allowed: ${String(review.policyAllowed)}`,
      `Policy reasons: ${review.policyReasons.length === 0 ? "none" : review.policyReasons.join(", ")}`,
      `Policy rules version: ${review.policyRulesVersion}`,
      `Policy configuration digest: ${review.policyConfigDigest}`,
      `Required approvals: ${review.requiredApprovals}`,
      `Accepted approvals so far: ${approvalCount}`,
      `Expires at: ${review.expiresAt}`,
      `Intent hash: ${review.intentHash}`,
      label === "reviewer"
        ? "After the accepted decision, the runner will repeat it once only to verify duplicate-approver rejection."
        : "This is the second and final human decision; the resulting state must remain AUTHORIZED_NO_DISPATCH.",
      "",
      `Type exactly: ${confirmation}`,
    ].join("\n"),
  );

  const prompt = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  let response: string;
  try {
    response = await prompt.question("> ");
  } catch {
    throw new PilotFailure("HUMAN_CONFIRMATION_ABORTED", `${label} confirmation ended before an exact decision`);
  } finally {
    prompt.close();
  }
  if (response !== confirmation) {
    throw new PilotFailure("HUMAN_CONFIRMATION_REJECTED", `${label} did not enter the exact approval confirmation`);
  }
}

async function loadHumanReview(
  accessToken: string,
  intentId: string,
  expected: HumanReviewSnapshot,
  expectedApprovalCount: number,
): Promise<HumanReviewSnapshot> {
  const result = await parimit(`/v1/intents/${intentId}`, { accessToken });
  expectStatus(result, 200, "proposal read before human decision");
  const intent = dataObject(result, "proposal read before human decision");
  const review = humanReviewSnapshot(intent);
  assertSameImmutableReview(review, expected);
  expect(intent.status === "AWAITING_APPROVAL", "Proposal is not awaiting human review");
  expect(intent.approval_count === expectedApprovalCount, "Proposal approval count changed before human review");
  return review;
}

function redact(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(redact);
  if (value !== null && typeof value === "object") {
    const result: JsonObject = {};
    for (const [key, child] of Object.entries(value)) {
      if (/token|secret|password|private|authorization|compact_jws|device_code/ui.test(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = redact(child);
      }
    }
    return result;
  }
  if (typeof value === "string" && /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(value)) {
    return "[REDACTED_JWT]";
  }
  return value;
}

async function writeReport(path: string, report: JsonObject): Promise<void> {
  assertManagedReportPath(path);
  const parentKind = await lstat(reportsDirectory).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (parentKind?.isSymbolicLink() || (parentKind && !parentKind.isDirectory())) {
    throw new PilotFailure("UNSAFE_REPORT_PATH", "Report directory is not a regular directory");
  }
  if (!parentKind) await mkdir(reportsDirectory, { mode: 0o700 });

  const targetKind = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (targetKind?.isSymbolicLink() || (targetKind && !targetKind.isFile())) {
    throw new PilotFailure("UNSAFE_REPORT_PATH", "Report target is not a regular file");
  }

  const temporary = join(
    reportsDirectory,
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  try {
    await writeFile(temporary, `${JSON.stringify(redact(report), null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await chmod(temporary, 0o600);
    await rename(temporary, path);
    await chmod(path, 0o600);
  } finally {
    await rm(temporary, { force: true });
  }
}

function gitCommit(): string | null {
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0 ? String(result.stdout).trim() : null;
}

function gitWorkingTreeDirty(): boolean {
  const result = spawnSync("git", ["status", "--porcelain", "--untracked-files=all"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error || result.status !== 0) {
    throw new PilotFailure("GIT_STATUS_FAILED", "Could not establish repository working-tree state");
  }
  return String(result.stdout).trim().length > 0;
}

async function execute(): Promise<void> {
  process.umask(0o077);
  const options = parseArguments(process.argv.slice(2));
  const startedAt = new Date().toISOString();
  const runId = `${Date.now().toString(36)}-${randomBytes(8).toString("hex")}`;
  const checks: CheckRecord[] = [];
  let reportStatus: "PASS" | "FAIL" = "FAIL";
  let safeFailure: JsonObject | undefined;
  let intentId: string | undefined;
  let sourceGitCommit: string | null = null;
  let repositoryWorkingTreeDirty: boolean | null = null;
  let effectiveComposeSha256: string | null = null;

  async function check(name: string, action: () => Promise<JsonValue | void>): Promise<void> {
    try {
      const detail = await action();
      checks.push({ name, status: "PASS", ...(detail === undefined ? {} : { detail }) });
      process.stdout.write(`PASS  ${name}\n`);
    } catch (error) {
      const message = describeError(error, "Unknown failure");
      checks.push({ name, status: "FAIL", detail: { message } });
      throw error;
    }
  }

  try {
    const environment = await readEnvironment(options.environmentFile);
    const ca = await readFile(caCertificateFile);
    const requiredType = environment.get("PARIMIT_OIDC_REQUIRED_TYP") || "JWT";

    if (!options.workloadSmoke && (!process.stdin.isTTY || !process.stdout.isTTY)) {
      throw new PilotFailure(
        "INTERACTIVE_TERMINAL_REQUIRED",
        "Full acceptance requires an interactive terminal for two browser-mediated human logins",
      );
    }

    await check("Docker supports secure loopback-only port publishing", async () => {
      return { server_version: dockerServerVersion(), minimum_version: "28.3.3" };
    });

    await check("Pilot inputs are traceable to a clean source state", async () => {
      sourceGitCommit = gitCommit();
      expect(sourceGitCommit !== null, "The pilot must run from a Git commit");
      repositoryWorkingTreeDirty = gitWorkingTreeDirty();
      expect(repositoryWorkingTreeDirty === false, "The repository has uncommitted or untracked files");
      effectiveComposeSha256 = composeConfigurationDigest(options);
      return {
        git_commit: sourceGitCommit,
        repository_working_tree_dirty: false,
        effective_compose_sha256: effectiveComposeSha256,
      };
    });

    await check("Canonical Compose stack rebuilds and starts without deleting state", async () => {
      runCompose(options, ["up", "-d", "--build"]);
      return { services: ["keycloak", "parimit"], volumes_deleted: false };
    });

    await check("Compose publishes only the two expected loopback endpoints", async () => {
      const runningServices = runningPilotServices();
      expect(
        runningServices.length === 2 &&
          runningServices[0] === "keycloak" &&
          runningServices[1] === "parimit",
        "The pilot Compose project has unexpected or missing running services",
      );
      const keycloakPorts = publishedPortBindings(options, "keycloak");
      const parimitPorts = publishedPortBindings(options, "parimit");
      expect(
        keycloakPorts.length === 1 && keycloakPorts[0] === "8443/tcp->127.0.0.1:8443",
        "Keycloak effective port bindings are not exactly 127.0.0.1:8443",
      );
      expect(
        parimitPorts.length === 1 && parimitPorts[0] === "8787/tcp->127.0.0.1:8787",
        "Parimit effective port bindings are not exactly 127.0.0.1:8787",
      );
      return {
        running_services: runningServices,
        keycloak: keycloakPorts,
        parimit: parimitPorts,
      };
    });

    let discovery: JsonObject = {};
    let jwks: JsonObject = {};
    await check("Keycloak discovery and JWKS are TLS-verified", async () => {
      const discoveryResult = await waitForJson("Keycloak", discoveryUrl, ca);
      discovery = object(discoveryResult.body, "OIDC discovery");
      expect(discovery.issuer === issuer, "OIDC discovery issuer mismatch");
      expect(discovery.token_endpoint === tokenUrl, "OIDC discovery token endpoint mismatch");
      expect(discovery.device_authorization_endpoint === deviceAuthorizationUrl, "OIDC discovery device endpoint mismatch");
      expect(typeof discovery.jwks_uri === "string", "OIDC discovery omitted jwks_uri");
      const jwksResult = await request(String(discovery.jwks_uri), { ca });
      expectStatus(jwksResult, 200, "Keycloak JWKS");
      jwks = object(jwksResult.body, "Keycloak JWKS");
      expect(array(jwks.keys, "Keycloak JWKS keys").length > 0, "Keycloak JWKS is empty");
      return { issuer, audience: expectedAudience, tls_ca: "local pinned CA" };
    });

    await check("Parimit declares the non-execution boundary", async () => {
      const result = await waitForJson("Parimit", `${parimitBaseUrl}/v1/safety`, undefined);
      const safety = dataObject(result, "Parimit safety");
      expect(safety.mode === "PROPOSAL_ONLY", "Parimit safety mode is not PROPOSAL_ONLY");
      expect(safety.moves_money === false, "Parimit safety metadata claims money movement");
      expect(safety.connects_to_upi === false, "Parimit safety metadata claims a UPI connection");
      expect(Array.isArray(safety.execution_routes) && safety.execution_routes.length === 0, "Execution routes must be empty");
      const identity = object(safety.identity, "Parimit safety identity");
      expect(identity.mode === "oidc" && identity.cryptographically_verified === true, "OIDC safety identity is not active");
      return { mode: safety.mode, moves_money: false, connects_to_upi: false, execution_routes: [] };
    });

    const agentSecret = requiredEnvironment(environment, "PARIMIT_AGENT_CLIENT_SECRET");
    const consumerSecret = requiredEnvironment(environment, "PARIMIT_CONSUMER_CLIENT_SECRET");
    let agentToken = "";
    let consumerToken = "";
    await check("Agent workload obtains a signed audience-bound token", async () => {
      agentToken = await clientCredentialsToken("parimit-agent-workload", agentSecret, ca);
      return verifyAccessToken(
        agentToken,
        jwks,
        "agent",
        requiredType,
        "parimit-agent-workload",
      );
    });
    await check("Consumer workload obtains a signed audience-bound token", async () => {
      consumerToken = await clientCredentialsToken("parimit-consumer-workload", consumerSecret, ca);
      return verifyAccessToken(
        consumerToken,
        jwks,
        "consumer",
        requiredType,
        "parimit-consumer-workload",
      );
    });

    let agentIdentity!: AccessIdentity;
    let consumerIdentity!: AccessIdentity;
    await check("Parimit maps workload identities to one role each", async () => {
      agentIdentity = await parimitIdentity(agentToken, "agent");
      consumerIdentity = await parimitIdentity(consumerToken, "consumer");
      expect(agentIdentity.actorId !== consumerIdentity.actorId, "Workload actors are not distinct");
      return {
        agent_actor_fingerprint: fingerprint(agentIdentity.actorId),
        consumer_actor_fingerprint: fingerprint(consumerIdentity.actorId),
      };
    });

    await check("Missing tokens and spoofed demo headers fail closed", async () => {
      const missing = await parimit("/v1/identity");
      expectStatus(missing, 401, "missing-token identity request");
      const spoofed = await parimit("/v1/identity", {
        headers: { "x-parimit-actor": "spoofed", "x-parimit-role": "admin" },
      });
      expectStatus(spoofed, 401, "demo-header spoof request");
      return { missing_token_status: 401, demo_header_status: 401 };
    });

    await check("Workload roles cannot cross authorization boundaries", async () => {
      const consumerList = await parimit("/v1/intents", { accessToken: consumerToken });
      expectStatus(consumerList, 403, "consumer proposal listing");
      const agentAdminOperation = await parimit(
        "/v1/demo/intents/00000000-0000-4000-8000-000000000000/observations",
        {
          method: "POST",
          accessToken: agentToken,
          body: { status: "IN_DOUBT", provider_reference: "fictional-unauthorized-probe" },
        },
      );
      expectStatus(agentAdminOperation, 403, "agent admin-operation attempt");
      return { consumer_list_status: 403, agent_admin_operation_status: 403 };
    });

    if (options.workloadSmoke) {
      await check("Workload smoke makes no approval or execution call", async () => ({
        interactive_humans: false,
        approvals_attempted: 0,
        state_mutations: 0,
        classification: "WORKLOAD_SMOKE_ONLY",
      }));
      reportStatus = "PASS";
      return;
    }

    const amountMinor = String(Number(requiredEnvironment(environment, "PARIMIT_DUAL_APPROVAL_THRESHOLD")) + 1);
    expect(/^\d+$/u.test(amountMinor) && Number(amountMinor) > 0, "Dual-approval threshold is invalid");
    const idempotencyKey = `keycloak-pilot-${runId}`;
    let immutableReview!: HumanReviewSnapshot;
    const proposal: JsonObject = {
      idempotency_key: idempotencyKey,
      requested_by: { type: "agent", id: agentIdentity.actorId },
      on_behalf_of: "fictional-pilot-participant",
      amount: { currency: "INR", minor: amountMinor },
      payee_reference: "merchant_pilot_001",
      purpose: "Fictional Keycloak acceptance proposal; no real payment or payment credential",
      expires_in_seconds: 1_800,
    };

    await check("Agent simulation is non-persistent and requires two approvals", async () => {
      const result = await parimit("/v1/intents/simulate", {
        method: "POST",
        accessToken: agentToken,
        body: proposal,
      });
      expectStatus(result, 200, "proposal simulation");
      const simulation = dataObject(result, "proposal simulation");
      expect(simulation.persisted === false && simulation.moves_money === false, "Simulation crossed the safety boundary");
      const policy = object(simulation.policy, "simulation policy");
      expect(policy.allowed === true && policy.required_approvals === 2, "Simulation did not require dual approval");
      return { allowed: true, required_approvals: 2, persisted: false, moves_money: false };
    });

    await check("Agent creates one fictional dual-approval proposal", async () => {
      const result = await parimit("/v1/intents", {
        method: "POST",
        accessToken: agentToken,
        body: proposal,
      });
      expectStatus(result, 201, "proposal creation");
      const intent = dataObject(result, "proposal creation");
      expect(typeof intent.id === "string", "Created proposal omitted its id");
      intentId = intent.id;
      expect(intent.intent_version === "parimit-payment-intent-v3", "Pilot proposal is not tenant-bound v3");
      expect(intent.status === "AWAITING_APPROVAL" && intent.required_approvals === 2, "Proposal is not awaiting dual approval");
      immutableReview = humanReviewSnapshot(intent);
      return {
        intent_id: intentId,
        intent_hash: immutableReview.intentHash,
        status: intent.status,
        required_approvals: 2,
      };
    });

    let reviewerToken = "";
    let reviewerIdentity!: AccessIdentity;
    await check("A human reviewer authenticates through Device Authorization", async () => {
      reviewerToken = await deviceAuthorizationToken("reviewer", "pilot-reviewer", ca);
      const tokenEvidence = verifyAccessToken(
        reviewerToken,
        jwks,
        "approver",
        requiredType,
        humanClientId,
        "pilot-reviewer",
      );
      reviewerIdentity = await parimitIdentity(reviewerToken, "approver");
      expect(reviewerIdentity.actorId !== agentIdentity.actorId, "Reviewer is the requesting agent");
      return {
        flow: "urn:ietf:params:oauth:grant-type:device_code",
        actor_fingerprint: fingerprint(reviewerIdentity.actorId),
        token: tokenEvidence,
      };
    });

    await check("Reviewer records the first approval but cannot satisfy dual control twice", async () => {
      const review = await loadHumanReview(reviewerToken, intentId!, immutableReview, 0);
      await requireTypedHumanApproval("reviewer", "pilot-reviewer", review, 0);
      const first = await parimit(`/v1/intents/${intentId}/approvals`, {
        method: "POST",
        accessToken: reviewerToken,
        body: { decision: "APPROVE" },
      });
      expectStatus(first, 200, "first human approval");
      const partial = dataObject(first, "first human approval");
      expect(partial.status === "AWAITING_APPROVAL" && partial.approval_count === 1, "First approval incorrectly completed dual control");
      const duplicate = await parimit(`/v1/intents/${intentId}/approvals`, {
        method: "POST",
        accessToken: reviewerToken,
        body: { decision: "APPROVE" },
      });
      expectStatus(duplicate, 409, "duplicate reviewer approval");
      expect(errorCode(duplicate) === "DUPLICATE_APPROVER", "Duplicate reviewer failed for an unexpected reason");
      return { status_after_first: "AWAITING_APPROVAL", approval_count: 1, duplicate_status: 409 };
    });

    let adminToken = "";
    let adminIdentity!: AccessIdentity;
    await check("A distinct human admin authenticates through Device Authorization", async () => {
      adminToken = await deviceAuthorizationToken("admin", "pilot-admin", ca);
      const tokenEvidence = verifyAccessToken(
        adminToken,
        jwks,
        "admin",
        requiredType,
        humanClientId,
        "pilot-admin",
      );
      adminIdentity = await parimitIdentity(adminToken, "admin");
      expect(adminIdentity.actorId !== reviewerIdentity.actorId, "Admin and reviewer are not distinct identities");
      expect(adminIdentity.actorId !== agentIdentity.actorId, "Admin is the requesting agent");
      return {
        flow: "urn:ietf:params:oauth:grant-type:device_code",
        actor_fingerprint: fingerprint(adminIdentity.actorId),
        distinct_from_reviewer: true,
        token: tokenEvidence,
      };
    });

    await check("Distinct admin approval reaches AUTHORIZED_NO_DISPATCH only", async () => {
      const review = await loadHumanReview(adminToken, intentId!, immutableReview, 1);
      await requireTypedHumanApproval("admin", "pilot-admin", review, 1);
      const result = await parimit(`/v1/intents/${intentId}/approvals`, {
        method: "POST",
        accessToken: adminToken,
        body: { decision: "APPROVE" },
      });
      expectStatus(result, 200, "second human approval");
      const approved = dataObject(result, "second human approval");
      expect(approved.status === "AUTHORIZED_NO_DISPATCH", "Fully reviewed proposal has unexpected status");
      expect(approved.approval_count === 2, "Fully reviewed proposal does not contain two approvals");
      const receipt = object(approved.receipt, "approval receipt");
      expect(receipt.execution_authorized === false, "Approval receipt claims execution authority");
      return { status: approved.status, approval_count: 2, execution_authorized: false };
    });

    const envelopeAudience = requiredEnvironment(environment, "PARIMIT_ENVELOPE_AUDIENCES");
    let compactJws = "";
    await check("Human admin issues a signed evidence-only envelope", async () => {
      const result = await parimit(`/v1/intents/${intentId}/evidence-envelopes`, {
        method: "POST",
        accessToken: adminToken,
        body: {
          audience: envelopeAudience,
          idempotency_key: `issue-${runId}`,
          expires_in_seconds: Math.min(
            240,
            Number(requiredEnvironment(environment, "PARIMIT_ENVELOPE_TTL_SECONDS")),
          ),
        },
      });
      expectStatus(result, 201, "evidence-envelope issuance");
      const envelope = dataObject(result, "evidence-envelope issuance");
      expect(typeof envelope.compact_jws === "string", "Evidence envelope omitted compact JWS");
      compactJws = envelope.compact_jws;
      expect(envelope.execution_authorized === false && envelope.moves_money === false, "Envelope crossed the safety boundary");
      const claims = object(envelope.claims, "envelope claims");
      const capability = object(claims.capability, "envelope capability");
      for (const field of ["payment_dispatch_authorized", "execution_authorized", "provider_instruction", "moves_money"]) {
        expect(capability[field] === false, `Envelope capability ${field} must be false`);
      }
      return {
        envelope_id: claims.jti,
        audience: claims.aud,
        capability: {
          kind: capability.kind,
          payment_dispatch_authorized: false,
          execution_authorized: false,
          provider_instruction: false,
          moves_money: false,
        },
      };
    });

    const presentation: JsonObject = { compact_jws: compactJws, audience: envelopeAudience };
    await check("Consumer verifies and consumes the envelope exactly once", async () => {
      consumerToken = await clientCredentialsToken("parimit-consumer-workload", consumerSecret, ca);
      verifyAccessToken(
        consumerToken,
        jwks,
        "consumer",
        requiredType,
        "parimit-consumer-workload",
      );
      const verification = await parimit("/v1/evidence-envelopes/verify", {
        method: "POST",
        accessToken: consumerToken,
        body: presentation,
      });
      expectStatus(verification, 200, "evidence-envelope verification");
      expect(dataObject(verification, "evidence-envelope verification").valid === true, "Evidence envelope did not verify");
      const consumptionBody: JsonObject = {
        ...presentation,
        idempotency_key: `consume-${runId}`,
      };
      const consumption = await parimit("/v1/evidence-envelopes/consume", {
        method: "POST",
        accessToken: consumerToken,
        body: consumptionBody,
      });
      expectStatus(consumption, 200, "evidence-envelope consumption");
      const consumed = dataObject(consumption, "evidence-envelope consumption");
      expect(object(consumed.consumption, "consumption state").state === "CONSUMED", "Envelope was not consumed");

      const idempotentRetry = await parimit("/v1/evidence-envelopes/consume", {
        method: "POST",
        accessToken: consumerToken,
        body: consumptionBody,
      });
      expectStatus(idempotentRetry, 200, "same-operation consumption retry");
      expect(dataObject(idempotentRetry, "same-operation retry").idempotent_replay === true, "Same operation was not idempotent");

      const conflictingReplay = await parimit("/v1/evidence-envelopes/consume", {
        method: "POST",
        accessToken: consumerToken,
        body: { ...presentation, idempotency_key: `replay-${runId}` },
      });
      expectStatus(conflictingReplay, 409, "conflicting envelope replay");
      expect(errorCode(conflictingReplay) === "ENVELOPE_REPLAY_DETECTED", "Replay was rejected for an unexpected reason");
      return { verified: true, consumed: true, idempotent_retry: true, conflicting_replay_status: 409 };
    });

    await check("Admin mock observation remains fictional and freezes IN_DOUBT", async () => {
      const observation = await parimit(`/v1/demo/intents/${intentId}/observations`, {
        method: "POST",
        accessToken: adminToken,
        body: { status: "IN_DOUBT", provider_reference: `fictional-${runId}` },
      });
      expectStatus(observation, 200, "mock IN_DOUBT observation");
      const observed = dataObject(observation, "mock IN_DOUBT observation");
      expect(observed.status === "AUTHORIZED_NO_DISPATCH", "Mock observation changed authorization state");
      const observationData = object(observed.observation, "mock observation");
      expect(observationData.source === "DEMO_MOCK", "Observation source is not DEMO_MOCK");
      expect(observationData.retry_permitted === false, "IN_DOUBT observation permits retry");
      const retry = await parimit(`/v1/demo/intents/${intentId}/observations`, {
        method: "POST",
        accessToken: adminToken,
        body: { status: "SUCCEEDED", provider_reference: `fictional-retry-${runId}` },
      });
      expectStatus(retry, 409, "post-IN_DOUBT observation");
      expect(errorCode(retry) === "IN_DOUBT_FROZEN", "IN_DOUBT was not frozen");
      return { source: "DEMO_MOCK", status: "IN_DOUBT", retry_permitted: false };
    });

    await check("Audit integrity is valid before restart", async () => {
      agentToken = await clientCredentialsToken("parimit-agent-workload", agentSecret, ca);
      verifyAccessToken(agentToken, jwks, "agent", requiredType, "parimit-agent-workload");
      const result = await parimit(`/v1/intents/${intentId}/audit/verify`, { accessToken: agentToken });
      expectStatus(result, 200, "pre-restart audit verification");
      const integrity = dataObject(result, "pre-restart audit verification");
      expect(integrity.valid === true, "Audit integrity failed before restart");
      return { valid: true };
    });

    await check("Payment execution routes do not exist", async () => {
      const paths = [
        "/v1/pay",
        "/v1/execute",
        `/v1/intents/${intentId}/execute`,
        "/v1/payments",
        "/v1/dispatch",
      ];
      for (const path of paths) {
        const result = await parimit(path, { method: "POST", accessToken: agentToken, body: {} });
        expectStatus(result, 404, `nonexistent execution route ${path}`);
      }
      return { checked_routes: paths, all_statuses: 404 };
    });

    await check("Durable evidence and replay protection survive Parimit restart", async () => {
      runCompose(options, ["restart", "parimit"]);
      await waitForJson("Parimit after restart", `${parimitBaseUrl}/v1/safety`, undefined);
      agentToken = await clientCredentialsToken("parimit-agent-workload", agentSecret, ca);
      consumerToken = await clientCredentialsToken("parimit-consumer-workload", consumerSecret, ca);
      const verification = await parimit("/v1/evidence-envelopes/verify", {
        method: "POST",
        accessToken: consumerToken,
        body: presentation,
      });
      expectStatus(verification, 200, "post-restart envelope verification");
      const verified = dataObject(verification, "post-restart envelope verification");
      expect(verified.valid === true, "Envelope failed verification after restart");
      expect(object(verified.consumption, "post-restart consumption").state === "CONSUMED", "Consumption state was lost on restart");
      const replay = await parimit("/v1/evidence-envelopes/consume", {
        method: "POST",
        accessToken: consumerToken,
        body: { ...presentation, idempotency_key: `post-restart-replay-${runId}` },
      });
      expectStatus(replay, 409, "post-restart envelope replay");
      expect(errorCode(replay) === "ENVELOPE_REPLAY_DETECTED", "Replay protection was lost on restart");
      const integrity = await parimit(`/v1/intents/${intentId}/audit/verify`, { accessToken: agentToken });
      expectStatus(integrity, 200, "post-restart audit verification");
      expect(dataObject(integrity, "post-restart audit verification").valid === true, "Audit failed after restart");
      return { envelope_valid: true, consumption_state: "CONSUMED", replay_status: 409, audit_valid: true };
    });

    reportStatus = "PASS";
  } catch (error) {
    const code = error instanceof PilotFailure ? error.code : "UNEXPECTED_FAILURE";
    const message = describeError(error, "Unknown pilot failure");
    safeFailure = { code, message };
    throw error;
  } finally {
    const completedAt = new Date().toISOString();
    const report: JsonObject = {
      schema_version: "parimit-keycloak-pilot-report-v1",
      classification: options.workloadSmoke ? "WORKLOAD_SMOKE_ONLY" : "INTERACTIVE_HUMAN_ACCEPTANCE",
      status: reportStatus,
      run_id: runId,
      started_at: startedAt,
      completed_at: completedAt,
      git_commit: sourceGitCommit ?? gitCommit(),
      source: {
        repository_working_tree_dirty: repositoryWorkingTreeDirty,
        effective_compose_sha256: effectiveComposeSha256,
      },
      keycloak: {
        issuer,
        audience: expectedAudience,
        image: "quay.io/keycloak/keycloak:26.7.4",
        image_index_digest: "sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c",
      },
      parimit: {
        base_url: parimitBaseUrl,
        intent_id: intentId ?? null,
        payment_execution_capability: false,
      },
      checks: checks as unknown as JsonValue,
      contains_sensitive_values: false,
      ...(safeFailure === undefined ? {} : { failure: safeFailure }),
    };
    try {
      await writeReport(options.reportFile, report);
      process.stdout.write(`Redacted report: ${relative(repositoryRoot, options.reportFile)}\n`);
    } catch (reportError) {
      const message = reportError instanceof Error ? reportError.message : "Unknown report failure";
      if (reportStatus === "PASS") {
        throw new PilotFailure(
          "REPORT_WRITE_FAILED",
          `Passing run could not persist its redacted report: ${message}`,
        );
      }
      process.stderr.write(`Could not write the failed-run report: ${message}\n`);
    }
  }
}

execute().catch((error: unknown) => {
  const message = describeError(error, "Unknown pilot failure");
  process.stderr.write(`Keycloak pilot ${process.argv.includes("--workload-smoke") ? "smoke" : "acceptance"} failed: ${message}\n`);
  process.exitCode = 1;
});
