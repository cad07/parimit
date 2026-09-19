import {
  constants as cryptoConstants,
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";

import { ParimitError } from "./errors.ts";
import type { ActorRole } from "./types.ts";

const DEFAULT_CLOCK_SKEW_SECONDS = 60;
const MAX_CLOCK_SKEW_SECONDS = 300;
const DEFAULT_JWKS_CACHE_SECONDS = 300;
const DEFAULT_JWKS_REFRESH_SECONDS = 30;
const DEFAULT_JWKS_TIMEOUT_MILLISECONDS = 5_000;
const MAX_JWT_BYTES = 16_384;
const MAX_JWKS_BYTES = 1_048_576;

export type JwtAlgorithm = "RS256" | "PS256" | "ES256";

export interface AuthenticatedActor {
  /** Stable, non-PII identifier safe for Parimit's actor_id columns. */
  actorId: string;
  actorRole: ActorRole;
  /** Immutable identifier asserted by the identity provider. */
  subject: string;
  authenticationMethod: "oidc" | "local_demo_headers";
  issuer?: string;
}

export type AuthenticationHeaders = Readonly<
  Record<string, string | readonly string[] | undefined>
>;

export interface IdentityProvider {
  readonly authenticationMethod: AuthenticatedActor["authenticationMethod"];
  authenticate(headers: AuthenticationHeaders): Promise<AuthenticatedActor>;
}

export interface OidcIdentityProviderOptions {
  issuer: string;
  audience: string | readonly string[];
  jwksUri: string;
  /** Exact top-level claim name. Dots and URL-shaped claim names are not expanded. */
  roleClaim?: string;
  /** Maps identity-provider role values onto Parimit's three deliberately small roles. */
  roleMapping?: Readonly<Record<string, ActorRole>>;
  allowedAlgorithms?: readonly JwtAlgorithm[];
  /** Optional JOSE `typ` discriminator when the provider guarantees one for access tokens. */
  requiredTokenType?: "JWT" | "at+jwt";
  clockSkewSeconds?: number;
  /** When set, `iat` is required and `exp - iat` cannot exceed this value. */
  maxTokenLifetimeSeconds?: number;
  jwksCacheSeconds?: number;
  jwksRefreshSeconds?: number;
  jwksTimeoutMilliseconds?: number;
  fetch?: typeof globalThis.fetch;
  clock?: () => Date;
  /** Intended only for loopback integration tests and local identity-provider development. */
  allowInsecureLoopbackHttp?: boolean;
}

interface JwtHeader {
  alg: JwtAlgorithm;
  kid: string;
  typ?: string;
}

interface JwksCache {
  keys: Record<string, unknown>[];
  expiresAtSeconds: number;
  fetchedAtSeconds: number;
}

function configurationError(message: string): ParimitError {
  return new ParimitError("INVALID_AUTH_CONFIGURATION", message, 500);
}

function invalidToken(): ParimitError {
  // Keep authentication failures deliberately generic so they do not become a key/token oracle.
  return new ParimitError("INVALID_TOKEN", "Bearer token is invalid or expired", 401);
}

function requireFiniteNonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw configurationError(`${name} must be a non-negative integer`);
  }
  return value;
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLocaleLowerCase("en-US").replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "::1" || normalized === "127.0.0.1";
}

function validateUrl(value: string, name: string, allowInsecureLoopbackHttp: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw configurationError(`${name} must be an absolute URL`);
  }
  if (url.username || url.password || url.hash) {
    throw configurationError(`${name} cannot contain credentials or a fragment`);
  }
  const secure = url.protocol === "https:";
  const allowedLoopback =
    allowInsecureLoopbackHttp && url.protocol === "http:" && isLoopbackHostname(url.hostname);
  if (!secure && !allowedLoopback) {
    throw configurationError(`${name} must use HTTPS`);
  }
  return url;
}

function readSingleHeader(headers: AuthenticationHeaders, name: string): string | undefined {
  const matches = Object.entries(headers).filter(
    ([key]) => key.toLocaleLowerCase("en-US") === name.toLocaleLowerCase("en-US"),
  );
  if (matches.length === 0) return undefined;
  if (matches.length !== 1 || Array.isArray(matches[0]![1])) throw invalidToken();
  return matches[0]![1] as string | undefined;
}

function bearerToken(headers: AuthenticationHeaders): string {
  const authorization = readSingleHeader(headers, "authorization");
  if (authorization === undefined) {
    throw new ParimitError(
      "AUTHENTICATION_REQUIRED",
      "Authorization: Bearer is required",
      401,
    );
  }
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/);
  if (!match || Buffer.byteLength(match[1]!, "ascii") > MAX_JWT_BYTES) throw invalidToken();
  return match[1]!;
}

function decodeBase64Url(segment: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(segment) || segment.length % 4 === 1) throw invalidToken();
  const decoded = Buffer.from(segment, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== segment) throw invalidToken();
  return decoded;
}

function parseJsonSegment(segment: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(segment)));
  } catch {
    throw invalidToken();
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw invalidToken();
  return parsed as Record<string, unknown>;
}

function parseHeader(segment: string, allowedAlgorithms: ReadonlySet<JwtAlgorithm>): JwtHeader {
  const value = parseJsonSegment(segment);
  if (
    typeof value.alg !== "string" ||
    !allowedAlgorithms.has(value.alg as JwtAlgorithm) ||
    typeof value.kid !== "string" ||
    value.kid.length === 0 ||
    value.kid.length > 256
  ) {
    throw invalidToken();
  }
  if (value.typ !== undefined && value.typ !== "JWT" && value.typ !== "at+jwt") throw invalidToken();
  if (value.crit !== undefined || value.b64 !== undefined) throw invalidToken();
  for (const embeddedKey of ["jwk", "jku", "x5u", "x5c"]) {
    if (value[embeddedKey] !== undefined) throw invalidToken();
  }
  return {
    alg: value.alg as JwtAlgorithm,
    kid: value.kid,
    ...(value.typ === undefined ? {} : { typ: value.typ as string }),
  };
}

function isNumericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function audienceMatches(claim: unknown, audiences: ReadonlySet<string>): boolean {
  if (typeof claim === "string") return audiences.has(claim);
  return (
    Array.isArray(claim) &&
    claim.length > 0 &&
    claim.every((entry) => typeof entry === "string") &&
    claim.some((entry) => audiences.has(entry as string))
  );
}

function claimValues(value: unknown): string[] {
  if (typeof value === "string" && value.length > 0) return [value];
  if (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((entry) => typeof entry === "string" && entry.length > 0)
  ) {
    return value as string[];
  }
  return [];
}

function compatibleJwk(
  key: Record<string, unknown>,
  header: JwtHeader,
): boolean {
  if (key.kid !== header.kid) return false;
  if (key.use !== undefined && key.use !== "sig") return false;
  if (
    key.key_ops !== undefined &&
    (!Array.isArray(key.key_ops) || !key.key_ops.includes("verify"))
  ) {
    return false;
  }
  if (key.alg !== undefined && key.alg !== header.alg) return false;
  if (["d", "p", "q", "dp", "dq", "qi", "oth"].some((field) => key[field] !== undefined)) {
    return false;
  }
  if ((header.alg === "RS256" || header.alg === "PS256") && key.kty !== "RSA") return false;
  if (header.alg === "ES256" && (key.kty !== "EC" || key.crv !== "P-256")) return false;
  return true;
}

function selectKey(
  keys: readonly Record<string, unknown>[],
  header: JwtHeader,
): Record<string, unknown> | undefined {
  const matches = keys.filter((key) => compatibleJwk(key, header));
  if (matches.length > 1) throw invalidToken();
  return matches[0];
}

function verifyJwtSignature(
  alg: JwtAlgorithm,
  signingInput: Buffer,
  signature: Buffer,
  jwk: Record<string, unknown>,
): boolean {
  try {
    const key = createPublicKey({ key: jwk, format: "jwk" } as Parameters<
      typeof createPublicKey
    >[0]);
    if (
      (alg === "RS256" || alg === "PS256") &&
      (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2_048
    ) {
      return false;
    }
    if (alg === "RS256") return verifySignature("RSA-SHA256", signingInput, key, signature);
    if (alg === "PS256") {
      return verifySignature(
        "sha256",
        signingInput,
        {
          key,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature,
      );
    }
    if (signature.length !== 64) return false;
    return verifySignature(
      "sha256",
      signingInput,
      { key, dsaEncoding: "ieee-p1363" },
      signature,
    );
  } catch {
    return false;
  }
}

function parseMaximumAge(cacheControl: string | null): number | undefined {
  if (cacheControl === null) return undefined;
  const match = cacheControl.match(/(?:^|,)\s*max-age=(\d+)\s*(?:,|$)/i);
  if (!match) return undefined;
  const seconds = Number(match[1]);
  return Number.isSafeInteger(seconds) ? seconds : undefined;
}

async function readLimitedResponseText(response: Response, maximumBytes: number): Promise<string> {
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      const chunk = Buffer.from(result.value);
      length += chunk.length;
      if (length > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw new ParimitError(
          "AUTH_PROVIDER_UNAVAILABLE",
          "Identity provider JWKS is too large",
          503,
        );
      }
      chunks.push(chunk);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, length));
  } finally {
    reader.releaseLock();
  }
}

function stableActorId(issuer: string, subject: string): string {
  const digest = createHash("sha256")
    .update(issuer, "utf8")
    .update("\0", "utf8")
    .update(subject, "utf8")
    .digest("hex");
  return `oidc:${digest}`;
}

export class OidcIdentityProvider implements IdentityProvider {
  readonly authenticationMethod = "oidc" as const;
  private readonly issuer: string;
  private readonly audiences: ReadonlySet<string>;
  private readonly jwksUri: string;
  private readonly roleClaim: string;
  private readonly roleMapping: Readonly<Record<string, ActorRole>>;
  private readonly allowedAlgorithms: ReadonlySet<JwtAlgorithm>;
  private readonly requiredTokenType?: "JWT" | "at+jwt";
  private readonly clockSkewSeconds: number;
  private readonly maxTokenLifetimeSeconds?: number;
  private readonly jwksCacheSeconds: number;
  private readonly jwksRefreshSeconds: number;
  private readonly jwksTimeoutMilliseconds: number;
  private readonly fetchImplementation: typeof globalThis.fetch;
  private readonly clock: () => Date;
  private cache?: JwksCache;
  private fetchInFlight?: Promise<JwksCache>;

  constructor(options: OidcIdentityProviderOptions) {
    const allowInsecure = options.allowInsecureLoopbackHttp === true;
    validateUrl(options.issuer, "issuer", allowInsecure);
    validateUrl(options.jwksUri, "jwksUri", allowInsecure);
    this.issuer = options.issuer;
    this.jwksUri = options.jwksUri;

    const audienceValues = typeof options.audience === "string" ? [options.audience] : options.audience;
    if (
      audienceValues.length === 0 ||
      audienceValues.some((audience) => typeof audience !== "string" || audience.length === 0)
    ) {
      throw configurationError("audience must contain at least one non-empty value");
    }
    this.audiences = new Set(audienceValues);

    this.roleClaim = options.roleClaim ?? "roles";
    if (this.roleClaim.length === 0) throw configurationError("roleClaim cannot be empty");
    const configuredRoleMapping = options.roleMapping ?? {
      agent: "agent",
      approver: "approver",
      admin: "admin",
    };
    const validRoles = new Set<ActorRole>(["agent", "approver", "admin"]);
    if (
      Object.keys(configuredRoleMapping).length === 0 ||
      Object.entries(configuredRoleMapping).some(
        ([source, role]) => source.length === 0 || !validRoles.has(role),
      )
    ) {
      throw configurationError("roleMapping must map non-empty provider roles to Parimit roles");
    }
    this.roleMapping = Object.freeze(
      Object.assign(Object.create(null) as Record<string, ActorRole>, configuredRoleMapping),
    );

    const algorithms = options.allowedAlgorithms ?? ["RS256"];
    const supported = new Set<JwtAlgorithm>(["RS256", "PS256", "ES256"]);
    if (
      algorithms.length === 0 ||
      new Set(algorithms).size !== algorithms.length ||
      algorithms.some((algorithm) => !supported.has(algorithm))
    ) {
      throw configurationError("allowedAlgorithms must contain unique RS256, PS256, or ES256 values");
    }
    this.allowedAlgorithms = new Set(algorithms);
    if (
      options.requiredTokenType !== undefined &&
      options.requiredTokenType !== "JWT" &&
      options.requiredTokenType !== "at+jwt"
    ) {
      throw configurationError("requiredTokenType must be 'JWT' or 'at+jwt'");
    }
    this.requiredTokenType = options.requiredTokenType;
    this.clockSkewSeconds = requireFiniteNonNegativeInteger(
      options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS,
      "clockSkewSeconds",
    );
    if (this.clockSkewSeconds > MAX_CLOCK_SKEW_SECONDS) {
      throw configurationError(`clockSkewSeconds cannot exceed ${MAX_CLOCK_SKEW_SECONDS}`);
    }
    if (options.maxTokenLifetimeSeconds !== undefined) {
      this.maxTokenLifetimeSeconds = requireFiniteNonNegativeInteger(
        options.maxTokenLifetimeSeconds,
        "maxTokenLifetimeSeconds",
      );
      if (this.maxTokenLifetimeSeconds === 0) {
        throw configurationError("maxTokenLifetimeSeconds must be greater than zero");
      }
    }
    this.jwksCacheSeconds = requireFiniteNonNegativeInteger(
      options.jwksCacheSeconds ?? DEFAULT_JWKS_CACHE_SECONDS,
      "jwksCacheSeconds",
    );
    this.jwksRefreshSeconds = requireFiniteNonNegativeInteger(
      options.jwksRefreshSeconds ?? DEFAULT_JWKS_REFRESH_SECONDS,
      "jwksRefreshSeconds",
    );
    this.jwksTimeoutMilliseconds = requireFiniteNonNegativeInteger(
      options.jwksTimeoutMilliseconds ?? DEFAULT_JWKS_TIMEOUT_MILLISECONDS,
      "jwksTimeoutMilliseconds",
    );
    if (this.jwksTimeoutMilliseconds === 0) {
      throw configurationError("jwksTimeoutMilliseconds must be greater than zero");
    }
    this.fetchImplementation = options.fetch ?? globalThis.fetch;
    if (typeof this.fetchImplementation !== "function") {
      throw configurationError("A Fetch API implementation is required for JWKS retrieval");
    }
    this.clock = options.clock ?? (() => new Date());
  }

  async authenticate(headers: AuthenticationHeaders): Promise<AuthenticatedActor> {
    const token = bearerToken(headers);
    const segments = token.split(".");
    if (segments.length !== 3) throw invalidToken();
    const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];
    const header = parseHeader(encodedHeader, this.allowedAlgorithms);
    if (this.requiredTokenType !== undefined && header.typ !== this.requiredTokenType) {
      throw invalidToken();
    }
    const claims = parseJsonSegment(encodedPayload);
    const signature = decodeBase64Url(encodedSignature);

    let jwk = selectKey((await this.getJwks(false)).keys, header);
    const now = this.nowSeconds();
    if (
      jwk === undefined &&
      this.cache !== undefined &&
      now - this.cache.fetchedAtSeconds >= this.jwksRefreshSeconds
    ) {
      jwk = selectKey((await this.getJwks(true)).keys, header);
    }
    if (jwk === undefined) throw invalidToken();

    const validSignature = verifyJwtSignature(
      header.alg,
      Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"),
      signature,
      jwk,
    );
    if (!validSignature) throw invalidToken();

    this.validateRegisteredClaims(claims, now);
    const subject = claims.sub as string;
    const mappedRoles = new Set(
      claimValues(claims[this.roleClaim])
        .map((role) =>
          Object.hasOwn(this.roleMapping, role) ? this.roleMapping[role] : undefined,
        )
        .filter((role): role is ActorRole => role !== undefined),
    );
    if (mappedRoles.size === 0) {
      throw new ParimitError(
        "ROLE_NOT_AUTHORIZED",
        "Authenticated subject has no Parimit role",
        403,
      );
    }
    if (mappedRoles.size !== 1) {
      throw new ParimitError(
        "AMBIGUOUS_ROLE",
        "Authenticated subject maps to more than one Parimit role",
        403,
      );
    }
    return {
      actorId: stableActorId(this.issuer, subject),
      actorRole: [...mappedRoles][0]!,
      subject,
      issuer: this.issuer,
      authenticationMethod: "oidc",
    };
  }

  private validateRegisteredClaims(claims: Record<string, unknown>, now: number): void {
    if (
      claims.iss !== this.issuer ||
      !audienceMatches(claims.aud, this.audiences) ||
      typeof claims.sub !== "string" ||
      claims.sub.length === 0 ||
      claims.sub.length > 1_024 ||
      !isNumericDate(claims.exp)
    ) {
      throw invalidToken();
    }
    if (now - this.clockSkewSeconds >= claims.exp) throw invalidToken();
    if (claims.nbf !== undefined) {
      if (!isNumericDate(claims.nbf) || now + this.clockSkewSeconds < claims.nbf) {
        throw invalidToken();
      }
      if (claims.nbf >= claims.exp) throw invalidToken();
    }
    if (claims.iat !== undefined) {
      if (
        !isNumericDate(claims.iat) ||
        now + this.clockSkewSeconds < claims.iat ||
        claims.iat >= claims.exp
      ) {
        throw invalidToken();
      }
    }
    if (
      this.maxTokenLifetimeSeconds !== undefined &&
      (claims.iat === undefined ||
        !isNumericDate(claims.iat) ||
        claims.exp - claims.iat > this.maxTokenLifetimeSeconds)
    ) {
      throw invalidToken();
    }
  }

  private nowSeconds(): number {
    return Math.floor(this.clock().getTime() / 1_000);
  }

  private async getJwks(forceRefresh: boolean): Promise<JwksCache> {
    const now = this.nowSeconds();
    if (!forceRefresh && this.cache !== undefined && now < this.cache.expiresAtSeconds) {
      return this.cache;
    }
    if (this.fetchInFlight !== undefined) return this.fetchInFlight;
    this.fetchInFlight = this.fetchJwks();
    try {
      this.cache = await this.fetchInFlight;
      return this.cache;
    } finally {
      this.fetchInFlight = undefined;
    }
  }

  private async fetchJwks(): Promise<JwksCache> {
    let response: Response;
    try {
      response = await this.fetchImplementation(this.jwksUri, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(this.jwksTimeoutMilliseconds),
      });
    } catch {
      throw new ParimitError(
        "AUTH_PROVIDER_UNAVAILABLE",
        "Identity provider keys are temporarily unavailable",
        503,
      );
    }
    if (!response.ok) {
      throw new ParimitError(
        "AUTH_PROVIDER_UNAVAILABLE",
        "Identity provider keys are temporarily unavailable",
        503,
      );
    }
    const contentLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(contentLength) && contentLength > MAX_JWKS_BYTES) {
      throw new ParimitError("AUTH_PROVIDER_UNAVAILABLE", "Identity provider JWKS is too large", 503);
    }
    let text: string;
    try {
      text = await readLimitedResponseText(response, MAX_JWKS_BYTES);
    } catch (error) {
      if (error instanceof ParimitError) throw error;
      throw new ParimitError(
        "AUTH_PROVIDER_UNAVAILABLE",
        "Identity provider keys are temporarily unavailable",
        503,
      );
    }
    let document: unknown;
    try {
      document = JSON.parse(text);
    } catch {
      throw new ParimitError("AUTH_PROVIDER_UNAVAILABLE", "Identity provider JWKS is invalid", 503);
    }
    if (
      typeof document !== "object" ||
      document === null ||
      Array.isArray(document) ||
      !Array.isArray((document as Record<string, unknown>).keys) ||
      (document as { keys: unknown[] }).keys.length === 0 ||
      !(document as { keys: unknown[] }).keys.every(
        (key) => typeof key === "object" && key !== null && !Array.isArray(key),
      )
    ) {
      throw new ParimitError("AUTH_PROVIDER_UNAVAILABLE", "Identity provider JWKS is invalid", 503);
    }
    const now = this.nowSeconds();
    const advertisedMaximumAge = parseMaximumAge(response.headers.get("cache-control"));
    const cacheSeconds = Math.min(advertisedMaximumAge ?? this.jwksCacheSeconds, this.jwksCacheSeconds);
    return {
      keys: (document as { keys: Record<string, unknown>[] }).keys,
      fetchedAtSeconds: now,
      expiresAtSeconds: now + cacheSeconds,
    };
  }
}

export interface LocalDemoHeaderIdentityProviderOptions {
  demoMode: boolean;
  host: string;
  /** Container-only escape hatch; the publisher must bind the host port to loopback. */
  allowNonLoopback?: boolean;
}

/**
 * Spoofable identity headers retained solely for a local demo. Construction fails unless demo
 * mode is explicit and the HTTP server is loopback-bound, apart from an explicit container escape
 * hatch whose published host port must itself remain loopback-only.
 */
export class LocalDemoHeaderIdentityProvider implements IdentityProvider {
  readonly authenticationMethod = "local_demo_headers" as const;

  constructor(options: LocalDemoHeaderIdentityProviderOptions) {
    if (
      !options.demoMode ||
      (!isLoopbackHostname(options.host) && options.allowNonLoopback !== true)
    ) {
      throw configurationError(
        "LocalDemoHeaderIdentityProvider requires explicit demo mode and a loopback host",
      );
    }
  }

  async authenticate(headers: AuthenticationHeaders): Promise<AuthenticatedActor> {
    const actorId = readSingleHeader(headers, "x-parimit-actor");
    const rawRole = readSingleHeader(headers, "x-parimit-role");
    if (actorId === undefined || rawRole === undefined) {
      throw new ParimitError(
        "DEMO_AUTH_REQUIRED",
        "x-parimit-actor and x-parimit-role are required in local demo mode",
        401,
      );
    }
    if (
      actorId.length === 0 ||
      actorId.length > 128 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$/.test(actorId)
    ) {
      throw new ParimitError("INVALID_DEMO_IDENTITY", "Demo actor identifier is invalid", 401);
    }
    const actorRole = rawRole.toLocaleLowerCase("en-US") as ActorRole;
    if (actorRole !== "agent" && actorRole !== "approver" && actorRole !== "admin") {
      throw new ParimitError("INVALID_DEMO_IDENTITY", "Demo actor role is invalid", 401);
    }
    return {
      actorId,
      actorRole,
      subject: actorId,
      authenticationMethod: "local_demo_headers",
    };
  }
}

export interface IdentityProviderDependencies {
  fetch?: typeof globalThis.fetch;
  clock?: () => Date;
}

function parseRoleMapping(value: string | undefined): Readonly<Record<string, ActorRole>> | undefined {
  if (value === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw configurationError("PARIMIT_OIDC_ROLE_MAPPING must be valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw configurationError("PARIMIT_OIDC_ROLE_MAPPING must be a JSON object");
  }
  return parsed as Record<string, ActorRole>;
}

export function createIdentityProviderFromEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
  dependencies: IdentityProviderDependencies = {},
): IdentityProvider {
  const mode = environment.PARIMIT_AUTH_MODE;
  if (mode === "demo_headers") {
    const demoMode = (environment.PARIMIT_DEMO_MODE ?? "").toLocaleLowerCase("en-US");
    const nonLoopback = (
      environment.PARIMIT_DEMO_ALLOW_NON_LOOPBACK_HEADERS ?? ""
    ).toLocaleLowerCase("en-US");
    return new LocalDemoHeaderIdentityProvider({
      demoMode: demoMode === "true" || demoMode === "1",
      host: environment.PARIMIT_HOST ?? "127.0.0.1",
      allowNonLoopback: nonLoopback === "true" || nonLoopback === "1",
    });
  }
  if (mode !== "oidc") {
    throw configurationError("PARIMIT_AUTH_MODE must be 'oidc' or 'demo_headers'");
  }
  const issuer = environment.PARIMIT_OIDC_ISSUER;
  const audience = environment.PARIMIT_OIDC_AUDIENCE;
  const jwksUri = environment.PARIMIT_OIDC_JWKS_URI;
  const roleMapping = environment.PARIMIT_OIDC_ROLE_MAPPING;
  if (!issuer || !audience || !jwksUri || !roleMapping) {
    throw configurationError(
      "OIDC mode requires PARIMIT_OIDC_ISSUER, PARIMIT_OIDC_AUDIENCE, PARIMIT_OIDC_JWKS_URI, and PARIMIT_OIDC_ROLE_MAPPING",
    );
  }
  const clockSkew = environment.PARIMIT_OIDC_CLOCK_SKEW_SECONDS;
  const maximumTokenLifetime =
    environment.PARIMIT_OIDC_MAX_TOKEN_LIFETIME_SECONDS ?? "3600";
  const requiredTokenType = environment.PARIMIT_OIDC_REQUIRED_TYP;
  return new OidcIdentityProvider({
    issuer,
    audience,
    jwksUri,
    roleClaim: environment.PARIMIT_OIDC_ROLE_CLAIM ?? "roles",
    roleMapping: parseRoleMapping(roleMapping),
    ...(clockSkew === undefined ? {} : { clockSkewSeconds: Number(clockSkew) }),
    maxTokenLifetimeSeconds: Number(maximumTokenLifetime),
    ...(requiredTokenType === undefined || requiredTokenType === ""
      ? {}
      : { requiredTokenType: requiredTokenType as "JWT" | "at+jwt" }),
    ...dependencies,
  });
}
