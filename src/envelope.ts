import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import { canonicalJson } from "./crypto.ts";

export const AUTHORIZATION_ENVELOPE_TYPE = "parimit-authz-envelope+jws";
export const MAX_AUTHORIZATION_ENVELOPE_BYTES = 65_536;

export interface EnvelopeSigningKey {
  readonly privateKey: KeyObject;
  readonly publicJwk: Readonly<Record<string, unknown>>;
  readonly keyId: string;
  readonly ephemeral: boolean;
}

export interface ParsedAuthorizationEnvelope {
  header: {
    alg: "EdDSA";
    kid: string;
    typ: typeof AUTHORIZATION_ENVELOPE_TYPE;
  };
  payload: Record<string, unknown>;
}

function decodeBase64Url(segment: string, field: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(segment) || segment.length % 4 === 1) {
    throw new TypeError(`${field} is not canonical base64url`);
  }
  const decoded = Buffer.from(segment, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== segment) {
    throw new TypeError(`${field} is not canonical base64url`);
  }
  return decoded;
}

function parseObject(buffer: Buffer, field: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer)) as unknown;
  } catch {
    throw new TypeError(`${field} must contain UTF-8 JSON`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${field} must contain a JSON object`);
  }
  return value as Record<string, unknown>;
}

function normalizedPublicJwk(publicKey: KeyObject): Record<string, unknown> {
  const exported = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519" || typeof exported.x !== "string") {
    throw new TypeError("Authorization-envelope signing key must be Ed25519");
  }
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: exported.x,
    use: "sig",
    key_ops: ["verify"],
    alg: "EdDSA",
  };
}

function jwkThumbprint(jwk: Record<string, unknown>): string {
  const thumbprintInput = canonicalJson({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash("sha256").update(thumbprintInput, "utf8").digest("base64url");
}

function isCanonicalEd25519Coordinate(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

export function createEnvelopeSigningKey(
  privateKeyPem?: string,
  configuredKeyId?: string,
): EnvelopeSigningKey {
  let privateKey: KeyObject;
  let ephemeral = false;
  if (privateKeyPem === undefined) {
    privateKey = generateKeyPairSync("ed25519").privateKey;
    ephemeral = true;
  } else {
    try {
      privateKey = createPrivateKey(privateKeyPem);
    } catch {
      throw new TypeError("Authorization-envelope private key is not valid PEM");
    }
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("Authorization-envelope private key must be Ed25519");
  }
  const publicJwk = normalizedPublicJwk(createPublicKey(privateKey));
  const keyId = configuredKeyId ?? `ed25519:${jwkThumbprint(publicJwk)}`;
  if (
    keyId.length < 1 ||
    keyId.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@/+-]*$/.test(keyId)
  ) {
    throw new TypeError("Authorization-envelope key id contains unsupported characters");
  }
  const immutablePublicJwk = Object.freeze({
    ...publicJwk,
    key_ops: Object.freeze(["verify"]),
    kid: keyId,
  });
  return Object.freeze({
    privateKey,
    publicJwk: immutablePublicJwk,
    keyId,
    ephemeral,
  });
}

export function signAuthorizationEnvelope(
  payload: Record<string, unknown>,
  signingKey: EnvelopeSigningKey,
): string {
  const header = {
    alg: "EdDSA",
    kid: signingKey.keyId,
    typ: AUTHORIZATION_ENVELOPE_TYPE,
  } as const;
  const encodedHeader = Buffer.from(canonicalJson(header), "utf8").toString("base64url");
  const encodedPayload = Buffer.from(canonicalJson(payload), "utf8").toString("base64url");
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = sign(null, Buffer.from(signingInput, "ascii"), signingKey.privateKey);
  return `${signingInput}.${signature.toString("base64url")}`;
}

export function parseAuthorizationEnvelope(
  compactJws: string,
): ParsedAuthorizationEnvelope {
  if (
    typeof compactJws !== "string" ||
    compactJws.length === 0 ||
    Buffer.byteLength(compactJws, "ascii") > MAX_AUTHORIZATION_ENVELOPE_BYTES
  ) {
    throw new TypeError("Authorization envelope has an invalid size");
  }
  const segments = compactJws.split(".");
  if (segments.length !== 3) throw new TypeError("Authorization envelope must be compact JWS");
  const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];
  const header = parseObject(decodeBase64Url(encodedHeader, "JWS header"), "JWS header");
  const payload = parseObject(decodeBase64Url(encodedPayload, "JWS payload"), "JWS payload");
  decodeBase64Url(encodedSignature, "JWS signature");
  if (
    header.alg !== "EdDSA" ||
    header.typ !== AUTHORIZATION_ENVELOPE_TYPE ||
    typeof header.kid !== "string" ||
    header.kid.length === 0 ||
    Object.keys(header).some((key) => !["alg", "kid", "typ"].includes(key))
  ) {
    throw new TypeError("Authorization envelope has an unsupported protected header");
  }
  if (Buffer.from(canonicalJson(header), "utf8").toString("base64url") !== encodedHeader) {
    throw new TypeError("Authorization envelope protected header is not canonical JSON");
  }
  return {
    header: {
      alg: "EdDSA",
      kid: header.kid,
      typ: AUTHORIZATION_ENVELOPE_TYPE,
    },
    payload,
  };
}

export function verifyAuthorizationEnvelopeSignature(
  compactJws: string,
  publicJwk: Record<string, unknown>,
): ParsedAuthorizationEnvelope {
  const parsed = parseAuthorizationEnvelope(compactJws);
  const allowedJwkFields = new Set(["alg", "crv", "key_ops", "kid", "kty", "use", "x"]);
  if (
    publicJwk.kty !== "OKP" ||
    publicJwk.crv !== "Ed25519" ||
    !isCanonicalEd25519Coordinate(publicJwk.x) ||
    publicJwk.kid !== parsed.header.kid ||
    (publicJwk.use !== undefined && publicJwk.use !== "sig") ||
    (publicJwk.alg !== undefined && publicJwk.alg !== "EdDSA") ||
    (publicJwk.key_ops !== undefined &&
      (!Array.isArray(publicJwk.key_ops) ||
        publicJwk.key_ops.length !== 1 ||
        publicJwk.key_ops[0] !== "verify")) ||
    Object.keys(publicJwk).some((field) => !allowedJwkFields.has(field))
  ) {
    throw new TypeError("Authorization envelope verification key is incompatible");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = compactJws.split(".") as [
    string,
    string,
    string,
  ];
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey({ key: publicJwk, format: "jwk" } as Parameters<
      typeof createPublicKey
    >[0]);
  } catch {
    throw new TypeError("Authorization envelope verification key is invalid");
  }
  const signature = decodeBase64Url(encodedSignature, "JWS signature");
  if (
    signature.length !== 64 ||
    !verify(
      null,
      Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"),
      publicKey,
      signature,
    )
  ) {
    throw new TypeError("Authorization envelope signature is invalid");
  }
  if (
    Buffer.from(canonicalJson(parsed.payload), "utf8").toString("base64url") !== encodedPayload
  ) {
    throw new TypeError("Authorization envelope payload is not canonical JSON");
  }
  return parsed;
}
