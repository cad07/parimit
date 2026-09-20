import { canonicalJson, sha256 } from "./crypto.ts";
import type { ActorRole } from "./types.ts";

export const LOCAL_DEMO_IDENTITY_TRUST_DOMAIN =
  "urn:parimit:identity-trust:local-demo-headers-v1";

export interface OidcIdentityTrustConfiguration {
  issuer: string;
  audiences: readonly string[];
  jwksUri: string;
  roleClaim: string;
  roleMapping: Readonly<Record<string, ActorRole>>;
  allowedAlgorithms: readonly string[];
  requiredTokenType: "JWT" | "at+jwt" | null;
  clockSkewSeconds: number;
  maxTokenLifetimeSeconds: number | null;
}

export function oidcIdentityTrustDomainId(
  configuration: OidcIdentityTrustConfiguration,
): string {
  return `sha256:${sha256(
    canonicalJson({
      version: "parimit-oidc-identity-trust-v1",
      issuer: configuration.issuer,
      audiences: [...configuration.audiences].sort(),
      jwks_uri: configuration.jwksUri,
      role_claim: configuration.roleClaim,
      role_mapping: configuration.roleMapping,
      allowed_algorithms: [...configuration.allowedAlgorithms].sort(),
      required_token_type: configuration.requiredTokenType,
      clock_skew_seconds: configuration.clockSkewSeconds,
      max_token_lifetime_seconds: configuration.maxTokenLifetimeSeconds,
    }),
  )}`;
}
