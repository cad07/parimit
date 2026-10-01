export const KEYCLOAK_CONFIGURED_ACCESS_TOKEN_LIFETIME_SECONDS = 300;

// Keycloak records iat at whole-second precision, then derives exp from a
// later millisecond clock read. A second-boundary rollover can therefore
// encode a configured 300-second token as exp - iat === 301.
export const KEYCLOAK_MAX_ENCODED_ACCESS_TOKEN_LIFETIME_SECONDS = 301;

export function isExpectedKeycloakAccessTokenLifetime(
  issuedAtSeconds: number,
  expiresAtSeconds: number,
): boolean {
  const lifetimeSeconds = expiresAtSeconds - issuedAtSeconds;
  return (
    lifetimeSeconds >= KEYCLOAK_CONFIGURED_ACCESS_TOKEN_LIFETIME_SECONDS &&
    lifetimeSeconds <= KEYCLOAK_MAX_ENCODED_ACCESS_TOKEN_LIFETIME_SECONDS
  );
}
