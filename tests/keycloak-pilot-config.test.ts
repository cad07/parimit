import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";

const repositoryRoot = new URL("../", import.meta.url);
const composeUrl = new URL("deploy/keycloak/docker-compose.yml", repositoryRoot);
const realmUrl = new URL("deploy/keycloak/parimit-pilot-realm.json", repositoryRoot);
const environmentUrl = new URL("deploy/keycloak/pilot.env.template", repositoryRoot);
const localIgnoreUrl = new URL("deploy/keycloak/.gitignore", repositoryRoot);
const decisionUrl = new URL(
  "docs/decisions/0003-keycloak-local-pilot.md",
  repositoryRoot,
);
const workflowUrl = new URL(".github/workflows/keycloak-pilot.yml", repositoryRoot);
const dockerIgnoreUrl = new URL(".dockerignore", repositoryRoot);
const dockerfileUrl = new URL("Dockerfile", repositoryRoot);
const runnerUrl = new URL("scripts/run-keycloak-pilot.ts", repositoryRoot);
const bootstrapUrl = new URL("scripts/bootstrap-keycloak-pilot.ts", repositoryRoot);
const ainxtAdapterUrl = new URL("integrations/ainxt/adapter.ts", repositoryRoot);
const keycloakReadmeUrl = new URL("deploy/keycloak/README.md", repositoryRoot);

const KEYCLOAK_IMAGE =
  "quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c";
const NODE_IMAGE =
  "node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6";
const RESOURCE_CLIENT = "parimit-pilot";
const ACCESS_SCOPE = "parimit-api-access";
const HUMAN_CLIENT = "parimit-human-cli";
const WORKLOAD_CLIENTS = new Set([
  "parimit-agent-workload",
  "parimit-consumer-workload",
]);
const PARIMIT_ROLES = new Set([
  "parimit-pilot-agent",
  "parimit-pilot-reviewer",
  "parimit-pilot-consumer",
  "parimit-pilot-admin",
]);
const PILOT_ALLOWED_PAYEES =
  "merchant_pilot_001,merchant_pilot_002,demo-coffee-merchant";

type JsonObject = Record<string, unknown>;

function object(value: unknown, label: string): JsonObject {
  assert.equal(typeof value, "object", `${label} must be an object`);
  assert.notEqual(value, null, `${label} must not be null`);
  assert.equal(Array.isArray(value), false, `${label} must not be an array`);
  return value as JsonObject;
}

function objects(value: unknown, label: string): JsonObject[] {
  assert.ok(Array.isArray(value), `${label} must be an array`);
  return value.map((entry, index) => object(entry, `${label}[${index}]`));
}

function strings(value: unknown, label: string): string[] {
  assert.ok(Array.isArray(value), `${label} must be an array`);
  for (const entry of value) assert.equal(typeof entry, "string", `${label} must contain strings`);
  return value as string[];
}

function property(value: JsonObject, name: string, label: string): string {
  assert.equal(typeof value[name], "string", `${label}.${name} must be a string`);
  return value[name] as string;
}

function env(text: string, name: string): string {
  const matches = text
    .split(/\r?\n/u)
    .filter((line) => !line.trimStart().startsWith("#"))
    .filter((line) => line.startsWith(`${name}=`));
  assert.equal(matches.length, 1, `${name} must appear exactly once in pilot.env.template`);
  return matches[0]!.slice(name.length + 1);
}

function mapperConfig(mapper: JsonObject): JsonObject {
  return object(mapper.config, `mapper ${String(mapper.name)} config`);
}

function git(...arguments_: string[]): string {
  return execFileSync("git", arguments_, {
    cwd: decodeURIComponent(repositoryRoot.pathname),
    encoding: "utf8",
  }).trim();
}

function forbiddenSecretFields(value: unknown, path = "realm"): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => forbiddenSecretFields(entry, `${path}[${index}]`));
  }
  if (typeof value !== "object" || value === null) return [];

  const findings: string[] = [];
  const record = value as JsonObject;
  for (const [key, child] of Object.entries(record)) {
    const lower = key.toLocaleLowerCase("en-US");
    const isRuntimePlaceholder =
      typeof child === "string" && /^\$\{[A-Z][A-Z0-9_]+\}$/u.test(child);
    if (
      ((lower === "secret" || lower === "password") && !isRuntimePlaceholder) ||
      lower === "privatekey" ||
      lower === "private_key" ||
      (key === "d" && typeof record.kty === "string")
    ) {
      findings.push(`${path}.${key}`);
    }
    findings.push(...forbiddenSecretFields(child, `${path}.${key}`));
  }
  return findings;
}

test("Keycloak and Parimit containers are digest-pinned, hardened, TLS-only, and loopback-published", async () => {
  const compose = await readFile(composeUrl, "utf8");
  const environment = await readFile(environmentUrl, "utf8");
  const dockerfile = await readFile(dockerfileUrl, "utf8");
  const runner = await readFile(runnerUrl, "utf8");
  const keycloakReadme = await readFile(keycloakReadmeUrl, "utf8");

  assert.ok(compose.includes(`image: ${KEYCLOAK_IMAGE}`), "Keycloak image must use the reviewed digest");
  assert.doesNotMatch(compose, /quay\.io\/keycloak\/keycloak:(?:latest|nightly)\b/iu);
  assert.match(dockerfile, new RegExp(`^FROM ${NODE_IMAGE.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}$`, "mu"));

  assert.match(compose, /["']127\.0\.0\.1:8443:8443["']/u);
  assert.match(compose, /["']127\.0\.0\.1:8787:8787["']/u);
  assert.deepEqual(
    new Set(
      [...compose.matchAll(/^\s*-\s*["']?([^"'\s]+:\d{2,5}:\d{2,5})["']?\s*$/gmu)]
        .map((match) => match[1]),
    ),
    new Set(["127.0.0.1:8443:8443", "127.0.0.1:8787:8787"]),
  );
  assert.doesNotMatch(compose, /^\s*-\s*target\s*:/gmu, "long-form port publications require review");
  assert.doesNotMatch(compose, /^\s*-\s*["']?(?:0\.0\.0\.0|\[::\]):\d+:/gmu);
  assert.doesNotMatch(compose, /^\s*-\s*["']?\d{2,5}:\d{2,5}["']?\s*$/gmu);

  for (const forbidden of [
    /^\s*privileged\s*:\s*(?:true|yes|1)\s*$/gimu,
    /^\s*network_mode\s*:\s*["']?host["']?\s*$/gimu,
    /^\s*pid\s*:\s*["']?host["']?\s*$/gimu,
    /^\s*ipc\s*:\s*["']?host["']?\s*$/gimu,
    /\/var\/run\/docker\.sock/giu,
    /^\s*cap_add\s*:/gimu,
  ]) {
    assert.doesNotMatch(compose, forbidden);
  }
  assert.match(compose, /no-new-privileges:true/u);
  assert.match(compose, /cap_drop:\s*\n\s*-\s*ALL/u);

  assert.match(compose, /KC_HTTPS_KEY_STORE_FILE:\s*\/run\/secrets\/keycloak\.p12\s*$/mu);
  assert.match(compose, /KC_HTTPS_KEY_STORE_PASSWORD:\s*"\$\{KEYCLOAK_HTTPS_KEYSTORE_PASSWORD:/u);
  assert.match(compose, /KC_HTTPS_KEY_STORE_TYPE:\s*PKCS12\s*$/mu);
  assert.doesNotMatch(compose, /KC_HTTPS_CERTIFICATE_(?:FILE|KEY_FILE)/u);
  assert.match(compose, /NODE_EXTRA_CA_CERTS/u);
  assert.match(compose, /KC_HOSTNAME:\s*https:\/\/localhost:8443\s*$/mu);
  assert.match(compose, /^\s*pilot-local:\s*$/mu);
  assert.match(compose, /^\s*driver:\s*bridge\s*$/mu);
  assert.doesNotMatch(compose, /^\s*internal:\s*true\s*$/mu);
  assert.doesNotMatch(compose, /^\s*KC_HTTP_ENABLED\s*:\s*["']?(?:true|yes|1)["']?\s*$/gimu);
  assert.match(runner, /minimum_version:\s*"28\.3\.3"/u);
  assert.doesNotMatch(runner, /--compose-file|--pilot-env-file|--no-start/u);
  assert.match(keycloakReadme, /Docker Engine\s+28\.3\.3 or newer/iu);
  assert.match(keycloakReadme, /DOCKER_INSECURE_NO_IPTABLES_RAW=1/u);

  const parimitBlock = compose.split("\n  parimit:\n")[1]?.split("\nnetworks:\n")[0];
  assert.ok(parimitBlock, "Parimit Compose service block must be present");
  assert.match(parimitBlock, /source:\s*local_ca_certificate/u);
  assert.doesNotMatch(parimitBlock, /source:\s*keycloak_keystore/u);

  assert.match(compose, /PARIMIT_AUTH_MODE\s*:\s*["']?oidc["']?\s*$/mu);
  assert.match(compose, /PARIMIT_DEMO_MODE\s*:\s*["']?false["']?\s*$/mu);
  assert.match(compose, /PARIMIT_OIDC_ISSUER:\s*https:\/\/localhost:8443\/realms\/parimit-pilot\s*$/mu);
  assert.match(
    compose,
    /PARIMIT_OIDC_JWKS_URI:\s*https:\/\/keycloak:8443\/realms\/parimit-pilot\/protocol\/openid-connect\/certs\s*$/mu,
  );
  assert.match(compose, /PARIMIT_OIDC_AUDIENCE:\s*parimit-pilot\s*$/mu);
  assert.match(compose, /PARIMIT_OIDC_ROLE_CLAIM:\s*roles\s*$/mu);
  const roleMapping = compose.match(/PARIMIT_OIDC_ROLE_MAPPING:\s*'([^']+)'/u);
  assert.ok(roleMapping, "Parimit role mapping must be a fixed JSON object");
  assert.deepEqual(JSON.parse(roleMapping[1]!) as unknown, {
    "parimit-pilot-agent": "agent",
    "parimit-pilot-reviewer": "approver",
    "parimit-pilot-consumer": "consumer",
    "parimit-pilot-admin": "admin",
  });
  assert.equal(env(environment, "PARIMIT_AUTH_MODE"), "oidc");
  assert.equal(env(environment, "PARIMIT_DEMO_MODE"), "false");
  assert.equal(env(environment, "PARIMIT_OIDC_ISSUER"), "https://localhost:8443/realms/parimit-pilot");
  assert.equal(
    env(environment, "PARIMIT_OIDC_JWKS_URI"),
    "https://keycloak:8443/realms/parimit-pilot/protocol/openid-connect/certs",
  );
  assert.equal(env(environment, "PARIMIT_OIDC_AUDIENCE"), RESOURCE_CLIENT);
  assert.equal(env(environment, "PARIMIT_OIDC_ROLE_CLAIM"), "roles");
  assert.equal(env(environment, "KEYCLOAK_HTTPS_KEYSTORE_PASSWORD"), "");

  for (const line of environment.split(/\r?\n/u)) {
    const assignment = line.match(/^([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY_PEM_BASE64))=(.*)$/u);
    if (assignment) {
      assert.equal(assignment[2], "", `${assignment[1]} must be blank in the committed template`);
    }
  }
});

test("Keycloak policy admits the bounded AiNxt coffee fixture while mobility stays denied", async () => {
  const [compose, environment, bootstrap, ainxtAdapter, keycloakReadme] = await Promise.all([
    readFile(composeUrl, "utf8"),
    readFile(environmentUrl, "utf8"),
    readFile(bootstrapUrl, "utf8"),
    readFile(ainxtAdapterUrl, "utf8"),
    readFile(keycloakReadmeUrl, "utf8"),
  ]);

  assert.equal(env(environment, "PARIMIT_ALLOWED_PAYEES"), PILOT_ALLOWED_PAYEES);
  assert.equal(env(environment, "PARIMIT_PER_TX_LIMIT"), "100000");
  assert.ok(
    compose.includes(
      `PARIMIT_ALLOWED_PAYEES: "\${PARIMIT_ALLOWED_PAYEES:-${PILOT_ALLOWED_PAYEES}}"`,
    ),
    "Compose must preserve the same synthetic allowlist default",
  );
  assert.ok(
    bootstrap.includes(`"${PILOT_ALLOWED_PAYEES}"`),
    "bootstrap must generate the same synthetic allowlist",
  );
  assert.match(
    ainxtAdapter,
    /coffee_order: Object\.freeze\(\{[\s\S]*?minor: "49900"[\s\S]*?payee_reference: "demo-coffee-merchant"/u,
  );
  assert.match(
    ainxtAdapter,
    /mobility_pass: Object\.freeze\(\{[\s\S]*?minor: "125000"[\s\S]*?payee_reference: "demo-mobility-pass"/u,
  );
  assert.match(keycloakReadme, /`demo-coffee-merchant`/u);
  assert.match(keycloakReadme, /`demo-mobility-pass`[\s\S]*exceeds that\s+ceiling/u);
  assert.equal(PILOT_ALLOWED_PAYEES.split(",").includes("demo-mobility-pass"), false);
});

test("realm emits one exact access-token audience and top-level Parimit role claim", async () => {
  const realmText = await readFile(realmUrl, "utf8");
  const realm = object(JSON.parse(realmText) as unknown, "realm");
  assert.equal(realm.realm, "parimit-pilot");
  assert.equal(realm.sslRequired, "all");
  assert.equal(realm.defaultSignatureAlgorithm, "RS256");
  assert.equal(realm.accessTokenLifespan, 300);
  assert.equal(realm.accessTokenLifespanForImplicitFlow, 0);

  const clientScopes = objects(realm.clientScopes, "realm.clientScopes");
  const accessScope = clientScopes.find((scope) => scope.name === ACCESS_SCOPE);
  assert.ok(accessScope, `${ACCESS_SCOPE} client scope is required`);
  const mappers = objects(accessScope.protocolMappers, `${ACCESS_SCOPE}.protocolMappers`);

  const roleMappers = mappers.filter((mapper) => {
    const config = mapperConfig(mapper);
    return config["claim.name"] === "roles";
  });
  assert.equal(roleMappers.length, 1, "exactly one top-level roles mapper is required");
  const roleMapper = roleMappers[0]!;
  const roleConfig = mapperConfig(roleMapper);
  assert.equal(roleMapper.protocolMapper, "oidc-usermodel-client-role-mapper");
  assert.equal(roleConfig["claim.name"], "roles");
  assert.equal(roleConfig["jsonType.label"], "String");
  assert.equal(roleConfig.multivalued, "true");
  assert.equal(roleConfig["access.token.claim"], "true");
  assert.equal(roleConfig["id.token.claim"], "false");
  assert.equal(roleConfig["userinfo.token.claim"], "false");
  assert.equal(roleConfig["usermodel.clientRoleMapping.clientId"], RESOURCE_CLIENT);
  assert.equal(roleConfig["usermodel.clientRoleMapping.rolePrefix"], "");

  const audienceMappers = mappers.filter(
    (mapper) => mapper.protocolMapper === "oidc-audience-mapper",
  );
  assert.equal(audienceMappers.length, 1, "exactly one API audience mapper is required");
  const audienceMapper = audienceMappers[0]!;
  const audienceConfig = mapperConfig(audienceMapper);
  assert.equal(audienceConfig["included.client.audience"], RESOURCE_CLIENT);
  assert.equal(audienceConfig["access.token.claim"], "true");
  assert.equal(audienceConfig["id.token.claim"], "false");

  const usernameMappers = mappers.filter((mapper) => {
    const config = mapperConfig(mapper);
    return config["claim.name"] === "preferred_username";
  });
  assert.equal(usernameMappers.length, 1, "exactly one preferred_username mapper is required");
  const usernameMapper = usernameMappers[0]!;
  const usernameConfig = mapperConfig(usernameMapper);
  assert.equal(usernameMapper.protocolMapper, "oidc-usermodel-property-mapper");
  assert.equal(usernameConfig["user.attribute"], "username");
  assert.equal(usernameConfig["access.token.claim"], "true");
  assert.equal(usernameConfig["id.token.claim"], "false");

  const clients = objects(realm.clients, "realm.clients");
  for (const client of clients) {
    const clientId = property(client, "clientId", "realm client");
    assert.equal(client.directAccessGrantsEnabled, false, `${clientId} must disable direct grants`);
    assert.equal(client.implicitFlowEnabled, false, `${clientId} must disable implicit flow`);
    assert.equal(client.standardFlowEnabled, false, `${clientId} must disable browser code flow`);
    assert.equal(client.fullScopeAllowed, false, `${clientId} must not inherit full scope`);
  }
  for (const clientId of [...WORKLOAD_CLIENTS, HUMAN_CLIENT]) {
    const client = clients.find((candidate) => candidate.clientId === clientId);
    assert.ok(client, `${clientId} must exist`);
    assert.ok(
      strings(client.defaultClientScopes, `${clientId}.defaultClientScopes`).includes(ACCESS_SCOPE),
      `${clientId} must receive ${ACCESS_SCOPE}`,
    );
  }

  const definedRoles = new Set<string>();
  const realmRoles = object(realm.roles ?? {}, "realm.roles");
  const clientRoleSets = object(realmRoles.client, "realm.roles.client");
  for (const role of objects(clientRoleSets[RESOURCE_CLIENT], "realm.roles.client.parimit-pilot")) {
    definedRoles.add(property(role, "name", "Parimit client role"));
  }
  assert.deepEqual(definedRoles, PARIMIT_ROLES);

  const clientScopeMappings = object(realm.clientScopeMappings, "realm.clientScopeMappings");
  const accessScopeMappings = objects(
    clientScopeMappings[RESOURCE_CLIENT],
    `realm.clientScopeMappings.${RESOURCE_CLIENT}`,
  );
  assert.equal(accessScopeMappings.length, 1);
  assert.equal(accessScopeMappings[0]!.clientScope, ACCESS_SCOPE);
  assert.equal(accessScopeMappings[0]!.client, undefined);
  assert.deepEqual(
    new Set(strings(accessScopeMappings[0]!.roles, `${ACCESS_SCOPE}.roles`)),
    PARIMIT_ROLES,
  );
});

test("only agent and consumer are service accounts; reviewer and admin require interactive device users", async () => {
  const realm = object(JSON.parse(await readFile(realmUrl, "utf8")) as unknown, "realm");
  const clients = objects(realm.clients, "realm.clients");

  const serviceAccountClients = new Set(
    clients
      .filter((client) => client.serviceAccountsEnabled === true)
      .map((client) => property(client, "clientId", "service-account client")),
  );
  assert.deepEqual(serviceAccountClients, WORKLOAD_CLIENTS);

  for (const client of clients) {
    assert.notEqual(
      client.directAccessGrantsEnabled,
      true,
      `${String(client.clientId)} must not enable the password/direct grant`,
    );
    assert.notEqual(client.implicitFlowEnabled, true, `${String(client.clientId)} must not enable implicit flow`);
  }

  const humanClient = clients.find((client) => client.clientId === HUMAN_CLIENT);
  assert.ok(humanClient, `${HUMAN_CLIENT} must exist`);
  assert.equal(humanClient.publicClient, true);
  assert.equal(humanClient.serviceAccountsEnabled, false);
  const humanAttributes = object(humanClient.attributes, `${HUMAN_CLIENT}.attributes`);
  assert.equal(humanAttributes["oauth2.device.authorization.grant.enabled"], "true");

  const users = objects(realm.users, "realm.users");
  const expectedHumans = new Map([
    ["pilot-reviewer", "parimit-pilot-reviewer"],
    ["pilot-admin", "parimit-pilot-admin"],
  ]);
  for (const [username, expectedRole] of expectedHumans) {
    const user = users.find((candidate) => candidate.username === username);
    assert.ok(user, `${username} must exist`);
    assert.equal(user.enabled, true);
    const requiredActions = new Set(strings(user.requiredActions, `${username}.requiredActions`));
    assert.ok(requiredActions.has("UPDATE_PASSWORD"), `${username} must replace its generated password`);
    assert.ok(requiredActions.has("CONFIGURE_TOTP"), `${username} must configure TOTP`);
    const clientRoles = object(user.clientRoles, `${username}.clientRoles`);
    assert.deepEqual(clientRoles[RESOURCE_CLIENT], [expectedRole]);
  }

  for (const user of users) {
    const username = property(user, "username", "realm user");
    const clientRoles =
      user.clientRoles === undefined ? {} : object(user.clientRoles, `${username}.clientRoles`);
    const roles = new Set(
      clientRoles[RESOURCE_CLIENT] === undefined
        ? []
        : strings(clientRoles[RESOURCE_CLIENT], `${username}.clientRoles.${RESOURCE_CLIENT}`),
    );
    if (roles.has("parimit-pilot-reviewer") || roles.has("parimit-pilot-admin")) {
      assert.ok(expectedHumans.has(username), `${username} must not carry a human decision role`);
    }
    if (username.startsWith("service-account-")) {
      assert.ok(
        username === "service-account-parimit-agent-workload" ||
          username === "service-account-parimit-consumer-workload",
        `${username} is an unexpected service identity`,
      );
      assert.equal(roles.has("parimit-pilot-reviewer"), false);
      assert.equal(roles.has("parimit-pilot-admin"), false);
      assert.deepEqual(
        roles,
        username === "service-account-parimit-agent-workload"
          ? new Set(["parimit-pilot-agent"])
          : new Set(["parimit-pilot-consumer"]),
      );
    }
  }
  assert.equal(users.some((user) => user.username === "pilot-bootstrap-admin"), false);
});

test("realm and tracked profile contain no literal credential or private-key material", async () => {
  const realmText = await readFile(realmUrl, "utf8");
  const realm = JSON.parse(realmText) as unknown;
  assert.deepEqual(forbiddenSecretFields(realm), []);

  const realmObject = object(realm, "realm");
  const clients = objects(realmObject.clients, "realm.clients");
  assert.equal(
    clients.find((client) => client.clientId === "parimit-agent-workload")?.secret,
    "${PARIMIT_AGENT_CLIENT_SECRET}",
  );
  assert.equal(
    clients.find((client) => client.clientId === "parimit-consumer-workload")?.secret,
    "${PARIMIT_CONSUMER_CLIENT_SECRET}",
  );
  const users = objects(realmObject.users, "realm.users");
  const expectedPasswordPlaceholders = new Map([
    ["pilot-reviewer", "${PARIMIT_REVIEWER_INITIAL_PASSWORD}"],
    ["pilot-admin", "${PARIMIT_ADMIN_INITIAL_PASSWORD}"],
  ]);
  for (const [username, placeholder] of expectedPasswordPlaceholders) {
    const user = users.find((candidate) => candidate.username === username);
    assert.ok(user, `${username} must exist`);
    const credentials = objects(user.credentials, `${username}.credentials`);
    assert.equal(credentials.length, 1);
    assert.deepEqual(credentials[0], { type: "password", value: placeholder, temporary: true });
  }
  for (const user of users) {
    if (expectedPasswordPlaceholders.has(String(user.username))) continue;
    assert.equal(user.credentials, undefined, `${String(user.username)} must not have credentials`);
  }

  const privateKeyMarker = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");
  assert.equal(realmText.includes(privateKeyMarker), false);
  assert.doesNotMatch(realmText, /"(?:p|q|dp|dq|qi|oth|k)"\s*:/u);

  const tracked = git("ls-files", "--", "deploy/keycloak").split(/\r?\n/u).filter(Boolean);
  assert.equal(tracked.some((path) => path.startsWith("deploy/keycloak/runtime/")), false);
  assert.equal(tracked.includes("deploy/keycloak/.env.local"), false);
  assert.equal(
    tracked.some((path) => /\.(?:key|p12|pfx|jks|keystore)$/iu.test(path)),
    false,
    "private-key and keystore files must never be tracked",
  );

  const ignore = await readFile(localIgnoreUrl, "utf8");
  const rules = new Set(
    ignore
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line !== "" && !line.startsWith("#")),
  );
  assert.ok(rules.has("runtime/"), "runtime/ must be ignored");
  assert.ok(rules.has(".env.local"), ".env.local must be ignored");

  const ignored = new Set(
    git("check-ignore", "deploy/keycloak/runtime/secret-probe", "deploy/keycloak/.env.local")
      .split(/\r?\n/u)
      .filter(Boolean),
  );
  assert.ok(ignored.has("deploy/keycloak/runtime/secret-probe"));
  assert.ok(ignored.has("deploy/keycloak/.env.local"));

  const dockerIgnore = new Set(
    (await readFile(dockerIgnoreUrl, "utf8"))
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line !== "" && !line.startsWith("#")),
  );
  assert.ok(
    dockerIgnore.has("deploy/keycloak/runtime/"),
    "generated runtime secrets must not enter the Docker build context",
  );
  assert.ok(
    dockerIgnore.has("deploy/keycloak/.env.local"),
    "the generated pilot environment must not enter the Docker build context",
  );
});

test("governance record preserves the non-human automation and no-payment boundaries", async () => {
  const decision = await readFile(decisionUrl, "utf8");
  assert.match(decision, /CI may validate configuration and may exercise agent and consumer/iu);
  assert.match(decision, /must never approve or reject a proposal/iu);
  assert.match(decision, /interactive human reviewer/iu);
  assert.match(decision, /two distinct human OIDC\s+subjects/iu);
  assert.match(decision, /no\s+payment connector/iu);
  assert.match(decision, /not supplied, endorsed or certified by NPCI/iu);
});

test("CI runs only the explicitly workload-scoped live smoke", async () => {
  const workflow = await readFile(workflowUrl, "utf8");
  assert.match(workflow, /^\s*runs-on:\s*ubuntu-26\.04\s*$/mu);
  for (const guardedPath of [
    ".dockerignore",
    "Dockerfile",
    "package.json",
    "src/**",
    "deploy/keycloak/**",
    "scripts/*keycloak-pilot*",
    "tests/keycloak-pilot-config.test.ts",
  ]) {
    assert.ok(
      workflow.includes(`- "${guardedPath}"`),
      `workflow path filters must include ${guardedPath}`,
    );
  }
  const runnerCommands = workflow
    .split(/\r?\n/u)
    .filter((line) => line.includes("scripts/run-keycloak-pilot.ts"));
  assert.deepEqual(runnerCommands, [
    "        run: node --experimental-strip-types scripts/run-keycloak-pilot.ts --workload-smoke",
  ]);
  assert.match(workflow, /agent\/consumer workload authentication smoke/iu);
  assert.match(workflow, /does not acquire reviewer or administrator tokens/iu);
  assert.match(workflow, /or certify human pilot acceptance/iu);
});
