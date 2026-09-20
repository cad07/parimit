#!/usr/bin/env node

import { createHash, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..");
const deploymentDirectory = join(repositoryRoot, "deploy", "keycloak");
const runtimeDirectory = join(deploymentDirectory, "runtime");
const tlsDirectory = join(runtimeDirectory, "tls");
const reportsDirectory = join(runtimeDirectory, "reports");

const environmentFile = join(deploymentDirectory, ".env.local");
const caCertificateFile = join(tlsDirectory, "local-ca.pem");
const tlsKeyStoreFile = join(tlsDirectory, "keycloak.p12");
const envelopePrivateKeyFile = join(runtimeDirectory, "envelope-private-key.pem");
const humanLoginFile = join(runtimeDirectory, "human-logins.txt");

const managedFiles = [
  environmentFile,
  caCertificateFile,
  tlsKeyStoreFile,
  envelopePrivateKeyFile,
  humanLoginFile,
] as const;

function usage(): string {
  return `Usage: node --experimental-strip-types scripts/bootstrap-keycloak-pilot.ts [--force]

Generate the protected local assets used by deploy/keycloak/docker-compose.yml.

  --force  Replace only the managed pilot files. Docker volumes are untouched.
           If interrupted, rerun --force before using the stack; never use a
           partially rotated trust set with existing volumes.
  --help   Show this help text.
`;
}

function parseArguments(arguments_: readonly string[]): { force: boolean } {
  let force = false;
  for (const argument of arguments_) {
    if (argument === "--force") {
      force = true;
    } else if (argument === "--help" || argument === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return { force };
}

function run(
  command: string,
  arguments_: readonly string[],
  options: { capture?: boolean; cwd?: string } = {},
): string {
  const result = spawnSync(command, [...arguments_], {
    cwd: options.cwd ?? repositoryRoot,
    encoding: "utf8",
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : ["ignore", "ignore", "pipe"],
  });
  if (result.error) {
    throw new Error(`${command} is unavailable: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const diagnostic = String(result.stderr ?? "")
      .split("\n")
      .filter(Boolean)
      .slice(-3)
      .join(" ")
      .slice(0, 500);
    throw new Error(`${command} failed${diagnostic ? `: ${diagnostic}` : ""}`);
  }
  return String(result.stdout ?? "");
}

async function existingKind(path: string): Promise<"missing" | "file" | "directory" | "symlink" | "other"> {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) return "symlink";
    if (stat.isFile()) return "file";
    if (stat.isDirectory()) return "directory";
    return "other";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing";
    throw error;
  }
}

async function ensureSafeDirectory(path: string, restrictPermissions = true): Promise<void> {
  const kind = await existingKind(path);
  if (kind === "symlink" || kind === "file" || kind === "other") {
    throw new Error(`Refusing unsafe directory path: ${relative(repositoryRoot, path)}`);
  }
  if (kind === "missing") {
    await mkdir(path, { recursive: true, mode: restrictPermissions ? 0o700 : 0o755 });
  }
  if (restrictPermissions) await chmod(path, 0o700);
}

function assertGitIgnored(path: string): void {
  const repositoryRelativePath = relative(repositoryRoot, path);
  const result = spawnSync("git", ["check-ignore", "--quiet", "--", repositoryRelativePath], {
    cwd: repositoryRoot,
    stdio: "ignore",
  });
  if (result.error) throw new Error(`git is unavailable: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(
      `Refusing to create sensitive file because it is not git-ignored: ${repositoryRelativePath}`,
    );
  }
}

function secret(bytes = 48): string {
  return randomBytes(bytes).toString("base64url");
}

function environmentLine(name: string, value: string): string {
  if (/\r|\n/.test(value)) throw new Error(`Generated ${name} contains a newline`);
  return `${name}=${value}`;
}

async function installFile(
  source: string,
  destination: string,
  force: boolean,
  mode: 0o600 | 0o644,
): Promise<void> {
  const currentKind = await existingKind(destination);
  if (currentKind === "symlink" || currentKind === "directory" || currentKind === "other") {
    throw new Error(`Refusing unsafe managed path: ${relative(repositoryRoot, destination)}`);
  }
  if (currentKind === "file" && !force) {
    throw new Error(
      `Managed pilot file already exists: ${relative(repositoryRoot, destination)}. ` +
        "Use --force only when intentionally rotating the complete local pilot trust set.",
    );
  }

  const data = await readFile(source);
  const temporaryDestination = `${destination}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(temporaryDestination, data, { flag: "wx", mode });
  await chmod(temporaryDestination, mode);
  await rename(temporaryDestination, destination);
  await chmod(destination, mode);
}

async function main(): Promise<void> {
  process.umask(0o077);
  const { force } = parseArguments(process.argv.slice(2));

  await ensureSafeDirectory(deploymentDirectory, false);
  await ensureSafeDirectory(runtimeDirectory);
  await ensureSafeDirectory(tlsDirectory);
  await ensureSafeDirectory(reportsDirectory);

  for (const path of managedFiles) assertGitIgnored(path);

  for (const path of managedFiles) {
    const kind = await existingKind(path);
    if (kind !== "missing" && !force) {
      throw new Error(
        `Pilot assets already exist (${relative(repositoryRoot, path)}). ` +
          "Nothing was changed. Pass --force only for an intentional full local rotation.",
      );
    }
    if (kind === "symlink" || kind === "directory" || kind === "other") {
      throw new Error(`Refusing unsafe managed path: ${relative(repositoryRoot, path)}`);
    }
  }

  run("openssl", ["version"]);
  const temporaryDirectory = await mkdtemp(join(runtimeDirectory, ".bootstrap-"));
  await chmod(temporaryDirectory, 0o700);

  try {
    const temporaryCaKey = join(temporaryDirectory, "local-ca.key");
    const temporaryCaCertificate = join(temporaryDirectory, "local-ca.pem");
    const temporaryCaConfig = join(temporaryDirectory, "local-ca.cnf");
    const temporaryCaSerial = join(temporaryDirectory, "local-ca.srl");
    const temporaryTlsKey = join(temporaryDirectory, "keycloak.key");
    const temporaryTlsRequest = join(temporaryDirectory, "keycloak.csr");
    const temporaryTlsCertificate = join(temporaryDirectory, "keycloak.crt");
    const temporaryTlsKeyStore = join(temporaryDirectory, "keycloak.p12");
    const temporaryTlsKeyStorePassword = join(temporaryDirectory, "keycloak-p12.password");
    const temporaryExtensions = join(temporaryDirectory, "keycloak-extensions.cnf");
    const temporaryEnvelopeKey = join(temporaryDirectory, "envelope-private-key.pem");
    const temporaryEnvironment = join(temporaryDirectory, ".env.local");
    const temporaryHumanLogin = join(temporaryDirectory, "human-logins.txt");

    await writeFile(
      temporaryCaConfig,
      `[req]\n` +
        `distinguished_name=ca_dn\n` +
        `x509_extensions=ca_extensions\n` +
        `prompt=no\n\n` +
        `[ca_dn]\n` +
        `CN=Parimit Pilot Local CA\n\n` +
        `[ca_extensions]\n` +
        `basicConstraints=critical,CA:TRUE\n` +
        `keyUsage=critical,keyCertSign,cRLSign\n` +
        `subjectKeyIdentifier=hash\n` +
        `authorityKeyIdentifier=keyid:always,issuer\n`,
      { mode: 0o600 },
    );
    run("openssl", ["genrsa", "-out", temporaryCaKey, "3072"]);
    run("openssl", [
      "req",
      "-new",
      "-x509",
      "-key",
      temporaryCaKey,
      "-sha256",
      "-days",
      "30",
      "-config",
      temporaryCaConfig,
      "-extensions",
      "ca_extensions",
      "-out",
      temporaryCaCertificate,
    ]);

    run("openssl", ["genrsa", "-out", temporaryTlsKey, "2048"]);
    run("openssl", [
      "req",
      "-new",
      "-key",
      temporaryTlsKey,
      "-subj",
      "/CN=localhost",
      "-out",
      temporaryTlsRequest,
    ]);
    await writeFile(
      temporaryExtensions,
      `[server_ext]\n` +
        `basicConstraints=critical,CA:FALSE\n` +
        `keyUsage=critical,digitalSignature,keyEncipherment\n` +
        `extendedKeyUsage=serverAuth\n` +
        `subjectAltName=@alt_names\n\n` +
        `[alt_names]\n` +
        `DNS.1=localhost\n` +
        `DNS.2=keycloak\n` +
        `DNS.3=keycloak.localhost\n` +
        `IP.1=127.0.0.1\n`,
      { mode: 0o600 },
    );
    run("openssl", [
      "x509",
      "-req",
      "-in",
      temporaryTlsRequest,
      "-CA",
      temporaryCaCertificate,
      "-CAkey",
      temporaryCaKey,
      "-CAserial",
      temporaryCaSerial,
      "-CAcreateserial",
      "-days",
      "30",
      "-sha256",
      "-extfile",
      temporaryExtensions,
      "-extensions",
      "server_ext",
      "-out",
      temporaryTlsCertificate,
    ]);
    run("openssl", ["verify", "-CAfile", temporaryCaCertificate, temporaryTlsCertificate]);
    const alternativeNames = run(
      "openssl",
      ["x509", "-in", temporaryTlsCertificate, "-noout", "-text"],
      { capture: true },
    );
    for (const expected of ["DNS:localhost", "DNS:keycloak", "IP Address:127.0.0.1"]) {
      if (!alternativeNames.includes(expected)) {
        throw new Error(`Generated TLS certificate is missing required SAN ${expected}`);
      }
    }

    const keyStorePassword = secret(32);
    await writeFile(temporaryTlsKeyStorePassword, `${keyStorePassword}\n`, { mode: 0o600 });
    run("openssl", [
      "pkcs12",
      "-export",
      "-name",
      "keycloak",
      "-inkey",
      temporaryTlsKey,
      "-in",
      temporaryTlsCertificate,
      "-certfile",
      temporaryCaCertificate,
      "-keypbe",
      "AES-256-CBC",
      "-certpbe",
      "AES-256-CBC",
      "-macalg",
      "sha256",
      "-out",
      temporaryTlsKeyStore,
      "-passout",
      `file:${temporaryTlsKeyStorePassword}`,
    ]);
    run("openssl", [
      "pkcs12",
      "-in",
      temporaryTlsKeyStore,
      "-noout",
      "-passin",
      `file:${temporaryTlsKeyStorePassword}`,
    ]);

    const { privateKey } = generateKeyPairSync("ed25519");
    const envelopePrivateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
    await writeFile(temporaryEnvelopeKey, envelopePrivateKeyPem, { mode: 0o600 });
    const envelopePublicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
    const envelopeKeyId = `parimit-pilot-${createHash("sha256")
      .update(envelopePublicDer)
      .digest("hex")
      .slice(0, 16)}`;

    const reviewerPassword = secret(24);
    const adminPassword = secret(24);
    const generatedAt = new Date().toISOString();
    const environment = [
      "# Generated by scripts/bootstrap-keycloak-pilot.ts.",
      "# Sensitive local pilot material. Do not commit, print, or share this file.",
      `# Generated at ${generatedAt}`,
      environmentLine("KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME", "pilot-bootstrap-admin"),
      environmentLine("KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD", secret()),
      environmentLine("KEYCLOAK_HTTPS_KEYSTORE_PASSWORD", keyStorePassword),
      environmentLine("PARIMIT_AGENT_CLIENT_SECRET", secret()),
      environmentLine("PARIMIT_CONSUMER_CLIENT_SECRET", secret()),
      environmentLine("PARIMIT_REVIEWER_INITIAL_PASSWORD", reviewerPassword),
      environmentLine("PARIMIT_ADMIN_INITIAL_PASSWORD", adminPassword),
      environmentLine("PARIMIT_RECEIPT_KEY", secret()),
      environmentLine("PARIMIT_TENANT_ID", "parimit-pilot-local"),
      environmentLine("PARIMIT_ENVELOPE_ISSUER", "urn:parimit:pilot:local"),
      environmentLine("PARIMIT_ENVELOPE_AUDIENCES", "urn:parimit:consumer:pilot-local"),
      environmentLine("PARIMIT_ENVELOPE_TTL_SECONDS", "300"),
      environmentLine("PARIMIT_ENVELOPE_SIGNING_KEY_ID", envelopeKeyId),
      environmentLine(
        "PARIMIT_ENVELOPE_PRIVATE_KEY_PEM_BASE64",
        Buffer.from(envelopePrivateKeyPem, "utf8").toString("base64"),
      ),
      environmentLine("PARIMIT_IMAGE_TAG", "local-unreleased"),
      environmentLine("PARIMIT_PER_TX_LIMIT", "100000"),
      environmentLine("PARIMIT_DAILY_AGENT_LIMIT", "500000"),
      environmentLine("PARIMIT_DUAL_APPROVAL_THRESHOLD", "50000"),
      environmentLine("PARIMIT_INTENT_TTL_SECONDS", "1800"),
      environmentLine("PARIMIT_MAX_EXPIRY_SECONDS", "86400"),
      environmentLine("PARIMIT_ALLOWED_PAYEES", "merchant_pilot_001,merchant_pilot_002"),
      environmentLine("PARIMIT_BLOCKED_PAYEES", "merchant_pilot_blocked"),
      "",
    ].join("\n");
    await writeFile(temporaryEnvironment, environment, { mode: 0o600 });

    const loginInstructions = [
      "PARIMIT LOCAL PILOT HUMAN LOGINS — SENSITIVE",
      "",
      "These accounts are only for the fictional local acceptance pilot.",
      "Use the browser-mediated Device Authorization pages shown by the runner.",
      "Never submit these passwords to Parimit or a token endpoint.",
      "",
      "Reviewer username: pilot-reviewer",
      `Reviewer initial password: ${reviewerPassword}`,
      "",
      "Admin username: pilot-admin",
      `Admin initial password: ${adminPassword}`,
      "",
    ].join("\n");
    await writeFile(temporaryHumanLogin, loginInstructions, { mode: 0o600 });

    const installs: ReadonlyArray<readonly [string, string, 0o600 | 0o644]> = [
      [temporaryEnvironment, environmentFile, 0o600],
      [temporaryCaCertificate, caCertificateFile, 0o644],
      [temporaryTlsKeyStore, tlsKeyStoreFile, 0o644],
      [temporaryEnvelopeKey, envelopePrivateKeyFile, 0o600],
      [temporaryHumanLogin, humanLoginFile, 0o600],
    ];
    for (const [source, destination, mode] of installs) {
      await installFile(source, destination, force, mode);
    }
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }

  process.stdout.write(
    [
      "Local Keycloak pilot assets generated successfully.",
      `Environment: ${relative(repositoryRoot, environmentFile)}`,
      `Local CA: ${relative(repositoryRoot, caCertificateFile)}`,
      `Human login file: ${relative(repositoryRoot, humanLoginFile)}`,
      "Secrets are git-ignored and mode 0600; the public CA and encrypted PKCS#12 are mode 0644.",
      "The raw TLS private key existed only in protected temporary storage and was removed.",
      force
        ? "The managed trust set was rotated. Existing Docker volumes were not changed and may now fail closed. If rotation was interrupted, rerun --force before using the stack."
        : "No secret values were printed.",
      "",
    ].join("\n"),
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown bootstrap failure";
  process.stderr.write(`Keycloak pilot bootstrap failed: ${message}\n`);
  process.exitCode = 1;
});
