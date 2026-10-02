#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";

interface MigrationManifest {
  format: "parimit-postgres-migration-manifest-v1";
  migrations: Array<{
    version: string;
    file: string;
    sha256: string;
  }>;
}

const directory = new URL("../db/postgres/", import.meta.url);
const manifestUrl = new URL("migrations.json", directory);
const manifest = JSON.parse(await readFile(manifestUrl, "utf8")) as MigrationManifest;

if (manifest.format !== "parimit-postgres-migration-manifest-v1") {
  throw new Error("Unsupported PostgreSQL migration manifest format");
}

const files = (await readdir(directory))
  .filter((file) => /^[0-9]{3}_[a-z0-9_]+[.]sql$/.test(file))
  .sort();
const listedFiles = manifest.migrations.map((migration) => migration.file);
if (JSON.stringify(files) !== JSON.stringify(listedFiles)) {
  throw new Error(
    `PostgreSQL migration manifest mismatch: found ${files.join(", ")}; listed ${listedFiles.join(", ")}`,
  );
}

const seenVersions = new Set<string>();
for (const [index, migration] of manifest.migrations.entries()) {
  const expectedVersion = migration.file.slice(0, 3);
  if (
    migration.version !== expectedVersion ||
    !/^[0-9]{3}$/.test(migration.version) ||
    seenVersions.has(migration.version) ||
    (index > 0 && migration.version <= manifest.migrations[index - 1].version)
  ) {
    throw new Error(`Invalid or out-of-order PostgreSQL migration version ${migration.version}`);
  }
  if (!/^[0-9a-f]{64}$/.test(migration.sha256)) {
    throw new Error(`Invalid SHA-256 for PostgreSQL migration ${migration.file}`);
  }
  seenVersions.add(migration.version);
  const bytes = await readFile(new URL(migration.file, directory));
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== migration.sha256) {
    throw new Error(
      `PostgreSQL migration ${migration.file} changed: expected ${migration.sha256}, got ${actual}`,
    );
  }
}

console.log(`PostgreSQL migration manifest check passed (${files.length} consistent entries).`);
