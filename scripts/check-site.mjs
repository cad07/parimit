import { readFile, stat } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const siteRoot = resolve(repoRoot, "site");
const htmlPath = resolve(siteRoot, "index.html");

const read = (relativePath) => readFile(resolve(siteRoot, relativePath), "utf8");

const html = await read("index.html");
const css = await read("styles.css");
const script = await read("script.js");
const manifest = JSON.parse(await read("manifest.webmanifest"));

const failures = [];
const requireText = (source, text, label) => {
  if (!source.includes(text)) failures.push(`${label} is missing: ${text}`);
};

requireText(html, "moves_money: false", "site boundary");
requireText(html, "No UPI, bank, PSP", "site boundary");
requireText(html, "Hard no-go for real money", "readiness statement");
requireText(html, "Independent software. Public inspiration. No implied endorsement.", "provenance statement");
requireText(html, "101", "alpha.4 test total");
requireText(html, "16/16", "published smoke result");
requireText(html, "no-script-nav", "no-JavaScript navigation fallback");
requireText(css, "prefers-reduced-motion", "reduced-motion support");
requireText(script, "IntersectionObserver", "progressive reveal behavior");

if (manifest.start_url !== "./") {
  failures.push("manifest start_url must remain relative for project Pages");
}

const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
if (duplicates.length > 0) {
  failures.push(`duplicate HTML ids: ${[...new Set(duplicates)].join(", ")}`);
}

const idSet = new Set(ids);
for (const match of html.matchAll(/href="#([^"]+)"/g)) {
  if (!idSet.has(match[1])) failures.push(`missing hash-link target: #${match[1]}`);
}

const localReferences = [];
for (const match of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
  const value = match[1];
  if (value.startsWith("/")) {
    failures.push(`root-relative URL breaks GitHub project Pages: ${value}`);
    continue;
  }
  if (
    value.startsWith("#") ||
    value.startsWith("https://") ||
    value.startsWith("http://localhost") ||
    value.startsWith("mailto:")
  ) {
    continue;
  }

  const clean = value.split(/[?#]/, 1)[0].replace(/^\.\//, "");
  if (clean) localReferences.push(clean);
}

for (const relativePath of [...new Set(localReferences)]) {
  const assetPath = resolve(siteRoot, relativePath);
  if (!assetPath.startsWith(`${siteRoot}${sep}`)) {
    failures.push(`local site reference escapes the published directory: ${relativePath}`);
    continue;
  }

  try {
    const entry = await stat(assetPath);
    if (!entry.isFile()) failures.push(`local site reference is not a file: ${relativePath}`);
  } catch {
    failures.push(`missing local site asset: ${relativePath}`);
  }
}

for (const requiredFile of [".nojekyll", "favicon.svg", "robots.txt", "sitemap.xml"]) {
  try {
    await stat(resolve(siteRoot, requiredFile));
  } catch {
    failures.push(`missing required publishing file: ${requiredFile}`);
  }
}

if (failures.length > 0) {
  console.error("Site check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(
    `Site check passed (${ids.length} ids, ${new Set(localReferences).size} local assets, explicit safety and provenance claims).`,
  );
}
