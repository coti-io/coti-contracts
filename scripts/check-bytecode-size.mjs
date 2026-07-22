#!/usr/bin/env node
/**
 * Fail if any production contract's deployedBytecode exceeds the Spurious Dragon create limit (24_576 bytes).
 * Usage: node scripts/check-bytecode-size.mjs
 */
import fs from "node:fs";
import path from "node:path";

const LIMIT = 24_576;
const ROOT = process.cwd();
const ARTIFACTS = path.join(ROOT, "artifacts");

/** Relative artifact dirs that must stay deployable on L1 / COTI. */
const INCLUDE_PREFIXES = [
  path.join("contracts", "pod"),
];

const EXCLUDE_PATH_PARTS = [
  `${path.sep}mocks${path.sep}`,
  `${path.sep}test${path.sep}`,
  `${path.sep}examples${path.sep}`,
];

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(p, out);
    else if (ent.name.endsWith(".json") && !ent.name.endsWith(".dbg.json")) out.push(p);
  }
  return out;
}

function deployedSize(artifactPath) {
  const j = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const raw = j.deployedBytecode?.object ?? j.deployedBytecode ?? "";
  const hex = String(raw).replace(/^0x/i, "");
  if (!hex || hex === "0") return 0;
  return hex.length / 2;
}

const files = walk(ARTIFACTS).filter((abs) => {
  const rel = path.relative(ARTIFACTS, abs);
  if (!INCLUDE_PREFIXES.some((prefix) => rel.startsWith(prefix))) return false;
  if (EXCLUDE_PATH_PARTS.some((part) => abs.includes(part))) return false;
  return true;
});

if (files.length === 0) {
  console.error("No production artifacts found under artifacts/contracts/pod — compile first.");
  process.exit(1);
}

const overs = [];
const rows = [];
for (const abs of files) {
  const n = deployedSize(abs);
  if (n === 0) continue;
  const name = path.basename(abs, ".json");
  rows.push({ name, n });
  if (n > LIMIT) overs.push({ name, n, abs });
}

rows.sort((a, b) => b.n - a.n);
console.log(`Spurious Dragon create limit: ${LIMIT} bytes`);
for (const r of rows.slice(0, 12)) {
  const tag = r.n > LIMIT ? "OVER" : "ok  ";
  console.log(`${tag} ${String(r.n).padStart(5)}  ${r.name}`);
}
if (rows.length > 12) console.log(`… ${rows.length - 12} more under limit`);

if (overs.length) {
  console.error("\nContracts exceeding create size limit:");
  for (const o of overs) console.error(`  ${o.name}: ${o.n} bytes`);
  process.exit(1);
}

console.log(`\nAll ${rows.length} production contracts are within ${LIMIT} bytes.`);
