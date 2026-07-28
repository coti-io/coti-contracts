#!/usr/bin/env node
/**
 * SoT drift guard wrapper — expects sibling ../pod-ecosystem-integration
 * Override: POD_REPOS_ROOT, POD_DEPLOY_CONFIG
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCOPE = "contracts";
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const reposRoot = path.resolve(process.env.POD_REPOS_ROOT || path.join(repoRoot, ".."));
const checker = path.join(reposRoot, "pod-ecosystem-integration/scripts/sot-drift/check.mjs");

if (!fs.existsSync(checker)) {
  console.error(
    `[check-sot-drift] missing ${checker}\nClone pod-ecosystem-integration as a sibling or set POD_REPOS_ROOT.`
  );
  process.exit(2);
}

const r = spawnSync(
  process.execPath,
  [checker, `--scope=${SCOPE}`, `--repos-root=${reposRoot}`],
  { stdio: "inherit", env: process.env }
);
process.exit(r.status ?? 1);
