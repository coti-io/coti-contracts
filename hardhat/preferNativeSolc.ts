/**
 * Prefer native / qemu-wrapped solc on linux-arm64 (wasm viaIR often OOMs).
 * Force wasm for 0.8.20 — the arm64 native cache incorrectly symlinks 0.8.20 → 0.8.28.
 *
 * Official soliditylang linux-arm64 builds start at 0.8.31; for 0.8.28 we wrap the
 * linux-amd64 binary with qemu-x86_64-static when available.
 */
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";

import { subtask } from "hardhat/config";
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } from "hardhat/builtin-tasks/task-names";

const CACHE = path.join(os.homedir(), ".cache/hardhat-nodejs/compilers-v2");
const QEMU = "/usr/bin/qemu-x86_64-static";

function writeQemuWrapper(amd64Solc: string, versionLabel: string): string | undefined {
  if (!fs.existsSync(QEMU) || !fs.existsSync(amd64Solc)) {
    return undefined;
  }
  const dir = path.join(CACHE, "linux-arm64");
  fs.mkdirSync(dir, { recursive: true });
  const wrapper = path.join(dir, `solc-linux-arm64-qemu-${versionLabel}`);
  const script = `#!/bin/sh\nexec ${QEMU} ${amd64Solc} "$@"\n`;
  fs.writeFileSync(wrapper, script, { mode: 0o755 });
  const probe = spawnSync(wrapper, ["--version"], { encoding: "utf8" });
  if (probe.status !== 0) {
    return undefined;
  }
  return wrapper;
}

subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD).setAction(async (taskArgs, _hre, runSuper) => {
  const { solcVersion } = taskArgs as { solcVersion: string };

  if (process.arch !== "arm64" || process.platform !== "linux") {
    // Pass full taskArgs (includes required `quiet`) — stripping it causes HH306 on solc download.
    return runSuper(taskArgs);
  }

  if (solcVersion === "0.8.28") {
    const dir = path.join(CACHE, "linux-arm64");
    if (fs.existsSync(dir)) {
      const match = fs
        .readdirSync(dir)
        .find(
          (f) =>
            f.startsWith("solc-linux-arm64-v0.8.28") || f.startsWith("solc-linux-aarch64-v0.8.28")
        );
      if (match) {
        return {
          compilerPath: path.join(dir, match),
          isSolcJs: false,
          version: solcVersion,
          longVersion: "0.8.28+commit.7893614a",
        };
      }
    }

    const amd64 = path.join(CACHE, "linux-amd64", "solc-linux-amd64-v0.8.28+commit.7893614a");
    const wrapper = writeQemuWrapper(amd64, "v0.8.28+commit.7893614a");
    if (wrapper) {
      return {
        compilerPath: wrapper,
        isSolcJs: false,
        version: solcVersion,
        longVersion: "0.8.28+commit.7893614a",
      };
    }
  }

  if (solcVersion === "0.8.20") {
    const wasm = path.join(CACHE, "wasm", "soljson-v0.8.20+commit.a1b79de6.js");
    if (fs.existsSync(wasm)) {
      return {
        compilerPath: wasm,
        isSolcJs: true,
        version: solcVersion,
        longVersion: "0.8.20+commit.a1b79de6",
      };
    }
  }

  return runSuper(taskArgs);
});
