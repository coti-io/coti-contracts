/**
 * Prefer native solc 0.8.28 on linux-arm64 (wasm viaIR often OOMs).
 * Force wasm for 0.8.20 — the arm64 native cache incorrectly symlinks 0.8.20 → 0.8.28.
 */
import fs from "fs";
import os from "os";
import path from "path";

import { subtask } from "hardhat/config";
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } from "hardhat/builtin-tasks/task-names";

const CACHE = path.join(os.homedir(), ".cache/hardhat-nodejs/compilers-v2");

subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD).setAction(async ({ solcVersion }, _hre, runSuper) => {
  if (process.arch !== "arm64" || process.platform !== "linux") {
    return runSuper({ solcVersion });
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

  return runSuper({ solcVersion });
});
