import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { subtask } from "hardhat/config";
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } from "hardhat/builtin-tasks/task-names";
import type { SolcBuild } from "hardhat/types/builtin-tasks/compile";

const NATIVE_SOLC_0_8_28 = join(
  homedir(),
  ".cache/hardhat-nodejs/compilers-v3/linux-arm64/solc-v0.8.28"
);

/** Hardhat 2 falls back to solcjs on linux-arm64 and OOMs on MpcCore; prefer the native 0.8.28 binary. */
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD).setAction(
  async (
    { solcVersion }: { quiet: boolean; solcVersion: string },
    _hre,
    runSuper
  ): Promise<SolcBuild> => {
    if (solcVersion === "0.8.28" && existsSync(NATIVE_SOLC_0_8_28)) {
      return {
        version: solcVersion,
        longVersion: "0.8.28+commit.7893614a.Linux.g++",
        compilerPath: NATIVE_SOLC_0_8_28,
        isSolcJs: false,
      };
    }
    return runSuper();
  }
);
