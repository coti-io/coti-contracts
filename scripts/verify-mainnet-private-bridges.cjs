/**
 * Verify mainnet private tokens + privacy bridges on mainnet.cotiscan.io.
 * Uses existing artifacts/build-info (no compile).
 *
 *   node scripts/verify-mainnet-private-bridges.cjs
 */
const fs = require("fs");
const path = require("path");
const { Interface } = require("ethers");

const BUILD_INFO_PATH = "artifacts/build-info/14a35ceda4d79e418b4c0b920191fca5.json";
const API_BASE = "https://mainnet.cotiscan.io";

const FEE = "0x0B90092a3a638fe52d938133c67c5b447Df9800a";
const RESCUE = "0xcaabe69719468e677ca5a1CC4c1A7edc38c69022";
const ORACLE = "0x830c5112E677459648C1aa7Bc5Dd65A36d71Aa4D";

const PUBLIC = {
  WETH: "0x639aCc80569c5FC83c6FBf2319A6Cc38bBfe26d1",
  WBTC: "0x8C39B1fD0e6260fdf20652Fc436d25026832bfEA",
  USDT: "0xfA6f73446b17A97a56e464256DA54AD43c2Cbc3E",
  USDC_E: "0xf1Feebc4376c68B7003450ae66343Ae59AB37D3C",
  WADA: "0xe757Ca19d2c237AA52eBb1d2E8E4368eeA3eb331",
  gCOTI: "0x7637C7838EC4Ec6b85080F28A678F8E234bB83D1",
};

const PRIVATE = {
  COTI: "0xD2F2692B83C3ecDF2EAa0f7c2632BBd46Ae1cC91",
  WETH: "0x4727FE8D8450CEBcB142331FAc034Cd8d311f0E5",
  WBTC: "0x65449561257ba5756631Aa0d34f07f6457a319be",
  USDT: "0x42107250C3D385ddfABE69ab6de163702040FeB0",
  USDC_E: "0x63C9a1D05471fc8d47C83968725Dcfdcb5410392",
  WADA: "0x3a8b49aAC1dAD86aa45a75231FbeC5bEb810e416",
  gCOTI: "0x394b3c4328160f000763Ca391D07F902926EDaAc",
};

const BRIDGE_ARGS = [FEE, RESCUE, ORACLE];

const JOBS = [
  {
    label: "PrivateCOTI",
    address: PRIVATE.COTI,
    sourcePath: "contracts/token/PrivateERC20/tokens/PrivateCOTI.sol",
    contractName: "PrivateCOTI",
    artifact: "artifacts/contracts/token/PrivateERC20/tokens/PrivateCOTI.sol/PrivateCOTI.json",
    args: [],
  },
  {
    label: "PrivateWrappedEther (p.WETH)",
    address: PRIVATE.WETH,
    sourcePath: "contracts/token/PrivateERC20/tokens/PrivateWrappedEther.sol",
    contractName: "PrivateWrappedEther",
    artifact: "artifacts/contracts/token/PrivateERC20/tokens/PrivateWrappedEther.sol/PrivateWrappedEther.json",
    args: [],
  },
  {
    label: "PrivateWrappedBTC (p.WBTC)",
    address: PRIVATE.WBTC,
    sourcePath: "contracts/token/PrivateERC20/tokens/PrivateWrappedBTC.sol",
    contractName: "PrivateWrappedBTC",
    artifact: "artifacts/contracts/token/PrivateERC20/tokens/PrivateWrappedBTC.sol/PrivateWrappedBTC.json",
    args: [],
  },
  {
    label: "PrivateTetherUSD (p.USDT)",
    address: PRIVATE.USDT,
    sourcePath: "contracts/token/PrivateERC20/tokens/PrivateTetherUSD.sol",
    contractName: "PrivateTetherUSD",
    artifact: "artifacts/contracts/token/PrivateERC20/tokens/PrivateTetherUSD.sol/PrivateTetherUSD.json",
    args: [],
  },
  {
    label: "PrivateBridgedUSDC (p.USDC_E)",
    address: PRIVATE.USDC_E,
    sourcePath: "contracts/token/PrivateERC20/tokens/PrivateBridgedUSDC.sol",
    contractName: "PrivateBridgedUSDC",
    artifact: "artifacts/contracts/token/PrivateERC20/tokens/PrivateBridgedUSDC.sol/PrivateBridgedUSDC.json",
    args: [],
  },
  {
    label: "PrivateWrappedADA (p.WADA)",
    address: PRIVATE.WADA,
    sourcePath: "contracts/token/PrivateERC20/tokens/PrivateWrappedADA.sol",
    contractName: "PrivateWrappedADA",
    artifact: "artifacts/contracts/token/PrivateERC20/tokens/PrivateWrappedADA.sol/PrivateWrappedADA.json",
    args: [],
  },
  {
    label: "PrivateCOTITreasuryGovernanceToken (p.gCOTI)",
    address: PRIVATE.gCOTI,
    sourcePath: "contracts/token/PrivateERC20/tokens/PrivateCOTITreasuryGovernanceToken.sol",
    contractName: "PrivateCOTITreasuryGovernanceToken",
    artifact:
      "artifacts/contracts/token/PrivateERC20/tokens/PrivateCOTITreasuryGovernanceToken.sol/PrivateCOTITreasuryGovernanceToken.json",
    args: [],
  },
  {
    label: "PrivacyBridgeCotiNative",
    address: "0x44D864973392064304dD88E2BDef39fF1ab11b7b",
    sourcePath: "contracts/privacyBridge/PrivacyBridgeCotiNative.sol",
    contractName: "PrivacyBridgeCotiNative",
    artifact: "artifacts/contracts/privacyBridge/PrivacyBridgeCotiNative.sol/PrivacyBridgeCotiNative.json",
    args: [PRIVATE.COTI, ...BRIDGE_ARGS],
  },
  {
    label: "PrivacyBridgeWETH",
    address: "0x7286c83300f0C7131b4006f3cf9F8e44BeB45c13",
    sourcePath: "contracts/privacyBridge/PrivacyBridgeWETH.sol",
    contractName: "PrivacyBridgeWETH",
    artifact: "artifacts/contracts/privacyBridge/PrivacyBridgeWETH.sol/PrivacyBridgeWETH.json",
    args: [PUBLIC.WETH, PRIVATE.WETH, ...BRIDGE_ARGS],
  },
  {
    label: "PrivacyBridgeWBTC",
    address: "0xc3B7EdEe4f1c0A0bA1AcD341e4982371eC869862",
    sourcePath: "contracts/privacyBridge/PrivacyBridgeWBTC.sol",
    contractName: "PrivacyBridgeWBTC",
    artifact: "artifacts/contracts/privacyBridge/PrivacyBridgeWBTC.sol/PrivacyBridgeWBTC.json",
    args: [PUBLIC.WBTC, PRIVATE.WBTC, ...BRIDGE_ARGS],
  },
  {
    label: "PrivacyBridgeUSDT",
    address: "0x7685B473DAF1c6DeD815Ca64C6fa18Da2227440D",
    sourcePath: "contracts/privacyBridge/PrivacyBridgeUSDT.sol",
    contractName: "PrivacyBridgeUSDT",
    artifact: "artifacts/contracts/privacyBridge/PrivacyBridgeUSDT.sol/PrivacyBridgeUSDT.json",
    args: [PUBLIC.USDT, PRIVATE.USDT, ...BRIDGE_ARGS],
  },
  {
    label: "PrivacyBridgeUSDCe",
    address: "0x29334fC23ffa2c44AF1b372336C2296591Eadd86",
    sourcePath: "contracts/privacyBridge/PrivacyBridgeUSDCe.sol",
    contractName: "PrivacyBridgeUSDCe",
    artifact: "artifacts/contracts/privacyBridge/PrivacyBridgeUSDCe.sol/PrivacyBridgeUSDCe.json",
    args: [PUBLIC.USDC_E, PRIVATE.USDC_E, ...BRIDGE_ARGS],
  },
  {
    label: "PrivacyBridgeWADA",
    address: "0xFa2126C07F517013c8d237cc465342da89B96f92",
    sourcePath: "contracts/privacyBridge/PrivacyBridgeWADA.sol",
    contractName: "PrivacyBridgeWADA",
    artifact: "artifacts/contracts/privacyBridge/PrivacyBridgeWADA.sol/PrivacyBridgeWADA.json",
    args: [PUBLIC.WADA, PRIVATE.WADA, ...BRIDGE_ARGS],
  },
  {
    label: "PrivacyBridgegCoti",
    address: "0xD4e0d9AB16b48c68044cB6aeA3A089380d6D8cD4",
    sourcePath: "contracts/privacyBridge/PrivacyBridgegCoti.sol",
    contractName: "PrivacyBridgegCoti",
    artifact: "artifacts/contracts/privacyBridge/PrivacyBridgegCoti.sol/PrivacyBridgegCoti.json",
    args: [PUBLIC.gCOTI, PRIVATE.gCOTI, ...BRIDGE_ARGS],
  },
];

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function encodeConstructorArgs(artifactPath, args) {
  if (!args.length) return "";
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  return new Interface(artifact.abi).encodeDeploy(args).slice(2);
}

async function isVerified(address) {
  const res = await fetch(
    `${API_BASE}/api?module=contract&action=getabi&address=${address}`,
    { headers: { "User-Agent": "Mozilla/5.0" } }
  );
  const json = await res.json();
  return json.status === "1" && json.result && json.result !== "Contract source code not verified";
}

function buildStandardJsonInput(bi, sourcePath, contractName) {
  const input = JSON.parse(JSON.stringify(bi.input));
  input.settings = {
    viaIR: true,
    optimizer: { enabled: true, runs: 10000 },
    metadata: { bytecodeHash: "none" },
    compilationTarget: { [sourcePath]: contractName },
    outputSelection: {
      "*": { "*": ["abi", "evm.bytecode", "evm.deployedBytecode", "evm.methodIdentifiers"] },
    },
  };
  return input;
}

async function submitVerification(job, bi, inputJsonPath) {
  const constructorArgs = encodeConstructorArgs(job.artifact, job.args);
  const autodetect = job.args.length === 0 ? "true" : "false";

  const fd = new FormData();
  fd.append("compiler_version", `v${bi.solcLongVersion}`);
  fd.append("contract_name", job.contractName);
  fd.append(
    "files[0]",
    new Blob([fs.readFileSync(inputJsonPath)], { type: "application/json" }),
    "input.json"
  );
  fd.append("autodetect_constructor_args", autodetect);
  fd.append("license_type", "mit");
  fd.append("is_optimization_enabled", "true");
  fd.append("optimization_runs", "10000");
  fd.append("evm_version", "paris");
  fd.append("is_via_ir", "true");
  if (constructorArgs) fd.append("constructor_args", constructorArgs);

  const res = await fetch(
    `${API_BASE}/api/v2/smart-contracts/${job.address}/verification/via/standard-input`,
    { method: "POST", headers: { "User-Agent": "Mozilla/5.0" }, body: fd }
  );
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  if (json.message !== "Smart-contract verification started") {
    throw new Error(text);
  }
}

async function waitVerified(address, maxAttempts = 90) {
  for (let i = 0; i < maxAttempts; i++) {
    if (await isVerified(address)) return true;
    await sleep(5000);
    process.stdout.write(".");
  }
  return false;
}

async function verifyOne(job, bi, tmpDir) {
  console.log(`\n[${job.label}] ${job.address}`);

  if (await isVerified(job.address)) {
    console.log("  already verified — skip");
    return { label: job.label, address: job.address, status: "skipped" };
  }

  const input = buildStandardJsonInput(bi, job.sourcePath, job.contractName);
  const inputPath = path.join(tmpDir, `${job.contractName}-input.json`);
  fs.writeFileSync(inputPath, JSON.stringify(input));

  console.log("  submitting...");
  await submitVerification(job, bi, inputPath);

  process.stdout.write("  waiting");
  const ok = await waitVerified(job.address);
  console.log(ok ? " verified" : " timed out");

  if (!ok) throw new Error("Verification did not complete in time");
  return { label: job.label, address: job.address, status: "verified" };
}

async function main() {
  console.log("Loading build-info (no compile)...");
  const bi = JSON.parse(fs.readFileSync(BUILD_INFO_PATH, "utf8"));
  console.log(`  solc ${bi.solcLongVersion}`);

  const tmpDir = fs.mkdtempSync(path.join(require("os").tmpdir(), "coti-verify-"));
  const results = [];

  for (const job of JOBS) {
    try {
      results.push(await verifyOne(job, bi, tmpDir));
    } catch (err) {
      console.error(`  FAILED: ${err.message}`);
      results.push({ label: job.label, address: job.address, status: "failed", error: err.message });
    }
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });

  console.log("\n========== SUMMARY ==========");
  for (const r of results) {
    console.log(
      `${r.status.padEnd(8)} ${r.label}: https://mainnet.cotiscan.io/address/${r.address}#code`
    );
    if (r.error) console.log(`         ${r.error}`);
  }

  process.exitCode = results.some((r) => r.status === "failed") ? 1 : 0;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
