/**
 * Redeployment script for Private Tokens and Bridges only.
 *
 * Fetches the current public token addresses from the remote config.ts in the
 * coti-privacy-portal repo, saves a local copy to deploy/privacy_bridge/config.ts,
 * and writes the updated addresses back to that local file after deployment.
 *
 * Run with:
 *   npx hardhat compile
 *   npx hardhat run deploy/privacy_bridge/redeploy-private-and-bridges.cjs --network coti-testnet
 *   npx hardhat run deploy/privacy_bridge/redeploy-private-and-bridges.cjs --network coti-mainnet
 */
const hre  = require("hardhat");
const fs   = require("node:fs");
const path = require("node:path");

const CHAIN_IDS = {
    "coti-testnet": 7082400,
    "coti-mainnet": 2632500,
};

// Local config.ts alongside this script
const CONFIG_PATH = path.resolve(__dirname, "config.ts");

/**
 * Parse the given chainId block from a config.ts string and return a plain address map.
 */
function readAddressesForChain(chainId) {
    const src = fs.readFileSync(CONFIG_PATH, "utf8");

    const startMarker = `${chainId}: {`;
    const startIdx = src.indexOf(startMarker);
    if (startIdx === -1) throw new Error(`Could not find ${chainId} block in config.ts`);

    let depth = 0, blockStart = src.indexOf("{", startIdx), i = blockStart;
    while (i < src.length) {
        if (src[i] === "{") depth++;
        else if (src[i] === "}") { depth--; if (depth === 0) break; }
        i++;
    }
    const block = src.slice(blockStart + 1, i);

    const addresses = {};
    const lines = block.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('//')) continue;
        
        const colonIdx = trimmed.indexOf(':');
        if (colonIdx === -1) continue;
        
        const keyRaw = trimmed.substring(0, colonIdx).trim();
        let valRaw = trimmed.substring(colonIdx + 1).trim();
        
        if (valRaw.endsWith(',')) {
            valRaw = valRaw.slice(0, -1).trim();
        }
        
        let key = keyRaw;
        if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
            key = key.substring(1, key.length - 1);
        }
        
        let val = valRaw;
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.substring(1, val.length - 1);
        }
        
        if (key && val) {
            addresses[key] = val;
        }
    }
    return addresses;
}

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    const networkName = hre.network.name;
    const chainId = CHAIN_IDS[networkName];

    if (!chainId) {
        throw new Error(`Unsupported network: "${networkName}". Use --network coti-testnet or --network coti-mainnet`);
    }

    console.log("Redeploying with account:", deployer.address);
    console.log("Network:", networkName, `(chainId: ${chainId})`);

    // ── Read current addresses from local config.ts ────────────────────────
    console.log("\n--- Reading current addresses from config.ts ---");
    const current = readAddressesForChain(chainId);

    const publicTokens = {
        WETH:   current["WETH"],
        WBTC:   current["WBTC"],
        USDT:   current["USDT"],
        USDC_E: current["USDC_E"],
        WADA:   current["WADA"],
        gCOTI:  current["gCOTI"],
    };

    for (const [key, addr] of Object.entries(publicTokens)) {
        if (!addr) throw new Error(`Missing public token address for ${key} in config.ts (${chainId} block)`);
        console.log(`  ${key}: ${addr}`);
    }

    const newAddresses = { ...publicTokens };

    // ── 1. Redeploy Private Tokens ─────────────────────────────────────────
    console.log("\n--- Redeploying Private Tokens ---");
    const privateTokens = [
        { name: "PrivateCOTI",                        key: "PrivateCOTI" },
        { name: "PrivateWrappedEther",                 key: "PrivateWrappedEther" },
        { name: "PrivateWrappedBTC",                   key: "PrivateWrappedBTC" },
        { name: "PrivateTetherUSD",                    key: "PrivateTetherUSD" },
        { name: "PrivateBridgedUSDC",                  key: "PrivateBridgedUSDC" },
        { name: "PrivateWrappedADA",                   key: "PrivateWrappedADA" },
        { name: "PrivateCOTITreasuryGovernanceToken",  key: "PrivateCOTITreasuryGovernanceToken" },
    ];

    for (const pt of privateTokens) {
        process.stdout.write(`  Deploying ${pt.name}... `);
        const Factory = await hre.ethers.getContractFactory(pt.name);
        const contract = await Factory.deploy({ gasLimit: 12000000 });
        await contract.waitForDeployment();
        newAddresses[pt.key] = await contract.getAddress();
        console.log(`✅ ${newAddresses[pt.key]}`);
    }

    // ── 2. Redeploy Bridges ────────────────────────────────────────────────
    console.log("\n--- Redeploying Bridges ---");
    const bridges = [
        { name: "PrivacyBridgeCotiNative", publicKey: null,       privateKey: "PrivateCOTI",                         bridgeKey: "PrivacyBridgeCotiNative" },
        { name: "PrivacyBridgeWETH",       publicKey: "WETH",     privateKey: "PrivateWrappedEther",                 bridgeKey: "PrivacyBridgeWETH" },
        { name: "PrivacyBridgeWBTC",       publicKey: "WBTC",     privateKey: "PrivateWrappedBTC",                   bridgeKey: "PrivacyBridgeWBTC" },
        { name: "PrivacyBridgeUSDT",       publicKey: "USDT",     privateKey: "PrivateTetherUSD",                    bridgeKey: "PrivacyBridgeUSDT" },
        { name: "PrivacyBridgeUSDCe",      publicKey: "USDC_E",   privateKey: "PrivateBridgedUSDC",                  bridgeKey: "PrivacyBridgeUSDCe" },
        { name: "PrivacyBridgeWADA",       publicKey: "WADA",     privateKey: "PrivateWrappedADA",                   bridgeKey: "PrivacyBridgeWADA" },
        { name: "PrivacyBridgegCoti",      publicKey: "gCOTI",    privateKey: "PrivateCOTITreasuryGovernanceToken",  bridgeKey: "PrivacyBridgegCoti" },
    ];

    for (const bridge of bridges) {
        process.stdout.write(`  Deploying ${bridge.name}... `);
        const Factory = await hre.ethers.getContractFactory(bridge.name);
        let contract;
        if (bridge.publicKey) {
            contract = await Factory.deploy(
                newAddresses[bridge.publicKey],
                newAddresses[bridge.privateKey],
                { gasLimit: 12000000 }
            );
        } else {
            contract = await Factory.deploy(newAddresses[bridge.privateKey], { gasLimit: 12000000 });
        }
        await contract.waitForDeployment();
        newAddresses[bridge.bridgeKey] = await contract.getAddress();
        console.log(`✅ ${newAddresses[bridge.bridgeKey]}`);
    }

    // ── 3. Grant Roles ─────────────────────────────────────────────────────
    console.log("\n--- Granting Roles ---");
    const MINTER_ROLE = hre.ethers.id("MINTER_ROLE");
    const BURNER_ROLE  = hre.ethers.id("BURNER_ROLE");

    for (const bridge of bridges) {
        const ptAddress     = newAddresses[bridge.privateKey];
        const bridgeAddress = newAddresses[bridge.bridgeKey];
        const ptContract    = await hre.ethers.getContractAt("PrivateERC20", ptAddress);

        process.stdout.write(`  ${bridge.name}: granting MINTER_ROLE... `);
        const tx1 = await ptContract.grantRole(MINTER_ROLE, bridgeAddress, { gasLimit: 5000000 });
        await tx1.wait();
        process.stdout.write("✅  BURNER_ROLE... ");
        const tx2 = await ptContract.grantRole(BURNER_ROLE, bridgeAddress, { gasLimit: 5000000 });
        await tx2.wait();
        console.log("✅");
    }

    // ── 4. Update local deploy/privacy_bridge/config.ts ─────────────────
    console.log("\n--- Updating local config.ts ---");

    let configContent = fs.readFileSync(CONFIG_PATH, "utf8");

    const newBlock = `    // ${chainId === 2632500 ? "COTI Mainnet" : "COTI Testnet"}
    ${chainId}: {
    // Native
    PrivateCoti: "${newAddresses.PrivateCOTI}",
    PrivacyBridgeCotiNative: "${newAddresses.PrivacyBridgeCotiNative}",

    // Public Tokens
    WETH: "${newAddresses.WETH}",
    WBTC: "${newAddresses.WBTC}",
    USDT: "${newAddresses.USDT}",
    USDC_E: "${newAddresses.USDC_E}",
    WADA: "${newAddresses.WADA}",
    gCOTI: "${newAddresses.gCOTI}",

    // Private Tokens
    "p.WETH": "${newAddresses.PrivateWrappedEther}",
    "p.WBTC": "${newAddresses.PrivateWrappedBTC}",
    "p.USDT": "${newAddresses.PrivateTetherUSD}",
    "p.USDC_E": "${newAddresses.PrivateBridgedUSDC}",
    "p.WADA": "${newAddresses.PrivateWrappedADA}",
    "p.gCOTI": "${newAddresses.PrivateCOTITreasuryGovernanceToken}",

    // Bridges
    PrivacyBridgeWETH: "${newAddresses.PrivacyBridgeWETH}",
    PrivacyBridgeWBTC: "${newAddresses.PrivacyBridgeWBTC}",
    PrivacyBridgeUSDT: "${newAddresses.PrivacyBridgeUSDT}",
    PrivacyBridgeUSDCe: "${newAddresses.PrivacyBridgeUSDCe}",
    PrivacyBridgeWADA: "${newAddresses.PrivacyBridgeWADA}",
    PrivacyBridgegCOTI: "${newAddresses.PrivacyBridgegCoti}"
  }`;

    // Use the parser to find the exact start/end of the chainId block, then replace it.
    const startMarker = `${chainId}: {`;
    const startIdx = configContent.indexOf(startMarker);
    if (startIdx === -1) {
        console.error(`❌ Could not find ${chainId} block in config.ts. Please update manually.`);
        process.exit(1);
    }

    // Walk backwards to include any preceding comment lines (e.g. "// COTI Testnet")
    let blockStart = startIdx;
    let lineStart = configContent.lastIndexOf("\n", startIdx - 1);
    // Check up to 2 lines back for a comment (handles blank line between comment and chainId)
    for (let look = 0; look < 2 && lineStart > 0; look++) {
        const prevLineStart = configContent.lastIndexOf("\n", lineStart - 1);
        const prevLine = configContent.slice(prevLineStart + 1, lineStart).trim();
        if (prevLine.startsWith("//")) {
            blockStart = prevLineStart + 1;
            break;
        }
        if (prevLine === "") {
            // blank line — keep looking
            lineStart = prevLineStart;
            continue;
        }
        break;
    }

    // Walk forward to find the matching closing brace
    let depth = 0;
    let i = configContent.indexOf("{", startIdx);
    while (i < configContent.length) {
        if (configContent[i] === "{") depth++;
        else if (configContent[i] === "}") {
            depth--;
            if (depth === 0) break;
        }
        i++;
    }
    const blockEnd = i + 1; // include the closing "}"

    configContent = configContent.slice(0, blockStart) + newBlock + configContent.slice(blockEnd);
    fs.writeFileSync(CONFIG_PATH, configContent, "utf8");
    console.log(`✅ config.ts updated at ${CONFIG_PATH}`);

    // ── 5. Summary ────────────────────────────────────────────────────────
    console.log("\n========================================================");
    console.log("  DEPLOYMENT COMPLETE");
    console.log("========================================================");
    console.log(`  PrivateCoti:             ${newAddresses.PrivateCOTI}`);
    console.log(`  PrivacyBridgeCotiNative: ${newAddresses.PrivacyBridgeCotiNative}`);
    console.log(`  p.WETH:                  ${newAddresses.PrivateWrappedEther}`);
    console.log(`  p.WBTC:                  ${newAddresses.PrivateWrappedBTC}`);
    console.log(`  p.USDT:                  ${newAddresses.PrivateTetherUSD}`);
    console.log(`  p.USDC_E:                ${newAddresses.PrivateBridgedUSDC}`);
    console.log(`  p.WADA:                  ${newAddresses.PrivateWrappedADA}`);
    console.log(`  p.gCOTI:                 ${newAddresses.PrivateCOTITreasuryGovernanceToken}`);
    console.log(`  PrivacyBridgeWETH:       ${newAddresses.PrivacyBridgeWETH}`);
    console.log(`  PrivacyBridgeWBTC:       ${newAddresses.PrivacyBridgeWBTC}`);
    console.log(`  PrivacyBridgeUSDT:       ${newAddresses.PrivacyBridgeUSDT}`);
    console.log(`  PrivacyBridgeUSDCe:      ${newAddresses.PrivacyBridgeUSDCe}`);
    console.log(`  PrivacyBridgeWADA:       ${newAddresses.PrivacyBridgeWADA}`);
    console.log(`  PrivacyBridgegCOTI:      ${newAddresses.PrivacyBridgegCoti}`);
    console.log("========================================================\n");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
