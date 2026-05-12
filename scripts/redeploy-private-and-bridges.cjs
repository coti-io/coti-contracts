/**
 * Redeployment script for Private Tokens and Bridges only.
 *
 * Public token addresses are hardcoded per network. After deployment,
 * the script prints the full config block to stdout for manual copy
 * into config.ts.
 *
 * Run with:
 *   npx hardhat compile
 *   npx hardhat run scripts/redeploy-private-and-bridges.cjs --network cotiTestnet
 *   npx hardhat run scripts/redeploy-private-and-bridges.cjs --network cotiMainnet
 */
const hre  = require("hardhat");

const CHAIN_IDS = {
    cotiTestnet: 7082400,
    cotiMainnet: 2632500,
    "coti-testnet": 7082400,
    "coti-mainnet": 2632500,
};

const PUBLIC_TOKEN_ADDRESSES = {
    7082400: { // COTI Testnet
        WETH:   "0x8bca4e6bbE402DB4aD189A316137aD08206154FB",
        WBTC:   "0x5dBDb2E5D51c3FFab5D6B862Caa11FCe1D83F492",
        USDT:   "0x9e961430053cd5AbB3b060544cEcCec848693Cf0",
        USDC_E: "0x63f3D2Cc8F5608F57ce6E5Aa3590A2Beb428D19C",
        WADA:   "0xe3E2cd3Abf412c73a404b9b8227B71dE3CfE829D",
        gCOTI:  "0x878a42D3cB737DEC9E6c7e7774d973F46fd8ed4C",
    },
    2632500: { // COTI Mainnet
        WETH:   "0x639aCc80569c5FC83c6FBf2319A6Cc38bBfe26d1",
        WBTC:   "0x8C39B1fD0e6260fdf20652Fc436d25026832bfEA",
        USDT:   "0xfA6f73446b17A97a56e464256DA54AD43c2Cbc3E",
        USDC_E: "0xf1Feebc4376c68B7003450ae66343Ae59AB37D3C",
        WADA:   "0xe757Ca19d2c237AA52eBb1d2E8E4368eeA3eb331",
        gCOTI:  "0x7637C7838EC4Ec6b85080F28A678F8E234bB83D1",
    },
};

function printConfigBlock(chainId, addresses) {
    const networkName = chainId === 2632500 ? "COTI Mainnet" : "COTI Testnet";
    console.log("\n========================================================");
    console.log("  DEPLOYMENT COMPLETE — Copy this block into config.ts:");
    console.log("========================================================");
    console.log(`    // ${networkName}`);
    console.log(`    ${chainId}: {`);
    console.log(`      // Native`);
    console.log(`      PrivateCoti: "${addresses.PrivateCOTI}",`);
    console.log(`      PrivacyBridgeCotiNative: "${addresses.PrivacyBridgeCotiNative}",`);
    console.log(``);
    console.log(`      // Public Tokens`);
    console.log(`      WETH: "${addresses.WETH}",`);
    console.log(`      WBTC: "${addresses.WBTC}",`);
    console.log(`      USDT: "${addresses.USDT}",`);
    console.log(`      USDC_E: "${addresses.USDC_E}",`);
    console.log(`      WADA: "${addresses.WADA}",`);
    console.log(`      gCOTI: "${addresses.gCOTI}",`);
    console.log(``);
    console.log(`      // Private Tokens`);
    console.log(`      "p.WETH": "${addresses.PrivateWrappedEther}",`);
    console.log(`      "p.WBTC": "${addresses.PrivateWrappedBTC}",`);
    console.log(`      "p.USDT": "${addresses.PrivateTetherUSD}",`);
    console.log(`      "p.USDC_E": "${addresses.PrivateBridgedUSDC}",`);
    console.log(`      "p.WADA": "${addresses.PrivateWrappedADA}",`);
    console.log(`      "p.gCOTI": "${addresses.PrivateCOTITreasuryGovernanceToken}",`);
    console.log(``);
    console.log(`      // Bridges`);
    console.log(`      PrivacyBridgeWETH: "${addresses.PrivacyBridgeWETH}",`);
    console.log(`      PrivacyBridgeWBTC: "${addresses.PrivacyBridgeWBTC}",`);
    console.log(`      PrivacyBridgeUSDT: "${addresses.PrivacyBridgeUSDT}",`);
    console.log(`      PrivacyBridgeUSDCe: "${addresses.PrivacyBridgeUSDCe}",`);
    console.log(`      PrivacyBridgeWADA: "${addresses.PrivacyBridgeWADA}",`);
    console.log(`      PrivacyBridgegCOTI: "${addresses.PrivacyBridgegCoti}"`);
    console.log(`    }`);
    console.log("========================================================\n");
}

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    const networkName = hre.network.name;
    const chainId = CHAIN_IDS[networkName];

    if (!chainId) {
        throw new Error(`Unsupported network: "${networkName}". Use --network cotiTestnet or --network cotiMainnet`);
    }

    console.log("Redeploying with account:", deployer.address);
    console.log("Network:", networkName, `(chainId: ${chainId})`);

    // ── Resolve public token addresses from hardcoded config ───────────────
    console.log("\n--- Public Token Addresses ---");
    const publicTokens = PUBLIC_TOKEN_ADDRESSES[chainId];
    if (!publicTokens) {
        throw new Error(`No public token addresses configured for chainId ${chainId}`);
    }
    for (const [key, addr] of Object.entries(publicTokens)) {
        if (!addr) throw new Error(`Missing public token address for ${key} (chainId: ${chainId})`);
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

    const feeRecipient = process.env.FEE_RECIPIENT;
    const rescueRecipient = process.env.RESCUE_RECIPIENT;
    if (!feeRecipient) throw new Error("FEE_RECIPIENT not set in .env");
    if (!rescueRecipient) throw new Error("RESCUE_RECIPIENT not set in .env");
    console.log(`  feeRecipient: ${feeRecipient}`);
    console.log(`  rescueRecipient: ${rescueRecipient}`);

    // CotiPriceConsumer deployed addresses per network
    const PRICE_ORACLE = {
        7082400: "0xAC89a381E84fbd5B3B536a3b895eB2aDdaDC36A1", // testnet
        2632500: "0x2D07EAE0E10d3B4753F7553Bba7e93C98A997077", // mainnet
    };
    const oracleAddr = PRICE_ORACLE[chainId];
    if (!oracleAddr) throw new Error(`No price oracle address configured for chainId ${chainId}`);
    console.log(`  priceOracle: ${oracleAddr}`);

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
            // ERC20 bridge: constructor(address _token, address _privateToken, address _feeRecipient, address _rescueRecipient, address _priceOracle)
            contract = await Factory.deploy(
                newAddresses[bridge.publicKey],
                newAddresses[bridge.privateKey],
                feeRecipient,
                rescueRecipient,
                oracleAddr,
                { gasLimit: 12000000 }
            );
        } else {
            // Native bridge: constructor(address _privateCoti, address _feeRecipient, address _rescueRecipient, address _priceOracle)
            contract = await Factory.deploy(newAddresses[bridge.privateKey], feeRecipient, rescueRecipient, oracleAddr, { gasLimit: 12000000 });
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


    // ── 5. Print config block ──────────────────────────────────────────────
    printConfigBlock(chainId, newAddresses);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
