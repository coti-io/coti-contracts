/**
 * Set deposit/withdraw limits on all mainnet privacy bridges via setLimits().
 * Caller must be the bridge owner (onlyOwner).
 *
 * Human-readable defaults (scaled per bridge token decimals):
 *   min deposit  = 1
 *   max deposit  = 100000
 *   min withdraw = 1
 *   max withdraw = 100000
 *
 * Example: COTI native (18 decimals) → min deposit = 1e18 wei.
 *
 * Run with:
 *   npx hardhat run scripts/set-bridge-limits-mainnet.cjs --network coti-mainnet
 *
 * Optional env overrides (human amounts): MIN_DEPOSIT, MAX_DEPOSIT, MIN_WITHDRAW, MAX_WITHDRAW
 */
const hre = require("hardhat");

const CHAIN_IDS = {
    cotiTestnet: 7082400,
    cotiMainnet: 2632500,
    "coti-testnet": 7082400,
    "coti-mainnet": 2632500,
};

/** Human-readable limit amounts (before decimals scaling). */
const DEFAULT_LIMITS_HUMAN = {
    minDeposit: 0n,
    maxDeposit: 100_000n,
    minWithdraw: 0n,
    maxWithdraw: 100_000n,
};

/** Privacy bridge contract addresses per chain (from redeploy-private-and-bridges.cjs output). */
const BRIDGE_ADDRESSES = {
    2632500: [
        { name: "PrivacyBridgeCotiNative", address: "0x44D864973392064304dD88E2BDef39fF1ab11b7b" },
        { name: "PrivacyBridgeWETH", address: "0x7286c83300f0C7131b4006f3cf9F8e44BeB45c13" },
        { name: "PrivacyBridgeWBTC", address: "0xc3B7EdEe4f1c0A0bA1AcD341e4982371eC869862" },
        { name: "PrivacyBridgeUSDT", address: "0x7685B473DAF1c6DeD815Ca64C6fa18Da2227440D" },
        { name: "PrivacyBridgeUSDCe", address: "0x29334fC23ffa2c44AF1b372336C2296591Eadd86" },
        { name: "PrivacyBridgeWADA", address: "0xFa2126C07F517013c8d237cc465342da89B96f92" },
        { name: "PrivacyBridgegCoti", address: "0xD4e0d9AB16b48c68044cB6aeA3A089380d6D8cD4" },
    ],
    7082400: [],
};

const DECIMALS_ABI = ["function decimals() view returns (uint8)"];

function parseLimitHuman(name, fallback) {
    const raw = process.env[name];
    if (raw === undefined || raw === "") return fallback;
    try {
        return BigInt(raw);
    } catch {
        throw new Error(`Invalid ${name}: ${raw}`);
    }
}

function scaleHumanAmount(humanAmount, decimals) {
    return humanAmount * 10n ** BigInt(decimals);
}

function scaleLimitsHuman(humanLimits, decimals) {
    return {
        minDeposit: scaleHumanAmount(humanLimits.minDeposit, decimals),
        maxDeposit: scaleHumanAmount(humanLimits.maxDeposit, decimals),
        minWithdraw: scaleHumanAmount(humanLimits.minWithdraw, decimals),
        maxWithdraw: scaleHumanAmount(humanLimits.maxWithdraw, decimals),
    };
}

function limitsMatch(onChain, limits) {
    return (
        onChain.minDeposit === limits.minDeposit &&
        onChain.maxDeposit === limits.maxDeposit &&
        onChain.minWithdraw === limits.minWithdraw &&
        onChain.maxWithdraw === limits.maxWithdraw
    );
}

async function getBridgeTokenDecimals(bridgeAddress, bridgeName) {
    if (bridgeName === "PrivacyBridgeCotiNative") {
        const bridge = await hre.ethers.getContractAt("PrivacyBridgeCotiNative", bridgeAddress);
        const privateCotiAddr = await bridge.privateCoti();
        const privateCoti = await hre.ethers.getContractAt(DECIMALS_ABI, privateCotiAddr);
        return privateCoti.decimals();
    }

    // ERC20 bridges expose `token()` on the concrete implementation ABI (not on abstract PrivacyBridge).
    const bridge = await hre.ethers.getContractAt("PrivacyBridgeWETH", bridgeAddress);
    const tokenAddr = await bridge.token();
    const token = await hre.ethers.getContractAt(DECIMALS_ABI, tokenAddr);
    return token.decimals();
}

async function main() {
    const networkName = hre.network.name;
    const chainId = CHAIN_IDS[networkName];
    if (!chainId) {
        throw new Error(`Unsupported network: "${networkName}". Use --network coti-testnet or --network coti-mainnet`);
    }

    const bridges = BRIDGE_ADDRESSES[chainId];
    if (!bridges?.length) {
        throw new Error(
            `No bridge addresses configured for chainId ${chainId}. Add entries to BRIDGE_ADDRESSES in scripts/set-bridge-limits-mainnet.cjs`
        );
    }

    const limitsHuman = {
        minDeposit: parseLimitHuman("MIN_DEPOSIT", DEFAULT_LIMITS_HUMAN.minDeposit),
        maxDeposit: parseLimitHuman("MAX_DEPOSIT", DEFAULT_LIMITS_HUMAN.maxDeposit),
        minWithdraw: parseLimitHuman("MIN_WITHDRAW", DEFAULT_LIMITS_HUMAN.minWithdraw),
        maxWithdraw: parseLimitHuman("MAX_WITHDRAW", DEFAULT_LIMITS_HUMAN.maxWithdraw),
    };

    if (limitsHuman.minDeposit > limitsHuman.maxDeposit || limitsHuman.minWithdraw > limitsHuman.maxWithdraw) {
        throw new Error("Invalid limits: min must be <= max for deposit and withdraw");
    }

    const [signer] = await hre.ethers.getSigners();
    console.log("Network:", networkName, `(chainId: ${chainId})`);
    console.log("Signer:", signer.address);
    console.log("Human limits (all bridges):");
    console.log("  minDeposit:", limitsHuman.minDeposit.toString());
    console.log("  maxDeposit:", limitsHuman.maxDeposit.toString());
    console.log("  minWithdraw:", limitsHuman.minWithdraw.toString());
    console.log("  maxWithdraw:", limitsHuman.maxWithdraw.toString());

    const balance = await hre.ethers.provider.getBalance(signer.address);
    if (balance === 0n) {
        throw new Error("Signer has no COTI for gas");
    }

    for (const bridge of bridges) {
        process.stdout.write(`  ${bridge.name} (${bridge.address})... `);
        const contract = await hre.ethers.getContractAt("PrivacyBridge", bridge.address, signer);

        const decimals = await getBridgeTokenDecimals(bridge.address, bridge.name);
        const limits = scaleLimitsHuman(limitsHuman, decimals);

        console.log(`decimals=${decimals}`);
        console.log(`    raw minDeposit=${limits.minDeposit} maxDeposit=${limits.maxDeposit}`);
        console.log(`    raw minWithdraw=${limits.minWithdraw} maxWithdraw=${limits.maxWithdraw}`);

        const onChain = {
            minDeposit: await contract.minDepositAmount(),
            maxDeposit: await contract.maxDepositAmount(),
            minWithdraw: await contract.minWithdrawAmount(),
            maxWithdraw: await contract.maxWithdrawAmount(),
        };

        if (limitsMatch(onChain, limits)) {
            console.log("    already set — skip");
            continue;
        }

        const tx = await contract.setLimits(
            limits.minDeposit,
            limits.maxDeposit,
            limits.minWithdraw,
            limits.maxWithdraw,
            { gasLimit: 5_000_000 }
        );
        const receipt = await tx.wait();
        console.log(`    ✅ tx ${receipt.hash}`);
    }

    console.log("\nDone.");
}

main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
