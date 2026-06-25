/**
 * Grant OPERATOR_ROLE on each privacy bridge via addOperator(account).
 * Caller must hold DEFAULT_ADMIN_ROLE on every bridge (typically the deployer owner).
 *
 * Run with:
 *   npx hardhat run scripts/add-bridge-operators.cjs --network coti-mainnet
 *
 * Optional env:
 *   OPERATOR_ACCOUNT=0x...  (default: 0x07dd528aC097f2Fb18fdC048e8d94376621b68C9)
 */
const hre = require("hardhat");

const CHAIN_IDS = {
    cotiTestnet: 7082400,
    cotiMainnet: 2632500,
    "coti-testnet": 7082400,
    "coti-mainnet": 2632500,
};

const DEFAULT_OPERATOR = "0x07dd528aC097f2Fb18fdC048e8d94376621b68C9";

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

async function main() {
    const networkName = hre.network.name;
    const chainId = CHAIN_IDS[networkName];
    if (!chainId) {
        throw new Error(`Unsupported network: "${networkName}". Use --network coti-testnet or --network coti-mainnet`);
    }

    const bridges = BRIDGE_ADDRESSES[chainId];
    if (!bridges?.length) {
        throw new Error(
            `No bridge addresses configured for chainId ${chainId}. Add entries to BRIDGE_ADDRESSES in scripts/add-bridge-operators.cjs`
        );
    }

    const operatorAccount = process.env.OPERATOR_ACCOUNT || DEFAULT_OPERATOR;
    if (!hre.ethers.isAddress(operatorAccount)) {
        throw new Error(`Invalid OPERATOR_ACCOUNT: ${operatorAccount}`);
    }

    const [signer] = await hre.ethers.getSigners();
    console.log("Network:", networkName, `(chainId: ${chainId})`);
    console.log("Signer:", signer.address);
    console.log("Operator to add:", operatorAccount);
    console.log("Bridges:", bridges.length);

    const balance = await hre.ethers.provider.getBalance(signer.address);
    if (balance === 0n) {
        throw new Error("Signer has no COTI for gas");
    }

    for (const bridge of bridges) {
        process.stdout.write(`  ${bridge.name} (${bridge.address})... `);
        const contract = await hre.ethers.getContractAt("PrivacyBridge", bridge.address, signer);

        const alreadyOperator = await contract.isOperator(operatorAccount);
        if (alreadyOperator) {
            console.log("already operator — skip");
            continue;
        }

        const tx = await contract.addOperator(operatorAccount, { gasLimit: 5_000_000 });
        const receipt = await tx.wait();
        console.log(`✅ tx ${receipt.hash}`);
    }

    console.log("\nDone.");
}

main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
