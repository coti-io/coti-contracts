/**
 * Deploy CotiPriceConsumer on COTI Mainnet.
 *
 * Run with:
 *   npx hardhat compile
 *   npx hardhat run deploy/oracle/deploy-coti-price-consumer-mainnet.cjs --network cotiMainnet
 */
const hre = require("hardhat");

// Band Protocol StdReferenceProxy on COTI Mainnet
const BAND_REF_PROXY = "0x9503d502435f8e228b874Ba0F792301d4401b523";

// Maximum staleness in seconds (1 hour).
const MAX_STALENESS = 3600;

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying CotiPriceConsumer with account:", deployer.address);
    console.log("Network:", hre.network.name);

    const balance = await hre.ethers.provider.getBalance(deployer.address);
    console.log("Balance:", hre.ethers.formatEther(balance), "COTI");

    if (balance === 0n) {
        throw new Error("Deployer account has no COTI — fund it first");
    }

    const Factory = await hre.ethers.getContractFactory("CotiPriceConsumer");
    const contract = await Factory.deploy(BAND_REF_PROXY, MAX_STALENESS, { gasLimit: 5000000 });
    await contract.waitForDeployment();

    const address = await contract.getAddress();
    console.log("✅ CotiPriceConsumer deployed to:", address);

    // Quick sanity read
    try {
        const price = await contract.getPrice("COTI");
        const readable = Number(price) / 1e18;
        console.log("   COTI/USD price (raw 1e18):", price.toString());
        console.log("   COTI/USD price (USD):     ", `$${readable}`);
    } catch (err) {
        console.log("   ⚠️  Could not read price:", err.reason || err.message);
    }
}

main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
