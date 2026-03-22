import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error(
      "No deployer signer found. Set PRIVATE_KEY in your environment."
    );
  }

  const owner = process.env.NFT_OWNER || deployer.address;
  const name = process.env.NFT_NAME || "Soulbound Node NFT";
  const symbol = process.env.NFT_SYMBOL || "SNODE";

  console.log("Deploying SoulboundNodeNFT...");
  console.log("Deployer:", deployer.address);
  console.log("Owner:", owner);
  console.log("Name:", name);
  console.log("Symbol:", symbol);

  const provider = deployer.provider;
  if (!provider) {
    throw new Error("No provider found for deployer signer.");
  }

  // COTI testnet RPC may not support "pending" block queries.
  // Use legacy gas price + latest nonce + explicit gas limit to avoid
  // pending-based fee/nonce/gas estimation lookups.
  const gasPrice = BigInt(await provider.send("eth_gasPrice", []));
  const nonce = await provider.getTransactionCount(deployer.address, "latest");
  const gasLimit = BigInt(process.env.NFT_DEPLOY_GAS_LIMIT || "6000000");

  const factory = await ethers.getContractFactory("SoulboundNodeNFT");
  const deployTxReq = await factory.getDeployTransaction(name, symbol, owner);
  if (!deployTxReq.data) {
    throw new Error("Failed to build deploy transaction data.");
  }

  const sentTx = await deployer.sendTransaction({
    data: deployTxReq.data,
    gasPrice,
    nonce,
    gasLimit,
  });
  console.log("Deployment tx hash:", sentTx.hash);
  const receipt = await sentTx.wait();
  if (!receipt || !receipt.contractAddress) {
    throw new Error("Deployment transaction mined but no contract address found.");
  }

  console.log("SoulboundNodeNFT deployed at:", receipt.contractAddress);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
