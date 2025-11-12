import fs from "fs"
import hre from "hardhat"
import { CotiNetwork, getDefaultProvider, parseEther, Wallet } from "@coti-io/coti-ethers"
import { JsonRpcProvider } from "ethers"

let pks = process.env.SIGNING_KEYS ? process.env.SIGNING_KEYS.split(",") : []

export async function setupAccounts() {
  // Get the network from Hardhat configuration
  const networkName = hre.network.name;
  let provider;
  let rpcUrl: string;
  
  if (networkName === "coti-private") {
    // Use the private network RPC URL from hardhat config
    const privateNetwork = hre.config.networks["coti-private"] as any;
    rpcUrl = privateNetwork?.url || "http://40.160.5.30:8545";
    provider = new JsonRpcProvider(rpcUrl);
  } else if (networkName === "coti-mainnet") {
    provider = getDefaultProvider(CotiNetwork.Mainnet);
    rpcUrl = "https://mainnet.coti.io/rpc";
  } else {
    // Default to testnet
    provider = getDefaultProvider(CotiNetwork.Testnet);
    rpcUrl = "https://testnet.coti.io/rpc";
  }

  // Verify and log network information
  try {
    const network = await provider.getNetwork();
    const blockNumber = await provider.getBlockNumber();
    console.log("\n" + "=".repeat(80));
    console.log("🌐 NETWORK VERIFICATION");
    console.log("=".repeat(80));
    console.log(`Network Name: ${networkName}`);
    console.log(`RPC URL: ${rpcUrl}`);
    console.log(`Chain ID: ${network.chainId.toString()}`);
    console.log(`Current Block: ${blockNumber}`);
    console.log("=".repeat(80) + "\n");
  } catch (error) {
    console.warn("⚠️  Could not verify network details:", error);
  }

  if (pks.length == 0) {
    const key1 = Wallet.createRandom(provider)
    const key2 = Wallet.createRandom(provider)
    pks = [key1.privateKey, key2.privateKey]

    setEnvValue("PUBLIC_KEYS", `${key1.address},${key2.address}`)
    setEnvValue("SIGNING_KEYS", `${key1.privateKey},${key2.privateKey}`)

    throw new Error(`Created new random accounts ${key1.address} and ${key2.address}. Please use faucet to fund them.`)
  }

  const wallets = pks.map((pk) => new Wallet(pk, provider))
  if ((await provider.getBalance(wallets[0].address)) === BigInt("0")) {
    throw new Error(`Please use faucet to fund account ${wallets[0].address}`)
  }

  let userKeys = process.env.USER_KEYS ? process.env.USER_KEYS.split(",") : []

  const toAccount = async (wallet: Wallet, userKey?: string) => {
    if (userKey) {
      wallet.setAesKey(userKey)
      return wallet
    }

    console.log("************* Onboarding user ", wallet.address, " *************")
    await wallet.generateOrRecoverAes()
    console.log("************* Onboarded! created user key and saved into .env file *************")

    return wallet
  }

  let accounts: Wallet[] = []
  if (userKeys.length !== wallets.length) {
    // Send more funds to second account to cover gas costs for all tests
    console.log(`\n💰 Initial funding: Sending 10.0 COTI to second account...`)
    console.log(`   From: ${wallets[0].address}`)
    console.log(`   To: ${wallets[1].address}`)
    console.log(`   RPC: ${rpcUrl}`)
    const tx = await wallets[0].sendTransaction({ to: wallets[1].address, value: parseEther("10.0") })
    const receipt = await tx.wait()
    console.log(`   ✅ Transaction confirmed: ${receipt?.hash}`)
    console.log(`   ✅ Block: ${receipt?.blockNumber}`)
    console.log(`   ✅ Network: ${networkName} (Chain ID: ${(await provider.getNetwork()).chainId})\n`)

    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account)))
    setEnvValue("USER_KEYS", accounts.map((a) => a.getUserOnboardInfo()?.aesKey).join(","))
  } else {
    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account, userKeys[i])))
    
    // Ensure second account has enough funds for gas (check and top up if needed)
    const secondAccountBalance = await provider.getBalance(wallets[1].address)
    const minBalance = parseEther("5.0")
    if (secondAccountBalance < minBalance) {
      console.log(`\n💰 Topping up second account ${wallets[1].address} with funds...`)
      console.log(`   Current balance: ${(Number(secondAccountBalance) / 1e18).toFixed(4)} COTI`)
      console.log(`   Sending: 10.0 COTI`)
      console.log(`   RPC: ${rpcUrl}`)
      const tx = await wallets[0].sendTransaction({ to: wallets[1].address, value: parseEther("10.0") })
      const receipt = await tx.wait()
      console.log(`   ✅ Transaction confirmed: ${receipt?.hash}`)
      console.log(`   ✅ Block: ${receipt?.blockNumber}`)
      console.log(`   ✅ Network: ${networkName} (Chain ID: ${(await provider.getNetwork()).chainId})\n`)
    }
  }

  return accounts
}

function setEnvValue(key: string, value: string) {
  fs.appendFileSync("./.env", `\n${key}=${value}`, "utf8")
}
