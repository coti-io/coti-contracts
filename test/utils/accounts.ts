import fs from "fs"
import hre from "hardhat"
import { JsonRpcProvider, parseEther, Wallet } from "@coti-io/coti-ethers"

let pks = process.env.SIGNING_KEYS ? process.env.SIGNING_KEYS.split(",") : []

export async function setupAccounts(skipOnboard: boolean = false) {
  // Get the network configuration from hardhat config
  const networkName = hre.network.name
  const networkConfig = hre.config.networks[networkName]
  
  if (!networkConfig || typeof networkConfig !== 'object' || !('url' in networkConfig)) {
    throw new Error(`Network configuration not found for ${networkName}`)
  }
  
  const provider = new JsonRpcProvider(networkConfig.url);

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

    if (skipOnboard) {
      return wallet
    }

    console.log("************* Onboarding user ", wallet.address, " *************")
    await wallet.generateOrRecoverAes('0x9bB7CEE67F31e47CBdd530DaE5746Fef2420E0E3')
    console.log("************* Onboarded! created user key and saved into .env file *************")

    return wallet
  }

  let accounts: Wallet[] = []
  if (userKeys.length !== wallets.length) {
    console.log("************* Funding accounts *************")
    for (let i = 0; i < wallets.length; i++) {
      const balance = await provider.getBalance(wallets[i].address)
      if(balance > parseEther("1.0")) {
        console.log("Account ", wallets[i].address, " already has 1.0 ETH, skipping")
        continue
      }
      console.log("Sending 100.0 ETH to ", wallets[i].address)
      await (await wallets[0].sendTransaction({ to: wallets[i].address, value: parseEther("100.0") })).wait()
    }
    console.log("************* Funded accounts *************")

    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account)))
    if (!skipOnboard) {
      setEnvValue("USER_KEYS", accounts.map((a) => a.getUserOnboardInfo()?.aesKey).join(","))
    }
  } else {
    accounts = await Promise.all(wallets.map(async (account, i) => await toAccount(account, userKeys[i])))
  }

  return accounts
}

function setEnvValue(key: string, value: string) {
  fs.appendFileSync("./.env", `\n${key}=${value}`, "utf8")
}
