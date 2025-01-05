import hre from "hardhat"
import { expect } from "chai"

import { generateRSAKeyPair } from "@coti-io/coti-sdk-typescript"
import { setupAccounts } from "../utils/accounts"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("AccountOnboard")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()
  
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("Account Onboard", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  it('Should successfully onboard the account', async function () {
    const { owner, contractAddress } = deployment

    await owner.generateOrRecoverAes(contractAddress)

    expect(owner.getUserOnboardInfo()?.aesKey).to.not.equal('')
  })

  it('Should revert when the signature is empty', async function () {
    const { owner, contract } = deployment

    const { publicKey } = generateRSAKeyPair()

    const tx = await contract
        .connect(owner)
        .onboardAccount(publicKey, '0x')
    
    expect(tx).to.be.reverted
  })
})