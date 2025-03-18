import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "./utils/accounts"

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("Mul128")
  const contract = await factory.connect(owner).deploy()
  await contract.waitForDeployment()

  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("mul", function () {
    it("Should compute the product", async function () {
        const { contract, contractAddress, owner } = deployment

        await (await contract.test(582344438318678632068591n, 576634920180150n)).wait()

        const result0 = await contract.result0()
        const result1 = await contract.result1()

        console.log(result0, result1)
    })
  })
})