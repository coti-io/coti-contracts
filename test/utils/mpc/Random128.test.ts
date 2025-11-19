import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000
let last_random_value = BigInt(0)

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  params: (bigint | number)[],
  expectedResult?: bigint
) {
  it(`${contractName}.${func}(${params}) should return a random value`, async function () {
    const [owner] = await setupAccounts()
    const provider = owner.provider!

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    const tx = await contract.getFunction(func)(...params, { gasLimit })
    const receipt = await tx.wait()
    
    const result = await contract.getFunction(resFunc)()
    
    if (resFunc === "getRandom" || resFunc === "getRandomBounded") {
      expect(result).to.not.equal(expectedResult || last_random_value)
      last_random_value = result
    } else {
      expect(result).to.equal(expectedResult)
    }
    
    const txFromChain = await provider.getTransactionReceipt(receipt.hash)
    expect(txFromChain).to.not.be.null
    expect(txFromChain?.status).to.equal(1)
  })
}

const numBits = 7

describe("Random 128-bit", function () {
  buildTest("Random128TestsContract", "randomTest", "getRandom", [], last_random_value)
  buildTest("Random128TestsContract", "randomBoundedTest", "getRandomBounded", [numBits], last_random_value)
})

