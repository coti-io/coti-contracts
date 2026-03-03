import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  param: bigint,
  expectedResult: bigint
) {
  it(`${contractName}.${func}(${param}) should return ${expectedResult}`, async function () {
    const [owner] = await setupAccounts()
    const provider = owner.provider!

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    const tx = await contract.getFunction(func)(param, { gasLimit })
    const receipt = await tx.wait()
    
    const result = await contract.getFunction(resFunc)()
    expect(result).to.equal(expectedResult)
    
    const txFromChain = await provider.getTransactionReceipt(receipt.hash)
    expect(txFromChain).to.not.be.null
    expect(txFromChain?.status).to.equal(1)
  })
}

// Test values
const MASK_128 = (BigInt(1) << BigInt(128)) - BigInt(1)
const HALF_MAX_128 = BigInt(1) << BigInt(127)
const testValue1 = BigInt("1000000000000000000")
const testValue2 = BigInt("500000000000000000")
const testValue3 = BigInt("2000000000000000000")

describe("OnBoard 128-bit", function () {
  describe("Round-trip tests (setPublic -> offBoard -> onBoard -> decrypt)", function () {
    buildTest("OnBoard128TestsContract", "testOnBoardOffBoardRoundTrip", "getOnboardOffboardResult", testValue1, testValue1)
    buildTest("OnBoard128TestsContract", "testOnBoardOffBoardRoundTrip", "getOnboardOffboardResult", testValue2, testValue2)
    buildTest("OnBoard128TestsContract", "testOnBoardOffBoardRoundTrip", "getOnboardOffboardResult", HALF_MAX_128, HALF_MAX_128)
  })

  describe("Multiple values test", function () {
    it("OnBoard128TestsContract.testOnBoardMultipleValues should handle multiple values", async function () {
      const [owner] = await setupAccounts()
      const provider = owner.provider!

      const factory = await hre.ethers.getContractFactory("OnBoard128TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Execute the transaction - the contract's require statements verify correctness
      // If the transaction succeeds, all three values were correctly processed
      const tx = await contract.testOnBoardMultipleValues(testValue1, testValue2, testValue3, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)
      
      const txFromChain = await provider.getTransactionReceipt(receipt.hash)
      expect(txFromChain).to.not.be.null
      expect(txFromChain?.status).to.equal(1)
    })
  })

  describe("Edge cases (zero and max)", function () {
    it("OnBoard128TestsContract.testOnBoardEdgeCases should handle zero and max values", async function () {
      const [owner] = await setupAccounts()
      const provider = owner.provider!

      const factory = await hre.ethers.getContractFactory("OnBoard128TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Execute the transaction - the contract's require statements verify correctness
      // If the transaction succeeds, both zero and max values were correctly processed
      const tx = await contract.testOnBoardEdgeCases({ gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)
      
      const txFromChain = await provider.getTransactionReceipt(receipt.hash)
      expect(txFromChain).to.not.be.null
      expect(txFromChain?.status).to.equal(1)
    })
  })
})

