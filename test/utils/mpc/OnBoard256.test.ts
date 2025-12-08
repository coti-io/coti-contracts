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
const MASK_256 = (BigInt(1) << BigInt(256)) - BigInt(1)
const HALF_MAX_256 = BigInt(1) << BigInt(255)
const testValue1 = BigInt("1000000000000000000")
const testValue2 = BigInt("500000000000000000")
const testValue3 = BigInt("2000000000000000000")
const valueAbove128 = BigInt(1) << BigInt(128)  // 2^128
const valueBelow128 = (BigInt(1) << BigInt(127)) - BigInt(1)  // 2^127 - 1

describe("OnBoard 256-bit", function () {
  describe("Round-trip tests (setPublic -> offBoard -> onBoard -> decrypt)", function () {
    buildTest("OnBoard256TestsContract", "testOnBoardOffBoardRoundTrip", "getOnboardOffboardResult", testValue1, testValue1)
    buildTest("OnBoard256TestsContract", "testOnBoardOffBoardRoundTrip", "getOnboardOffboardResult", testValue2, testValue2)
    buildTest("OnBoard256TestsContract", "testOnBoardOffBoardRoundTrip", "getOnboardOffboardResult", HALF_MAX_256, HALF_MAX_256)
    buildTest("OnBoard256TestsContract", "testOnBoardOffBoardRoundTrip", "getOnboardOffboardResult", valueAbove128, valueAbove128)
  })

  describe("Multiple values test", function () {
    it("OnBoard256TestsContract.testOnBoardMultipleValues should handle multiple values", async function () {
      const [owner] = await setupAccounts()
      const provider = owner.provider!

      const factory = await hre.ethers.getContractFactory("OnBoard256TestsContract", owner as any)
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
    it("OnBoard256TestsContract.testOnBoardEdgeCases should handle zero and max values", async function () {
      const [owner] = await setupAccounts()
      const provider = owner.provider!

      const factory = await hre.ethers.getContractFactory("OnBoard256TestsContract", owner as any)
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

  describe("128-bit boundary test", function () {
    it("OnBoard256TestsContract.testOnBoard128BitBoundary should handle values crossing 128-bit boundary", async function () {
      const [owner] = await setupAccounts()
      const provider = owner.provider!

      const factory = await hre.ethers.getContractFactory("OnBoard256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Execute the transaction - the contract's require statements verify correctness
      // If the transaction succeeds, both boundary values were correctly processed
      const tx = await contract.testOnBoard128BitBoundary({ gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)
      
      const txFromChain = await provider.getTransactionReceipt(receipt.hash)
      expect(txFromChain).to.not.be.null
      expect(txFromChain?.status).to.equal(1)
    })
  })
})

