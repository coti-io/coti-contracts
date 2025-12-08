import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  params: bigint[],
  expectedResult: bigint
) {
  it(`${contractName}.${func}(${params}) should return ${expectedResult}`, async function () {
    const [owner] = await setupAccounts()
    const provider = owner.provider!

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    const tx = await contract.getFunction(func)(...params, { gasLimit })
    const receipt = await tx.wait()
    
    const result = await contract.getFunction(resFunc)()
    expect(result).to.equal(expectedResult)
    
    const txFromChain = await provider.getTransactionReceipt(receipt.hash)
    expect(txFromChain).to.not.be.null
    expect(txFromChain?.status).to.equal(1)
  })
}

// buildNotTest function removed - NOT operation is not supported for 128-bit and 256-bit types

// Basic test values
const params = [
  BigInt("1000000000000000000"),
  BigInt("500000000000000000")
]
const [a, b] = params

// For 128-bit, we need to mask to 128 bits for NOT operation
// MASK_128 = 2^128 - 1 (all bits set)
const MASK_128 = (BigInt(1) << BigInt(128)) - BigInt(1)

// Note: NOT operation helper removed - NOT is not supported for 128-bit and 256-bit types

// Test values that exercise upper bits
const HALF_MAX_128 = BigInt(1) << BigInt(127)  // 2^127 - tests upper bit
const UPPER_BITS_128 = BigInt("0xFFFFFFFFFFFFFFFF0000000000000000")  // Upper 64 bits set
const LOWER_BITS_128 = BigInt("0x0000000000000000FFFFFFFFFFFFFFFF")  // Lower 64 bits set
const SINGLE_BIT_127 = BigInt(1) << BigInt(127)  // Bit 127 set (highest bit)
const SINGLE_BIT_64 = BigInt(1) << BigInt(64)    // Bit 64 set (middle boundary)

describe("Bitwise 128-bit", function () {
  describe("Basic operations with small values", function () {
    buildTest("Bitwise128TestsContract", "andTest", "getAndResult", params, a & b)
    buildTest("Bitwise128TestsContract", "orTest", "getOrResult", params, a | b)
    buildTest("Bitwise128TestsContract", "xorTest", "getXorResult", params, a ^ b)
    // Note: NOT operation is not supported for 128-bit and 256-bit types in the MPC precompile
    // It only supports NOT for boolean types
  })

  describe("Edge cases - zero and max values", function () {
    buildTest("Bitwise128TestsContract", "andTest", "getAndResult", [BigInt(0), MASK_128], BigInt(0))
    buildTest("Bitwise128TestsContract", "orTest", "getOrResult", [BigInt(0), MASK_128], MASK_128)
    buildTest("Bitwise128TestsContract", "xorTest", "getXorResult", [BigInt(0), MASK_128], MASK_128)
    buildTest("Bitwise128TestsContract", "andTest", "getAndResult", [MASK_128, MASK_128], MASK_128)
    buildTest("Bitwise128TestsContract", "orTest", "getOrResult", [MASK_128, MASK_128], MASK_128)
    buildTest("Bitwise128TestsContract", "xorTest", "getXorResult", [MASK_128, MASK_128], BigInt(0))
  })

  describe("Operations with upper bits (2^127)", function () {
    buildTest("Bitwise128TestsContract", "andTest", "getAndResult", [HALF_MAX_128, HALF_MAX_128], HALF_MAX_128)
    buildTest("Bitwise128TestsContract", "orTest", "getOrResult", [HALF_MAX_128, HALF_MAX_128], HALF_MAX_128)
    buildTest("Bitwise128TestsContract", "xorTest", "getXorResult", [HALF_MAX_128, HALF_MAX_128], BigInt(0))
  })

  describe("Operations with upper and lower bit patterns (64-bit boundary)", function () {
    buildTest("Bitwise128TestsContract", "andTest", "getAndResult", [UPPER_BITS_128, LOWER_BITS_128], BigInt(0))
    buildTest("Bitwise128TestsContract", "orTest", "getOrResult", [UPPER_BITS_128, LOWER_BITS_128], MASK_128)
    buildTest("Bitwise128TestsContract", "xorTest", "getXorResult", [UPPER_BITS_128, LOWER_BITS_128], MASK_128)
  })

  describe("Operations with single bits at key positions", function () {
    buildTest("Bitwise128TestsContract", "andTest", "getAndResult", [SINGLE_BIT_127, SINGLE_BIT_64], BigInt(0))
    buildTest("Bitwise128TestsContract", "orTest", "getOrResult", [SINGLE_BIT_127, SINGLE_BIT_64], SINGLE_BIT_127 | SINGLE_BIT_64)
    buildTest("Bitwise128TestsContract", "xorTest", "getXorResult", [SINGLE_BIT_127, SINGLE_BIT_64], SINGLE_BIT_127 | SINGLE_BIT_64)
  })
})

