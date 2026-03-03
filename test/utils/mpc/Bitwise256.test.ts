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
  BigInt("1000000000000000000"),  // 1e18
  BigInt("500000000000000000")    // 0.5e18
]
const [a, b] = params

// For 256-bit, we need to mask to 256 bits for NOT operation
// MASK_256 = 2^256 - 1 (all bits set)
const MASK_256 = (BigInt(1) << BigInt(256)) - BigInt(1)

// Note: NOT operation helper removed - NOT is not supported for 128-bit and 256-bit types

// Test values that exercise upper bits
const HALF_MAX_256 = BigInt(1) << BigInt(255)  // 2^255 - tests upper bit
const UPPER_128_BITS_256 = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000")  // Upper 128 bits set
const LOWER_128_BITS_256 = BigInt("0x00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")  // Lower 128 bits set
const SINGLE_BIT_255 = BigInt(1) << BigInt(255)  // Bit 255 set (highest bit)
const SINGLE_BIT_128 = BigInt(1) << BigInt(128)  // Bit 128 set (128-bit boundary)
const SINGLE_BIT_64 = BigInt(1) << BigInt(64)    // Bit 64 set

describe("Bitwise 256-bit", function () {
  describe("Basic operations with small values", function () {
    buildTest("Bitwise256TestsContract", "andTest", "getAndResult", params, a & b)
    buildTest("Bitwise256TestsContract", "orTest", "getOrResult", params, a | b)
    buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", params, a ^ b)
    // Note: NOT operation is not supported for 128-bit and 256-bit types in the MPC precompile
    // It only supports NOT for boolean types
  })

  describe("Edge cases - zero and max values", function () {
    buildTest("Bitwise256TestsContract", "andTest", "getAndResult", [BigInt(0), MASK_256], BigInt(0))
    buildTest("Bitwise256TestsContract", "orTest", "getOrResult", [BigInt(0), MASK_256], MASK_256)
    buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", [BigInt(0), MASK_256], MASK_256)
    buildTest("Bitwise256TestsContract", "andTest", "getAndResult", [MASK_256, MASK_256], MASK_256)
    buildTest("Bitwise256TestsContract", "orTest", "getOrResult", [MASK_256, MASK_256], MASK_256)
    buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", [MASK_256, MASK_256], BigInt(0))
  })

  describe("Operations with upper bits (2^255)", function () {
    buildTest("Bitwise256TestsContract", "andTest", "getAndResult", [HALF_MAX_256, HALF_MAX_256], HALF_MAX_256)
    buildTest("Bitwise256TestsContract", "orTest", "getOrResult", [HALF_MAX_256, HALF_MAX_256], HALF_MAX_256)
    buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", [HALF_MAX_256, HALF_MAX_256], BigInt(0))
  })

  describe("Operations with upper and lower 128-bit patterns (128-bit boundary)", function () {
    buildTest("Bitwise256TestsContract", "andTest", "getAndResult", [UPPER_128_BITS_256, LOWER_128_BITS_256], BigInt(0))
    buildTest("Bitwise256TestsContract", "orTest", "getOrResult", [UPPER_128_BITS_256, LOWER_128_BITS_256], MASK_256)
    buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", [UPPER_128_BITS_256, LOWER_128_BITS_256], MASK_256)
  })

  describe("Operations with single bits at key positions", function () {
    buildTest("Bitwise256TestsContract", "andTest", "getAndResult", [SINGLE_BIT_255, SINGLE_BIT_128], BigInt(0))
    buildTest("Bitwise256TestsContract", "orTest", "getOrResult", [SINGLE_BIT_255, SINGLE_BIT_128], SINGLE_BIT_255 | SINGLE_BIT_128)
    buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", [SINGLE_BIT_255, SINGLE_BIT_128], SINGLE_BIT_255 | SINGLE_BIT_128)
  })

  describe("Operations crossing 128-bit boundary", function () {
    const cross128_1 = (BigInt(1) << BigInt(127)) | (BigInt(1) << BigInt(128))  // Bits 127 and 128 set
    const cross128_2 = (BigInt(1) << BigInt(126)) | (BigInt(1) << BigInt(129))  // Bits 126 and 129 set
    buildTest("Bitwise256TestsContract", "andTest", "getAndResult", [cross128_1, cross128_2], cross128_1 & cross128_2)
    buildTest("Bitwise256TestsContract", "orTest", "getOrResult", [cross128_1, cross128_2], cross128_1 | cross128_2)
    buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", [cross128_1, cross128_2], cross128_1 ^ cross128_2)
  })
})

