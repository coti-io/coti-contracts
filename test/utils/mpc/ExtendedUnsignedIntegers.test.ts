import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import crypto from "crypto"
import { itUint, Wallet } from "@coti-io/coti-ethers"
import { CtUint128Struct, ItUint128Struct } from "../../../typechain-types/contracts/mocks/utils/mpc/ExtendedMiscellaneousTestsContract"

const MAX_UINT128 = BigInt('0xffffffffffffffffffffffffffffffff')

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const extendedMiscellaneousTestsContract = await hre.ethers.getContractFactory("ExtendedMiscellaneousTestsContract")
  const extendedMiscellaneousTests = await extendedMiscellaneousTestsContract.connect(owner).deploy()
  await extendedMiscellaneousTests.waitForDeployment()

  const extendedArithmeticTestsContract = await hre.ethers.getContractFactory("ExtendedArithmeticTestsContract")
  const extendedArithmeticTests = await extendedArithmeticTestsContract.connect(owner).deploy()
  await extendedArithmeticTests.waitForDeployment()

  const extendedBitwiseTestsContract = await hre.ethers.getContractFactory("ExtendedBitwiseTestsContract")
  const extendedBitwiseTests = await extendedBitwiseTestsContract.connect(owner).deploy()
  await extendedBitwiseTests.waitForDeployment()

  const extendedComparisonTestsContract = await hre.ethers.getContractFactory("ExtendedComparisonTestsContract")
  const extendedComparisonTests = await extendedComparisonTestsContract.connect(owner).deploy()
  await extendedComparisonTests.waitForDeployment()

  return { extendedMiscellaneousTests, extendedArithmeticTests, extendedBitwiseTests, extendedComparisonTests, owner }
}

function generateRandomNumber(numBytes: number): bigint {
  const bytes = crypto.randomBytes(numBytes)
  // Convert bytes to BigInt
  return BigInt('0x' + bytes.toString('hex'))
}

async function encryptUint128(number: bigint, account: Wallet, contractAddress: string, functionSelector: string): Promise<ItUint128Struct> {
  // Convert to hex string and ensure it is 32 characters (16 bytes)
  const hexString = number.toString(16).padStart(32, '0');

  // Split into two 8-byte (16-character) segments
  const high = hexString.slice(0, 16);
  const low = hexString.slice(16, 32);

  const itHigh = await account.encryptValue(
    BigInt(`0x${high}`),
    contractAddress,
    functionSelector
  ) as itUint

  const itLow = await account.encryptValue(
    BigInt(`0x${low}`),
    contractAddress,
    functionSelector
  ) as itUint

  return {
    ciphertext: { high: itHigh.ciphertext, low: itLow.ciphertext },
    signature: [itHigh.signature, itLow.signature]
  }
}

async function decryptUint128(ctNumber: CtUint128Struct, account: Wallet): Promise<bigint> {
  const high = await account.decryptValue(ctNumber.high as bigint)
  const low = await account.decryptValue(ctNumber.low as bigint)

  // Convert both high and low parts to hex strings, ensuring they are 16 characters (8 bytes) long
  let highHex = high.toString(16).padStart(16, '0');
  let lowHex = low.toString(16).padStart(16, '0');

  // Concatenate and convert back to a single bigint
  return BigInt(`0x${highHex + lowHex}`);
}

describe("MPC Core", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("128-bit unsigned integers", function () {
    // it("validateCiphertext", async function () {
    //     const { extendedMiscellaneousTests, owner } = deployment

    //     // Generate two arrays of 10 random 128-bit integers
    //     const numbers: bigint[] = []
    //     const encryptedNumbers: ItUint128Struct[] = []

    //     for (let i = 0; i < 100; i++) {
    //       // Generate random 128-bit integers
    //       const number = generateRandomNumber(16)

    //       numbers.push(number)
    //       encryptedNumbers.push(
    //         await encryptUint128(
    //           number,
    //           owner,
    //           await extendedMiscellaneousTests.getAddress(),
    //           extendedMiscellaneousTests.validateCiphertextTest.fragment.selector
    //         )
    //       )
    //     }

    //     // Call validateCiphertextTest with the array
    //     await (await extendedMiscellaneousTests.validateCiphertextTest(encryptedNumbers)).wait()

    //     // Verify results
    //     for (let i = 0; i < 100; i++) {
    //         const result = await extendedMiscellaneousTests.numbers(i)
    //         expect(result).to.equal(numbers[i])
    //     }
    // })

    // it("offBoardToUser", async function () {
    //   const { extendedMiscellaneousTests, owner } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     numbers.push(generateRandomNumber(16))
    //   }

    //   // Call validateCiphertextTest with the array
    //   await (await extendedMiscellaneousTests.offBoardToUserTest(numbers)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //       const ctNumber = await extendedMiscellaneousTests.ctNumbers(i)

    //       const result = await decryptUint128(ctNumber, owner)

    //       expect(result).to.equal(numbers[i])
    //   }
    // })

    // it("setPublic", async function () {
    //     const { extendedMiscellaneousTests } = deployment

    //     // Generate two arrays of 10 random 128-bit integers
    //     const numbers: bigint[] = []

    //     for (let i = 0; i < 100; i++) {
    //         // Generate random 128-bit integers
    //         numbers.push(generateRandomNumber(16))
    //     }

    //     // Call setPublicTest with the arrays
    //     await (await extendedMiscellaneousTests.setPublicTest(numbers)).wait()

    //     // Verify results
    //     for (let i = 0; i < 100; i++) {
    //         const result = await extendedMiscellaneousTests.numbers(i)
    //         expect(result).to.equal(numbers[i])
    //     }
    // })

    // TODO: FIX REVERTING TESTS FOR TRANSFER AND TRANSFERWITHALLOWANCE
    //
    // it("transfer", async function () {
    //   const { extendedMiscellaneousTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const aArr: bigint[] = []
    //   const bArr: bigint[] = []
    //   const amountArr: bigint[] = []
    //   const newA: bigint[] = []
    //   const newB: bigint[] = []
    //   const successArr: boolean[] = []

    //   for (let i = 0; i < 100; i++) {
    //       // Generate random 128-bit integers

    //       const a = generateRandomNumber(15)
    //       const b = generateRandomNumber(15)
    //       const amount = generateRandomNumber(15)

    //       aArr.push(a)
    //       bArr.push(b)
    //       amountArr.push(amount)

    //       const success = a >= amount

    //       newA.push(success ? a - amount : a)
    //       newB.push(success ? b + amount : b)
    //       successArr.push(success)
    //   }

    //   // Call transferTest with the arrays
    //   await (await extendedMiscellaneousTests.transferTest(aArr, bArr, amountArr)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //       const a = await extendedMiscellaneousTests.a(i)
    //       const b = await extendedMiscellaneousTests.b(i)
    //       const success = await extendedMiscellaneousTests.success(i)

    //       expect(a).to.equal(newA[i])
    //       expect(b).to.equal(newB[i])
    //       expect(success).to.equal(successArr[i])
    //   }
    // })

    // it("transferWithAllowance", async function () {
    //   const { extendedMiscellaneousTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const aArr: bigint[] = []
    //   const bArr: bigint[] = []
    //   const amountArr: bigint[] = []
    //   const allowanceArr: bigint[] = []
    //   const newA: bigint[] = []
    //   const newB: bigint[] = []
    //   const successArr: boolean[] = []
    //   const newAllowanceArr: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //       // Generate random 128-bit integers

    //       const a = generateRandomNumber(15)
    //       const b = generateRandomNumber(15)
    //       const amount = generateRandomNumber(15)
    //       const allowance = generateRandomNumber(15)

    //       aArr.push(a)
    //       bArr.push(b)
    //       amountArr.push(amount)
    //       allowanceArr.push(allowance)

    //       const success = a >= amount && amount <= allowance

    //       newA.push(success ? a - amount : a)
    //       newB.push(success ? b + amount : b)
    //       successArr.push(success)
    //       newAllowanceArr.push(allowance - amount)
    //   }

    //   // Call transferWithAllowanceTest with the arrays
    //   await (await extendedMiscellaneousTests.transferWithAllowanceTest(aArr, bArr, amountArr, allowanceArr)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //       const a = await extendedMiscellaneousTests.a(i)
    //       const b = await extendedMiscellaneousTests.b(i)
    //       const success = await extendedMiscellaneousTests.success(i)
    //       const allowance = await extendedMiscellaneousTests.allowance(i)

    //       expect(a).to.equal(newA[i])
    //       expect(b).to.equal(newB[i])
    //       expect(success).to.equal(successArr[i])
    //       expect(allowance).to.equal(allowanceArr[i])
    //   }
    // })

    // it("add", async function () {
    //   const { extendedArithmeticTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(15)
    //     const num2 = generateRandomNumber(15)
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 + num2)
    //   }

    //   // Call addTest with the arrays
    //   await (await extendedArithmeticTests.addTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedArithmeticTests.numbers(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("checkedAdd", async function () {
    //   const { extendedArithmeticTests, owner } = deployment

    //   for (let i = 0; i < 10; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = generateRandomNumber(16)
        
    //     if (num1 + num2 <= MAX_UINT128) { // max uint128
    //       // Call checkedAddTest
    //       await (await extendedArithmeticTests.checkedAddTest(num1, num2)).wait()

    //       const result = await extendedArithmeticTests.numbers(0)
    //       expect(result).to.equal(num1 + num2)
    //     } else {
    //       // Expect revert
    //       const tx = await extendedArithmeticTests.checkedAddTest(num1, num2)

    //       try {
    //         await tx.wait()
    //       } catch (e) {
    //         const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
    //         expect(receipt?.status).to.be.equal(0)
    //       }
    //     }
    //   }
    // })

    // it("checkedAddWithOverflowBit", async function () {
    //   const { extendedArithmeticTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedOverflows: boolean[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 50; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = generateRandomNumber(16)
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedOverflows.push(num1 + num2 > MAX_UINT128)
    //     expectedResults.push(num1 + num2)
    //   }

    //   // Call checkedAddWithOverflowBitTest with the arrays
    //   await (await extendedArithmeticTests.checkedAddWithOverflowBitTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 50; i++) {
    //     const bit = await extendedArithmeticTests.overflows(i)
    //     const bitLHS = await extendedArithmeticTests.overflowsLHS(i)
    //     const bitRHS = await extendedArithmeticTests.overflowsRHS(i)
    //     const result = await extendedArithmeticTests.numbers(i)
    //     const resultLHS = await extendedArithmeticTests.numbersLHS(i)
    //     const resultRHS = await extendedArithmeticTests.numbersRHS(i)

    //     expect(bit).to.equal(expectedOverflows[i])
    //     expect(bitLHS).to.equal(expectedOverflows[i])
    //     expect(bitRHS).to.equal(expectedOverflows[i])

    //     if (bit) {
    //       expect(result).to.not.equal(expectedResults[i])
    //       expect(resultLHS).to.not.equal(expectedResults[i])
    //       expect(resultRHS).to.not.equal(expectedResults[i])
    //     } else {
    //       expect(result).to.equal(expectedResults[i])
    //       expect(resultLHS).to.equal(expectedResults[i])
    //       expect(resultRHS).to.equal(expectedResults[i])
    //     }
    //   }
    // })

    // it("sub", async function () {
    //     const { extendedArithmeticTests } = deployment
  
    //     // Generate two arrays of 10 random 128-bit integers
    //     const numbers1: bigint[] = []
    //     const numbers2: bigint[] = []
    //     const expectedResults: bigint[] = []
  
    //     for (let i = 0; i < 100; i++) {
    //       // Generate random 128-bit integers
    //       const num1 = generateRandomNumber(16)
    //       const num2 = generateRandomNumber(16)
          
    //       if (num1 >= num2) {
    //           numbers1.push(num1)
    //           numbers2.push(num2)
    //           expectedResults.push(num1 - num2)
    //       } else {
    //         numbers1.push(num2)
    //         numbers2.push(num1)
    //         expectedResults.push(num2 - num1)
    //       }
    //     }
  
    //     // Call subTest with the arrays
    //     await (await extendedArithmeticTests.subTest(numbers1, numbers2)).wait()
  
    //     // Verify results
    //     for (let i = 0; i < 100; i++) {
    //       const result = await extendedArithmeticTests.numbers(i)
    //       expect(result).to.equal(expectedResults[i])
    //     }
    // })

    // it("checkedSub", async function () {
    //   const { extendedArithmeticTests, owner } = deployment

    //   for (let i = 0; i < 10; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = generateRandomNumber(16)
        
    //     if (num1 - num2 >= 0n) {
    //       // Call checkedSubTest
    //       await (await extendedArithmeticTests.checkedSubTest(num1, num2)).wait()

    //       const result = await extendedArithmeticTests.numbers(0)
    //       expect(result).to.equal(num1 - num2)
    //     } else {
    //       // Expect revert
    //       const tx = await extendedArithmeticTests.checkedSubTest(num1, num2)

    //       try {
    //         await tx.wait()
    //       } catch (e) {
    //         const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
    //         expect(receipt?.status).to.be.equal(0)
    //       }
    //     }
    //   }
    // })

    // it("checkedSubWithOverflowBit", async function () {
    //   const { extendedArithmeticTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedOverflows: boolean[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 50; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = generateRandomNumber(16)
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedOverflows.push(num1 - num2 < 0n)
    //     expectedResults.push(num1 - num2)
    //   }

    //   // Call checkedSubWithOverflowBitTest with the arrays
    //   await (await extendedArithmeticTests.checkedSubWithOverflowBitTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 50; i++) {
    //     const bit = await extendedArithmeticTests.overflows(i)
    //     const bitLHS = await extendedArithmeticTests.overflowsLHS(i)
    //     const bitRHS = await extendedArithmeticTests.overflowsRHS(i)
    //     const result = await extendedArithmeticTests.numbers(i)
    //     const resultLHS = await extendedArithmeticTests.numbersLHS(i)
    //     const resultRHS = await extendedArithmeticTests.numbersRHS(i)

    //     expect(bit).to.equal(expectedOverflows[i])
    //     expect(bitLHS).to.equal(expectedOverflows[i])
    //     expect(bitRHS).to.equal(expectedOverflows[i])

    //     if (bit) {
    //       expect(result).to.not.equal(expectedResults[i])
    //       expect(resultLHS).to.not.equal(expectedResults[i])
    //       expect(resultRHS).to.not.equal(expectedResults[i])
    //     } else {
    //       expect(result).to.equal(expectedResults[i])
    //       expect(resultLHS).to.equal(expectedResults[i])
    //       expect(resultRHS).to.equal(expectedResults[i])
    //     }
    //   }
    // })

    it("mul", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers1.length < 1) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(10)
        const num2 = generateRandomNumber(8)

        if (num1 * num2 > MAX_UINT128) continue

        console.log(num1, num2, num1 * num2)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 * num2)
      }

      // Call addTest with the arrays
      await (await extendedArithmeticTests.mulTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 10; i++) {
        const result = await extendedArithmeticTests.numbers(i)

        console.log(numbers1[i], numbers2[i], expectedResults[i], result)

        expect(result).to.equal(expectedResults[i])
      }
    })

    it("checkedMul", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 10; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(10)
        const num2 = generateRandomNumber(8)
        
        if (num1 * num2 <= MAX_UINT128) {
          // Call checkedSubTest
          await (await extendedArithmeticTests.checkedMulTest(num1, num2)).wait()

          const result = await extendedArithmeticTests.numbers(0)
          expect(result).to.equal(num1 * num2)
        } else {
          // Expect revert
          const tx = await extendedArithmeticTests.checkedMulTest(num1, num2)

          try {
            await tx.wait()
          } catch (e) {
            const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
            expect(receipt?.status).to.be.equal(0)
          }
        }
      }
    })

    it("checkedMulWithOverflowBit", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 10; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(10)
        const num2 = generateRandomNumber(8)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 * num2 > MAX_UINT128)
        expectedResults.push(num1 * num2)
      }

      // Call checkedSubWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedMulWithOverflowBitTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 10; i++) {
        const bit = await extendedArithmeticTests.overflows(i)
        const bitLHS = await extendedArithmeticTests.overflowsLHS(i)
        const bitRHS = await extendedArithmeticTests.overflowsRHS(i)
        const result = await extendedArithmeticTests.numbers(i)
        const resultLHS = await extendedArithmeticTests.numbersLHS(i)
        const resultRHS = await extendedArithmeticTests.numbersRHS(i)

        expect(bit).to.equal(expectedOverflows[i])
        expect(bitLHS).to.equal(expectedOverflows[i])
        expect(bitRHS).to.equal(expectedOverflows[i])

        if (bit) {
          expect(result).to.not.equal(expectedResults[i])
          expect(resultLHS).to.not.equal(expectedResults[i])
          expect(resultRHS).to.not.equal(expectedResults[i])
        } else {
          expect(result).to.equal(expectedResults[i])
          expect(resultLHS).to.equal(expectedResults[i])
          expect(resultRHS).to.equal(expectedResults[i])
        }
      }
    })

    // it("and", async function () {
    //   const { extendedBitwiseTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = generateRandomNumber(16)
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 & num2)
    //   }

    //   // Call addTest with the arrays
    //   await (await extendedBitwiseTests.andTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedBitwiseTests.numbers(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("or", async function () {
    //   const { extendedBitwiseTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = generateRandomNumber(16)
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 | num2)
    //   }

    //   // Call orTest with the arrays
    //   await (await extendedBitwiseTests.orTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedBitwiseTests.numbers(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("xor", async function () {
    //   const { extendedBitwiseTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = generateRandomNumber(16)
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 ^ num2)
    //   }

    //   // Call xorTest with the arrays
    //   await (await extendedBitwiseTests.xorTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedBitwiseTests.numbers(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("eq", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: boolean[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 === num2)
    //   }

    //   // Call eqTest with the arrays
    //   await (await extendedComparisonTests.eqTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.boolResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("ne", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: boolean[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 !== num2)
    //   }

    //   // Call neTest with the arrays
    //   await (await extendedComparisonTests.neTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.boolResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("ge", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: boolean[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 >= num2)
    //   }

    //   // Call geTest with the arrays
    //   await (await extendedComparisonTests.geTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.boolResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("gt", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: boolean[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 > num2)
    //   }

    //   // Call gtTest with the arrays
    //   await (await extendedComparisonTests.gtTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.boolResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("le", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: boolean[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 <= num2)
    //   }

    //   // Call leTest with the arrays
    //   await (await extendedComparisonTests.leTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.boolResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("lt", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: boolean[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 < num2)
    //   }

    //   // Call ltTest with the arrays
    //   await (await extendedComparisonTests.ltTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.boolResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("min", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 <= num2 ? num1 : num2)
    //   }

    //   // Call minTest with the arrays
    //   await (await extendedComparisonTests.minTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.uintResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })

    // it("max", async function () {
    //   const { extendedComparisonTests } = deployment

    //   // Generate two arrays of 10 random 128-bit integers
    //   const numbers1: bigint[] = []
    //   const numbers2: bigint[] = []
    //   const expectedResults: bigint[] = []

    //   for (let i = 0; i < 100; i++) {
    //     // Generate random 128-bit integers
    //     const num1 = generateRandomNumber(16)
    //     const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
    //     numbers1.push(num1)
    //     numbers2.push(num2)
    //     expectedResults.push(num1 >= num2 ? num1 : num2)
    //   }

    //   // Call maxTest with the arrays
    //   await (await extendedComparisonTests.maxTest(numbers1, numbers2)).wait()

    //   // Verify results
    //   for (let i = 0; i < 100; i++) {
    //     const result = await extendedComparisonTests.uintResults(i)
    //     expect(result).to.equal(expectedResults[i])
    //   }
    // })
  })
})