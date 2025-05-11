import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { ItUint256Struct } from "../../../typechain-types/contracts/mocks/utils/mpc/Miscellaneous256BitTestsContract"
import { decryptUint256, encryptUint256, generateRandomNumber } from "./helpers"

const MAX_UINT256 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const extendedMiscellaneousTestsContract = await hre.ethers.getContractFactory("Miscellaneous256BitTestsContract")
  const extendedMiscellaneousTests = await extendedMiscellaneousTestsContract.connect(owner).deploy()
  await extendedMiscellaneousTests.waitForDeployment()

  const extendedArithmeticTestsContract = await hre.ethers.getContractFactory("Arithmetic256BitTestsContract")
  const extendedArithmeticTests = await extendedArithmeticTestsContract.connect(owner).deploy()
  await extendedArithmeticTests.waitForDeployment()

  const extendedBitwiseTestsContract = await hre.ethers.getContractFactory("Bitwise256BitTestsContract")
  const extendedBitwiseTests = await extendedBitwiseTestsContract.connect(owner).deploy()
  await extendedBitwiseTests.waitForDeployment()

  const extendedComparisonTestsContract = await hre.ethers.getContractFactory("Comparison256BitTestsContract")
  const extendedComparisonTests = await extendedComparisonTestsContract.connect(owner).deploy()
  await extendedComparisonTests.waitForDeployment()

  return { extendedMiscellaneousTests, extendedArithmeticTests, extendedBitwiseTests, extendedComparisonTests, owner }
}

describe("MPC Core", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("256-bit unsigned integers", function () {
    it("validateCiphertext", async function () {
        const { extendedMiscellaneousTests, owner } = deployment

        // Generate two arrays of 10 random 256-bit integers
        const numbers: bigint[] = []
        const encryptedNumbers: ItUint256Struct[] = []

        for (let i = 0; i < 1; i++) {
          // Generate random 256-bit integers
          const number = generateRandomNumber(32)

          numbers.push(number)
          encryptedNumbers.push(
            await encryptUint256(
              number,
              owner,
              await extendedMiscellaneousTests.getAddress(),
              extendedMiscellaneousTests.validateCiphertextTest.fragment.selector
            ) as ItUint256Struct
          )
        }

        // Call validateCiphertextTest with the array
        await (await extendedMiscellaneousTests.validateCiphertextTest(encryptedNumbers)).wait()

        // Verify results
        for (let i = 0; i < 1; i++) {
            const result = await extendedMiscellaneousTests.numbers2(i)
            expect(result).to.equal(numbers[i])
        }
    })

    it("offBoardToUser", async function () {
      const { extendedMiscellaneousTests, owner } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        numbers.push(generateRandomNumber(32))
      }

      // Call validateCiphertextTest with the array
      await (await extendedMiscellaneousTests.offBoardToUserTest(numbers)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
          const ctNumber = await extendedMiscellaneousTests.ctNumbers2(i)

          const result = await decryptUint256(ctNumber, owner)

          expect(result).to.equal(numbers[i])
      }
    })

    it("setPublic", async function () {
        const { extendedMiscellaneousTests } = deployment

        // Generate two arrays of 10 random 256-bit integers
        const numbers: bigint[] = []

        for (let i = 0; i < 1; i++) {
            // Generate random 256-bit integers
            numbers.push(generateRandomNumber(32))
        }

        // Call setPublicTest with the arrays
        await (await extendedMiscellaneousTests.setPublicTest(numbers)).wait()

        // Verify results
        for (let i = 0; i < 1; i++) {
            const result = await extendedMiscellaneousTests.numbers2(i)
            expect(result).to.equal(numbers[i])
        }
    })

    it("rand", async function () {
        const { extendedMiscellaneousTests } = deployment

        const length: bigint = generateRandomNumber(1)

        // Call setPublicTest with the arrays
        await (await extendedMiscellaneousTests.randTest2(length)).wait()

        // Verify results
        for (let i = 0; i < length; i++) {
            const result = await extendedMiscellaneousTests.numbers2(i)
            expect(result).to.not.equal(0n)
        }
    })

    it("randBoundedBits", async function () {
      const { extendedMiscellaneousTests } = deployment

      // Generate an array of 10 random 8-bit integers
      const numbers: bigint[] = []

      while (numbers.length < 1) {
          // Generate random 8-bit integers
          numbers.push(generateRandomNumber(1))
      }

      // Call setPublicTest with the arrays
      await (await extendedMiscellaneousTests.randBoundedBitsTest2(numbers)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
          const result = await extendedMiscellaneousTests.numbers2(i)
          expect(result).to.not.equal(0n)
      }
    })
    
    it("transfer", async function () {
      const { extendedMiscellaneousTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const aArr: bigint[] = []
      const bArr: bigint[] = []
      const amountArr: bigint[] = []
      const newA: bigint[] = []
      const newB: bigint[] = []
      const successArr: boolean[] = []

      while (aArr.length < 1) {
          // Generate random 256-bit integers

          const a = generateRandomNumber(30)
          const b = generateRandomNumber(30)
          const amount = generateRandomNumber(30)

          if (b + amount > MAX_UINT256) continue

          aArr.push(a)
          bArr.push(b)
          amountArr.push(amount)

          const success = a >= amount

          newA.push(success ? a - amount : a)
          newB.push(success ? b + amount : b)
          successArr.push(success)
      }

      // Call transferTest with the arrays
      await (await extendedMiscellaneousTests.transferTest(aArr, bArr, amountArr)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
          const a = await extendedMiscellaneousTests.a2(i)
          const b = await extendedMiscellaneousTests.b2(i)
          const success = await extendedMiscellaneousTests.success(i)

          expect(a).to.equal(newA[i])
          expect(b).to.equal(newB[i])
          expect(success).to.equal(successArr[i])
      }
    })

    it("transferWithAllowance", async function () {
      const { extendedMiscellaneousTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const aArr: bigint[] = []
      const bArr: bigint[] = []
      const amountArr: bigint[] = []
      const allowanceArr: bigint[] = []
      const newA: bigint[] = []
      const newB: bigint[] = []
      const successArr: boolean[] = []
      const newAllowanceArr: bigint[] = []

      while (aArr.length < 1) {
          // Generate random 256-bit integers

          const a = generateRandomNumber(30)
          const b = generateRandomNumber(30)
          const amount = generateRandomNumber(30)
          const allowance = generateRandomNumber(30)

          if (b + amount > MAX_UINT256) continue

          aArr.push(a)
          bArr.push(b)
          amountArr.push(amount)
          allowanceArr.push(allowance)

          const success = a >= amount && amount <= allowance

          newA.push(success ? a - amount : a)
          newB.push(success ? b + amount : b)
          successArr.push(success)
          newAllowanceArr.push(success ? allowance - amount : allowance)
      }

      // Call transferWithAllowanceTest with the arrays
      await (await extendedMiscellaneousTests.transferWithAllowanceTest(aArr, bArr, amountArr, allowanceArr)).wait()
      
      // Verify results
      for (let i = 0; i < 1; i++) {
          const a = await extendedMiscellaneousTests.a2(i)
          const b = await extendedMiscellaneousTests.b2(i)
          const success = await extendedMiscellaneousTests.success(i)
          const allowance = await extendedMiscellaneousTests.allowance2(i)

          expect(a).to.equal(newA[i])
          expect(b).to.equal(newB[i])
          expect(success).to.equal(successArr[i])
          expect(allowance).to.equal(newAllowanceArr[i])
      }
    })

    it("add", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(30)
        const num2 = generateRandomNumber(30)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 + num2)
      }

      // Call addTest with the arrays
      await (await extendedArithmeticTests.addTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedArithmeticTests.numbers2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("checkedAdd", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = generateRandomNumber(32)
        
        if (num1 + num2 <= MAX_UINT256) { // max uint256
          // Call checkedAddTest
          await (await extendedArithmeticTests.checkedAddTest(num1, num2)).wait()

          const result = await extendedArithmeticTests.numbers2(0)
          expect(result).to.equal(num1 + num2)
        } else {
          // Expect revert
          const tx = await extendedArithmeticTests.checkedAddTest(num1, num2)

          try {
            await tx.wait()
          } catch (e) {
            const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
            expect(receipt?.status).to.be.equal(0)
          }
        }
      }
    })

    it("checkedAddWithOverflowBit", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = generateRandomNumber(32)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 + num2 > MAX_UINT256)
        expectedResults.push(num1 + num2)
      }

      // Call checkedAddWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedAddWithOverflowBitTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const bit = await extendedArithmeticTests.overflows(i)
        const bitLHS = await extendedArithmeticTests.overflowsLHS(i)
        const bitRHS = await extendedArithmeticTests.overflowsRHS(i)
        const result = await extendedArithmeticTests.numbers2(i)
        const resultLHS = await extendedArithmeticTests.numbersLHS2(i)
        const resultRHS = await extendedArithmeticTests.numbersRHS2(i)

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

    it("sub", async function () {
        const { extendedArithmeticTests } = deployment
  
        // Generate two arrays of 10 random 256-bit integers
        const numbers1: bigint[] = []
        const numbers2: bigint[] = []
        const expectedResults: bigint[] = []
  
        for (let i = 0; i < 1; i++) {
          // Generate random 256-bit integers
          const num1 = generateRandomNumber(32)
          const num2 = generateRandomNumber(32)
          
          if (num1 >= num2) {
              numbers1.push(num1)
              numbers2.push(num2)
              expectedResults.push(num1 - num2)
          } else {
            numbers1.push(num2)
            numbers2.push(num1)
            expectedResults.push(num2 - num1)
          }
        }
  
        // Call subTest with the arrays
        await (await extendedArithmeticTests.subTest(numbers1, numbers2)).wait()
  
        // Verify results
        for (let i = 0; i < 1; i++) {
          const result = await extendedArithmeticTests.numbers2(i)
          expect(result).to.equal(expectedResults[i])
        }
    })

    it("checkedSub", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = generateRandomNumber(32)
        
        if (num1 - num2 >= 0n) {
          // Call checkedSubTest
          await (await extendedArithmeticTests.checkedSubTest(num1, num2)).wait()

          const result = await extendedArithmeticTests.numbers2(0)
          expect(result).to.equal(num1 - num2)
        } else {
          // Expect revert
          const tx = await extendedArithmeticTests.checkedSubTest(num1, num2)

          try {
            await tx.wait()
          } catch (e) {
            const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
            expect(receipt?.status).to.be.equal(0)
          }
        }
      }
    })

    it("checkedSubWithOverflowBit", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = generateRandomNumber(32)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 - num2 < 0n)
        expectedResults.push(num1 - num2)
      }

      // Call checkedSubWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedSubWithOverflowBitTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const bit = await extendedArithmeticTests.overflows(i)
        const bitLHS = await extendedArithmeticTests.overflowsLHS(i)
        const bitRHS = await extendedArithmeticTests.overflowsRHS(i)
        const result = await extendedArithmeticTests.numbers2(i)
        const resultLHS = await extendedArithmeticTests.numbersLHS2(i)
        const resultRHS = await extendedArithmeticTests.numbersRHS2(i)

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

    it("mul", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers1.length < 1) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)

        if (num1 * num2 > MAX_UINT256) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 * num2)
      }

      // Call addTest with the arrays
      await (await extendedArithmeticTests.mulTest(numbers1, numbers2, 0n, { gasLimit: 80000000 })).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedArithmeticTests.numbers2(i)

        expect(result).to.equal(expectedResults[i])
      }
    })

    it("mulLHS", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers1.length < 1) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)

        if (num1 * num2 > MAX_UINT256) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 * num2)
      }

      // Call addTest with the arrays
      await (await extendedArithmeticTests.mulTest(numbers1, numbers2, 1n, { gasLimit: 80000000 })).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedArithmeticTests.numbers2(i)

        expect(result).to.equal(expectedResults[i])
      }
    })

    it("mulRHS", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers1.length < 1) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)

        if (num1 * num2 > MAX_UINT256) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 * num2)
      }

      // Call addTest with the arrays
      await (await extendedArithmeticTests.mulTest(numbers1, numbers2, 2n, { gasLimit: 80000000 })).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedArithmeticTests.numbers2(i)

        expect(result).to.equal(expectedResults[i])
      }
    })

    it("checkedMul", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 10; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)
        
        if (num1 * num2 <= MAX_UINT256) {
          // Call checkedSubTest
          await (await extendedArithmeticTests.checkedMulTest(num1, num2, 0n, { gasLimit: 80000000 })).wait()

          const result = await extendedArithmeticTests.numbers2(0)
          expect(result).to.equal(num1 * num2)
        } else {
          // Expect revert
          const tx = await extendedArithmeticTests.checkedMulTest(num1, num2, 0n, { gasLimit: 80000000 })

          try {
            await tx.wait()
          } catch (e) {
            const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
            expect(receipt?.status).to.be.equal(0)
          }
        }
      }
    })

    it("checkedMulLHS", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 10; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)
        
        if (num1 * num2 <= MAX_UINT256) {
          // Call checkedSubTest
          await (await extendedArithmeticTests.checkedMulTest(num1, num2, 1n, { gasLimit: 80000000 })).wait()

          const result = await extendedArithmeticTests.numbers2(0)
          expect(result).to.equal(num1 * num2)
        } else {
          // Expect revert
          const tx = await extendedArithmeticTests.checkedMulTest(num1, num2, 1n, { gasLimit: 80000000 })

          try {
            await tx.wait()
          } catch (e) {
            const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
            expect(receipt?.status).to.be.equal(0)
          }
        }
      }
    })

    it("checkedMulRHS", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 10; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)
        
        if (num1 * num2 <= MAX_UINT256) {
          // Call checkedSubTest
          await (await extendedArithmeticTests.checkedMulTest(num1, num2, 2n, { gasLimit: 80000000 })).wait()

          const result = await extendedArithmeticTests.numbers2(0)
          expect(result).to.equal(num1 * num2)
        } else {
          // Expect revert
          const tx = await extendedArithmeticTests.checkedMulTest(num1, num2, 2n, { gasLimit: 80000000 })

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

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 * num2 > MAX_UINT256)
        expectedResults.push(num1 * num2)
      }

      // Call checkedSubWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedMulWithOverflowBitTest(numbers1, numbers2, 0n, { gasLimit: 80000000 })).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const bit = await extendedArithmeticTests.overflows(i)
        const result = await extendedArithmeticTests.numbers2(i)

        expect(bit).to.equal(expectedOverflows[i])

        if (bit) {
          expect(result).to.not.equal(expectedResults[i])
        } else {
          expect(result).to.equal(expectedResults[i])
        }
      }
    })

    it("checkedMulWithOverflowBitLHS", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 * num2 > MAX_UINT256)
        expectedResults.push(num1 * num2)
      }

      // Call checkedSubWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedMulWithOverflowBitTest(numbers1, numbers2, 1n, { gasLimit: 80000000 })).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const bit = await extendedArithmeticTests.overflows(i)
        const result = await extendedArithmeticTests.numbers2(i)

        expect(bit).to.equal(expectedOverflows[i])

        if (bit) {
          expect(result).to.not.equal(expectedResults[i])
        } else {
          expect(result).to.equal(expectedResults[i])
        }
      }
    })

    it("checkedMulWithOverflowBitRHS", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(17)
        const num2 = generateRandomNumber(17)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 * num2 > MAX_UINT256)
        expectedResults.push(num1 * num2)
      }

      // Call checkedSubWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedMulWithOverflowBitTest(numbers1, numbers2, 2n, { gasLimit: 80000000 })).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const bit = await extendedArithmeticTests.overflows(i)
        const result = await extendedArithmeticTests.numbers2(i)

        expect(bit).to.equal(expectedOverflows[i])

        if (bit) {
          expect(result).to.not.equal(expectedResults[i])
        } else {
          expect(result).to.equal(expectedResults[i])
        }
      }
    })

    it("and", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = generateRandomNumber(32)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 & num2)
      }

      // Call addTest with the arrays
      await (await extendedBitwiseTests.andTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedBitwiseTests.numbers2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("or", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = generateRandomNumber(32)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 | num2)
      }

      // Call orTest with the arrays
      await (await extendedBitwiseTests.orTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedBitwiseTests.numbers2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("xor", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = generateRandomNumber(32)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 ^ num2)
      }

      // Call xorTest with the arrays
      await (await extendedBitwiseTests.xorTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedBitwiseTests.numbers2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("shl", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate an arrays of 10 random 256-bit integers and 10 random 8-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers2.length < 1) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(1)

        if (num1 << num2 > MAX_UINT256) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 << num2)
      }

      // Call xorTest with the arrays
      await (await extendedBitwiseTests.shlTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedBitwiseTests.numbers2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("shr", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate an arrays of 10 random 256-bit integers and 10 random 8-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers2.length < 1) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(1)

        if ((num1 & ((1n << num2) - 1n)) !== 0n) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 >> num2)
      }

      // Call xorTest with the arrays
      await (await extendedBitwiseTests.shrTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedBitwiseTests.numbers2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("eq", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 === num2)
      }

      // Call eqTest with the arrays
      await (await extendedComparisonTests.eqTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("ne", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 !== num2)
      }

      // Call neTest with the arrays
      await (await extendedComparisonTests.neTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("ge", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 >= num2)
      }

      // Call geTest with the arrays
      await (await extendedComparisonTests.geTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("gt", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 > num2)
      }

      // Call gtTest with the arrays
      await (await extendedComparisonTests.gtTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("le", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 <= num2)
      }

      // Call leTest with the arrays
      await (await extendedComparisonTests.leTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("lt", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 < num2)
      }

      // Call ltTest with the arrays
      await (await extendedComparisonTests.ltTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("min", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 <= num2 ? num1 : num2)
      }

      // Call minTest with the arrays
      await (await extendedComparisonTests.minTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.uintResults2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("max", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 256-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 1; i++) {
        // Generate random 256-bit integers
        const num1 = generateRandomNumber(32)
        const num2 = i % 2 === 0 ? generateRandomNumber(32) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 >= num2 ? num1 : num2)
      }

      // Call maxTest with the arrays
      await (await extendedComparisonTests.maxTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 1; i++) {
        const result = await extendedComparisonTests.uintResults2(i)
        expect(result).to.equal(expectedResults[i])
      }
    })
  })
})