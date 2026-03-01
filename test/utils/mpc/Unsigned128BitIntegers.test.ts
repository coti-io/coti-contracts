import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { generateRandomNumber } from "./helpers"
import { ItUint128Struct } from "../../../typechain-types/contracts/mocks/utils/mpc/Miscellaneous128BitTestsContract"


const MAX_UINT128 = BigInt('0xffffffffffffffffffffffffffffffff')

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const extendedMiscellaneousTestsContract = await hre.ethers.getContractFactory("Miscellaneous128BitTestsContract")
  const extendedMiscellaneousTests = await extendedMiscellaneousTestsContract.connect(owner).deploy()
  await extendedMiscellaneousTests.waitForDeployment()

  const extendedArithmeticTestsContract = await hre.ethers.getContractFactory("Arithmetic128BitTestsContract")
  const extendedArithmeticTests = await extendedArithmeticTestsContract.connect(owner).deploy()
  await extendedArithmeticTests.waitForDeployment()

  const extendedBitwiseTestsContract = await hre.ethers.getContractFactory("Bitwise128BitTestsContract")
  const extendedBitwiseTests = await extendedBitwiseTestsContract.connect(owner).deploy()
  await extendedBitwiseTests.waitForDeployment()

  const extendedComparisonTestsContract = await hre.ethers.getContractFactory("Comparison128BitTestsContract")
  const extendedComparisonTests = await extendedComparisonTestsContract.connect(owner).deploy()
  await extendedComparisonTests.waitForDeployment()

  return { extendedMiscellaneousTests, extendedArithmeticTests, extendedBitwiseTests, extendedComparisonTests, owner }
}

describe("MPC Core", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("128-bit unsigned integers", function () {
    it("validateCiphertext", async function () {
        const { extendedMiscellaneousTests, owner } = deployment

        // Generate two arrays of 10 random 128-bit integers
        const numbers: bigint[] = []
        const encryptedNumbers: ItUint128Struct[] = []

        for (let i = 0; i < 100; i++) {
          // Generate random 128-bit integers
          const number = generateRandomNumber(16)

          numbers.push(number)
          encryptedNumbers.push(
            await owner.encryptUint128(
              number,
              await extendedMiscellaneousTests.getAddress(),
              extendedMiscellaneousTests.validateCiphertextTest.fragment.selector
            )
          )
        }

        // Call validateCiphertextTest with the array
        await (await extendedMiscellaneousTests.validateCiphertextTest(encryptedNumbers)).wait()

        // Verify results
        for (let i = 0; i < 100; i++) {
            const result = await extendedMiscellaneousTests.numbers(i)
            expect(result).to.equal(numbers[i])
        }
    })

    it("offBoardToUser", async function () {
      const { extendedMiscellaneousTests, owner } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers: bigint[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        numbers.push(generateRandomNumber(16))
      }

      // Call validateCiphertextTest with the array
      await (await extendedMiscellaneousTests.offBoardToUserTest(numbers)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
          const ctNumber = await extendedMiscellaneousTests.ctNumbers(i)

          const result = await owner.decryptUint128(ctNumber)

          expect(result).to.equal(numbers[i])
      }
    })

    it("setPublic", async function () {
        const { extendedMiscellaneousTests } = deployment

        // Generate two arrays of 10 random 128-bit integers
        const numbers: bigint[] = []

        for (let i = 0; i < 100; i++) {
            // Generate random 128-bit integers
            numbers.push(generateRandomNumber(16))
        }

        // Call setPublicTest with the arrays
        await (await extendedMiscellaneousTests.setPublicTest(numbers)).wait()

        // Verify results
        for (let i = 0; i < 100; i++) {
            const result = await extendedMiscellaneousTests.numbers(i)
            expect(result).to.equal(numbers[i])
        }
    })

    it("rand", async function () {
        const { extendedMiscellaneousTests } = deployment

        const length: bigint = generateRandomNumber(1)

        // Call setPublicTest with the arrays
        await (await extendedMiscellaneousTests.randTest(length)).wait()

        // Verify results
        for (let i = 0; i < length; i++) {
            const result = await extendedMiscellaneousTests.numbers(i)
            expect(result).to.not.equal(0n)
        }
    })

    it("randBoundedBits", async function () {
      const { extendedMiscellaneousTests } = deployment

      // Generate an array of 10 random 8-bit integers
      const numbers: bigint[] = []

      while (numbers.length < 10) {
          // Generate random 8-bit integers
          const number = generateRandomNumber(1)

          if (number <= 128n) {
            numbers.push(number)
          }
      }

      // Call setPublicTest with the arrays
      await (await extendedMiscellaneousTests.randBoundedBitsTest(numbers)).wait()

      // Verify results
      for (let i = 0; i < 10; i++) {
          const result = await extendedMiscellaneousTests.numbers(i)
          expect(result).to.not.equal(0n)
      }
    })
    
    it("transfer", async function () {
      const { extendedMiscellaneousTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const aArr: bigint[] = []
      const bArr: bigint[] = []
      const amountArr: bigint[] = []
      const newA: bigint[] = []
      const newB: bigint[] = []
      const successArr: boolean[] = []

      while (aArr.length < 100) {
          // Generate random 128-bit integers

          const a = generateRandomNumber(15)
          const b = generateRandomNumber(15)
          const amount = generateRandomNumber(15)

          if (b + amount > MAX_UINT128) continue

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
      for (let i = 0; i < 100; i++) {
          const a = await extendedMiscellaneousTests.a(i)
          const b = await extendedMiscellaneousTests.b(i)
          const success = await extendedMiscellaneousTests.success(i)

          expect(a).to.equal(newA[i])
          expect(b).to.equal(newB[i])
          expect(success).to.equal(successArr[i])
      }
    })

    it("transferWithAllowance", async function () {
      const { extendedMiscellaneousTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const aArr: bigint[] = []
      const bArr: bigint[] = []
      const amountArr: bigint[] = []
      const allowanceArr: bigint[] = []
      const newA: bigint[] = []
      const newB: bigint[] = []
      const successArr: boolean[] = []
      const newAllowanceArr: bigint[] = []

      while (aArr.length < 50) {
          // Generate random 128-bit integers

          const a = generateRandomNumber(15)
          const b = generateRandomNumber(15)
          const amount = generateRandomNumber(15)
          const allowance = generateRandomNumber(15)

          if (b + amount > MAX_UINT128) continue

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
      for (let i = 0; i < 50; i++) {
          const a = await extendedMiscellaneousTests.a(i)
          const b = await extendedMiscellaneousTests.b(i)
          const success = await extendedMiscellaneousTests.success(i)
          const allowance = await extendedMiscellaneousTests.allowance(i)

          expect(a).to.equal(newA[i])
          expect(b).to.equal(newB[i])
          expect(success).to.equal(successArr[i])
          expect(allowance).to.equal(newAllowanceArr[i])
      }
    })

    it("add", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(15)
        const num2 = generateRandomNumber(15)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 + num2)
      }

      // Call addTest with the arrays
      await (await extendedArithmeticTests.addTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedArithmeticTests.numbers(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("checkedAdd", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 10; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(16)
        
        if (num1 + num2 <= MAX_UINT128) { // max uint128
          // Call checkedAddTest
          await (await extendedArithmeticTests.checkedAddTest(num1, num2)).wait()

          const result = await extendedArithmeticTests.numbers(0)
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

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 50; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(16)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 + num2 > MAX_UINT128)
        expectedResults.push(num1 + num2)
      }

      // Call checkedAddWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedAddWithOverflowBitTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 50; i++) {
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

    it("sub", async function () {
        const { extendedArithmeticTests } = deployment
  
        // Generate two arrays of 10 random 128-bit integers
        const numbers1: bigint[] = []
        const numbers2: bigint[] = []
        const expectedResults: bigint[] = []
  
        for (let i = 0; i < 100; i++) {
          // Generate random 128-bit integers
          const num1 = generateRandomNumber(16)
          const num2 = generateRandomNumber(16)
          
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
        for (let i = 0; i < 100; i++) {
          const result = await extendedArithmeticTests.numbers(i)
          expect(result).to.equal(expectedResults[i])
        }
    })

    it("checkedSub", async function () {
      const { extendedArithmeticTests, owner } = deployment

      for (let i = 0; i < 10; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(16)
        
        if (num1 - num2 >= 0n) {
          // Call checkedSubTest
          await (await extendedArithmeticTests.checkedSubTest(num1, num2)).wait()

          const result = await extendedArithmeticTests.numbers(0)
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

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedOverflows: boolean[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 50; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(16)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedOverflows.push(num1 - num2 < 0n)
        expectedResults.push(num1 - num2)
      }

      // Call checkedSubWithOverflowBitTest with the arrays
      await (await extendedArithmeticTests.checkedSubWithOverflowBitTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 50; i++) {
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

    it("mul", async function () {
      const { extendedArithmeticTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers1.length < 3) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(10)
        const num2 = generateRandomNumber(8)

        if (num1 * num2 > MAX_UINT128) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 * num2)
      }

      // Call addTest with the arrays
      await (await extendedArithmeticTests.mulTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 3; i++) {
        const result = await extendedArithmeticTests.numbers(i)

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

      for (let i = 0; i < 3; i++) {
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
      for (let i = 0; i < 3; i++) {
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

    it("div", async function () {
      const { extendedArithmeticTests } = deployment

      // Hardcoded test cases for each division scenario
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      // Case 1: Both numbers fit in 64 bits (a.high == 0 && b.high == 0)
      numbers1.push(10n)
      numbers2.push(5n)
      expectedResults.push(2n)
      
      numbers1.push(1000000n)
      numbers2.push(3n)
      expectedResults.push(333333n)

      // Case 2: Large dividend, small divisor (a.high != 0 && b.high == 0) 
      // Use 2^70 ÷ 1000 = 1180591620717411303424 ÷ 1000 = 1180591620717411303
      numbers1.push(1180591620717411303424n) // 2^70
      numbers2.push(1000n)
      expectedResults.push(1180591620717411303n)
      
      // Use 2^65 ÷ 7 = 36893488147419103232 ÷ 7 = 5270498592488443318
      numbers1.push(36893488147419103232n) // 2^65
      numbers2.push(7n)
      expectedResults.push(5270498306774157604n)

      // Case 3: Both numbers are large (a.high != 0 && b.high != 0)
      // Use 2^100 ÷ 2^70 = large ÷ large
      numbers1.push(1267650600228229401496703205376n) // 2^100  
      numbers2.push(1180591620717411303424n) // 2^70 (this has high != 0)
      expectedResults.push(1073741824n) // 2^30
      
      // Use another case: 2^80 ÷ 2^65 = 32768
      numbers1.push(1208925819614629174706176n) // 2^80
      numbers2.push(36893488147419103232n) // 2^65 (this has high != 0)  
      expectedResults.push(32768n) // 2^15

      // Add some random test cases
      for (let i = 0; i < 4; i++) {
        // Generate random 128-bit integers, ensuring divisor is not zero
        const num1 = generateRandomNumber(10)
        let num2 = generateRandomNumber(8)
        
        // Ensure divisor is not zero
        if (num2 === 0n) {
          num2 = 1n
        }
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 / num2)
      }

      const cases = numbers1.length
      console.log(`Testing ${cases} division cases:`)
      for (let i = 0; i < cases; i++) {
        console.log(`Case ${i + 1}: ${numbers1[i].toString()} ÷ ${numbers2[i].toString()} = ${expectedResults[i].toString()}`)
        
        // Determine which case this should be
        const aHigh = numbers1[i] >> 64n
        const bHigh = numbers2[i] >> 64n
        let caseType = ""
        if (aHigh === 0n && bHigh === 0n) caseType = "Case 1 (both 64-bit)"
        else if (aHigh !== 0n && bHigh === 0n) caseType = "Case 2 (128÷64-bit)"
        else if (aHigh !== 0n && bHigh !== 0n) caseType = "Case 3 (both 128-bit)"
        console.log(`  -> ${caseType}`)
      }

      // Call divTest with the arrays
      await (await extendedArithmeticTests.divTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < cases; i++) {
        const result = await extendedArithmeticTests.numbers(i)
        console.log(`Result ${i + 1}: ${result.toString()}, Expected: ${expectedResults[i].toString()}`)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("and", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(16)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 & num2)
      }

      // Call addTest with the arrays
      await (await extendedBitwiseTests.andTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedBitwiseTests.numbers(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("or", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(16)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 | num2)
      }

      // Call orTest with the arrays
      await (await extendedBitwiseTests.orTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedBitwiseTests.numbers(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("xor", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = generateRandomNumber(16)
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 ^ num2)
      }

      // Call xorTest with the arrays
      await (await extendedBitwiseTests.xorTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedBitwiseTests.numbers(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("shl", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate an arrays of 10 random 128-bit integers and 10 random 8-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers2.length < 10) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(8)
        const num2 = generateRandomNumber(1)

        if (num1 << num2 > MAX_UINT128) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 << num2)
      }

      // Call xorTest with the arrays
      await (await extendedBitwiseTests.shlTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 10; i++) {
        const result = await extendedBitwiseTests.numbers(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("shr", async function () {
      const { extendedBitwiseTests } = deployment

      // Generate an arrays of 10 random 128-bit integers and 10 random 8-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      while (numbers2.length < 10) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(8)
        const num2 = generateRandomNumber(1)

        if ((num1 & ((1n << num2) - 1n)) !== 0n) continue
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 >> num2)
      }

      // Call xorTest with the arrays
      await (await extendedBitwiseTests.shrTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 10; i++) {
        const result = await extendedBitwiseTests.numbers(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("eq", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 === num2)
      }

      // Call eqTest with the arrays
      await (await extendedComparisonTests.eqTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("ne", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 !== num2)
      }

      // Call neTest with the arrays
      await (await extendedComparisonTests.neTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("ge", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 >= num2)
      }

      // Call geTest with the arrays
      await (await extendedComparisonTests.geTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("gt", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 > num2)
      }

      // Call gtTest with the arrays
      await (await extendedComparisonTests.gtTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("le", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 <= num2)
      }

      // Call leTest with the arrays
      await (await extendedComparisonTests.leTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("lt", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: boolean[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 < num2)
      }

      // Call ltTest with the arrays
      await (await extendedComparisonTests.ltTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.boolResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("min", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 <= num2 ? num1 : num2)
      }

      // Call minTest with the arrays
      await (await extendedComparisonTests.minTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.uintResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })

    it("max", async function () {
      const { extendedComparisonTests } = deployment

      // Generate two arrays of 10 random 128-bit integers
      const numbers1: bigint[] = []
      const numbers2: bigint[] = []
      const expectedResults: bigint[] = []

      for (let i = 0; i < 100; i++) {
        // Generate random 128-bit integers
        const num1 = generateRandomNumber(16)
        const num2 = i % 2 === 0 ? generateRandomNumber(16) : num1
        
        numbers1.push(num1)
        numbers2.push(num2)
        expectedResults.push(num1 >= num2 ? num1 : num2)
      }

      // Call maxTest with the arrays
      await (await extendedComparisonTests.maxTest(numbers1, numbers2)).wait()

      // Verify results
      for (let i = 0; i < 100; i++) {
        const result = await extendedComparisonTests.uintResults(i)
        expect(result).to.equal(expectedResults[i])
      }
    })
  })
})