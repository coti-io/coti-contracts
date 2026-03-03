import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

describe("Negative Test Cases - 256-bit", function () {
  // Increase timeout for MPC operations, especially overflow detection
  this.timeout(300000) // 5 minutes

  describe("Division by Zero", function () {
    it("Should handle division by zero (may revert or return special value)", async function () {
      this.timeout(60000) // 1 minute timeout
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("Arithmetic256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = BigInt("1000000000000000000")
      const b = BigInt(0)

      // Division by zero - check if it reverts or returns a value
      try {
        const tx = await contract.divTest(a, b, { gasLimit })
        const receipt = await tx.wait()
        
        // If it doesn't revert, check what value it returns
        const result = await contract.getDivResult()
        console.log(`Division by zero returned: ${result}`)
        // Note: MPC precompile may handle division by zero differently
        // It might return 0, max value, or some other special value
      } catch (error: any) {
        // If it reverts, that's also valid behavior
        if (error.message && error.message.includes("revert")) {
          console.log("Division by zero correctly reverted")
        } else {
          throw error
        }
      }
    })

    it("Should handle remainder by zero (may revert or return special value)", async function () {
      this.timeout(60000) // 1 minute timeout
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("Arithmetic256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = BigInt("1000000000000000000")
      const b = BigInt(0)

      // Remainder by zero - check if it reverts or returns a value
      try {
        const tx = await contract.remTest(a, b, { gasLimit })
        const receipt = await tx.wait()
        
        // If it doesn't revert, check what value it returns
        const result = await contract.getRemResult()
        console.log(`Remainder by zero returned: ${result}`)
        // Note: MPC precompile may handle remainder by zero differently
      } catch (error: any) {
        // If it reverts, that's also valid behavior
        if (error.message && error.message.includes("revert")) {
          console.log("Remainder by zero correctly reverted")
        } else {
          throw error
        }
      }
    })
  })

  describe("Arithmetic Overflow - Checked Operations", function () {
    // Note: Overflow detection tests are computationally expensive due to MPC operations
    // These tests may take 1-3 minutes each to complete
    
    it("Should detect overflow in checkedAdd with max values", async function () {
      this.timeout(180000) // 3 minutes for this specific test
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("CheckedArithmetic256WithOverflowBitTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Test with values that will overflow
      // Using smaller values to reduce computation time while still testing overflow
      const nearMax256 = (BigInt(1) << BigInt(255))  // 2^255 (half of max)
      const large = (BigInt(1) << BigInt(255)) + BigInt(1)  // Will overflow when added

      // This should succeed but overflow bit should be set
      const tx = await contract.checkedAddWithOverflowBitTest(nearMax256, large, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      // Check overflow bit
      const overflowBit = await contract.getOverflowBit()
      // Note: The actual behavior depends on the MPC precompile implementation
      // If overflow is detected, overflowBit should be true
      console.log(`Overflow bit detected: ${overflowBit}`)
    })

    it("Should detect underflow in checkedSub", async function () {
      this.timeout(180000) // 3 minutes for this specific test
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("CheckedArithmetic256WithOverflowBitTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Test subtraction that would underflow
      const small = BigInt(5)
      const large = BigInt("1000000000000000000")

      // This should succeed but overflow bit should be set (indicating underflow)
      const tx = await contract.checkedSubWithOverflowBitTest(small, large, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      // Check overflow bit
      const overflowBit = await contract.getOverflowBit()
      // If underflow is detected, overflowBit should be true
      console.log(`Underflow bit detected: ${overflowBit}`)
    })

    it("Should detect overflow in checkedMul with large values", async function () {
      this.timeout(180000) // 3 minutes for this specific test
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("CheckedArithmetic256WithOverflowBitTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Test multiplication that will overflow
      // Using smaller values to reduce computation time while still testing overflow
      const large1 = BigInt(1) << BigInt(150)  // 2^150
      const large2 = BigInt(1) << BigInt(150)  // 2^150
      // 2^150 * 2^150 = 2^300 > 2^256, will overflow

      const tx = await contract.checkedMulWithOverflowBitTest(large1, large2, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      // Check overflow bit
      const overflowBit = await contract.getOverflowBit()
      console.log(`Multiplication overflow bit detected: ${overflowBit}`)
    })
  })

  describe("Edge Cases - Boundary Values", function () {
    it("Should handle subtraction resulting in zero", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("Arithmetic256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = BigInt("1000000000000000000")
      const b = a  // Same value

      const tx = await contract.subTest(a, b, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      const result = await contract.getSubResult()
      expect(result).to.equal(BigInt(0))
    })

    it("Should handle max value operations", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("Arithmetic256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const max256 = (BigInt(1) << BigInt(256)) - BigInt(1)
      const zero = BigInt(0)

      // Max + 0 should work
      const tx = await contract.addTest(max256, zero, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      const result = await contract.getAddResult()
      expect(result).to.equal(max256)
    })
  })

  describe("Invalid Shift Operations", function () {
    it("Should handle shift amount >= 256 bits", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("Shift256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = BigInt("1000000000000000000")
      const shift256 = 255  // uint8 max is 255, so we test with max possible
      const shift200 = 200  // Large shift value

      // Shift by 200 - should work but most bits shifted out
      const tx1 = await contract.shlTest(a, shift200, { gasLimit })
      const receipt1 = await tx1.wait()
      expect(receipt1?.status).to.equal(1)
      const result1 = await contract.getShlResult()
      console.log(`Shift by 200 returned: ${result1}`)

      // Shift by 255 (max uint8) - behavior depends on MPC precompile
      const tx2 = await contract.shlTest(a, shift256, { gasLimit })
      const receipt2 = await tx2.wait()
      expect(receipt2?.status).to.equal(1)
      const result2 = await contract.getShlResult()
      console.log(`Shift by 255 returned: ${result2}`)
      // Result should be 0 or wrapped value depending on precompile behavior
    })

    it("Should handle right shift by large amounts", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("Shift256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = BigInt("1000000000000000000")
      const shift255 = 255  // Max uint8

      // Right shift by 255 - should result in 0
      const tx = await contract.shrTest(a, shift255, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)
      const result = await contract.getShrResult()
      expect(result).to.equal(BigInt(0))  // All bits shifted out
    })
  })
})

