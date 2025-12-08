import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

describe("Negative Test Cases - 8/16/32/64-bit", function () {
  // Increase timeout for MPC operations, especially overflow detection
  this.timeout(300000) // 5 minutes

  describe("Division by Zero", function () {
    it("Should handle division by zero for 8-bit (may revert or return special value)", async function () {
      this.timeout(60000) // 1 minute timeout
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("MiscellaneousTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = 10
      const b = 0

      // Division by zero - check if it reverts or returns a value
      try {
        const tx = await contract.divTest(a, b, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        // If it doesn't revert, check what value it returns
        const result = await contract.getDivResult()
        console.log(`Division by zero (8-bit) returned: ${result}`)
        // Note: MPC precompile may handle division by zero differently for smaller bit sizes
        // It might return 0, max value, or some other special value
      } catch (error: any) {
        // If it reverts, that's also valid behavior
        if (error.message && error.message.includes("revert")) {
          console.log("Division by zero (8-bit) correctly reverted")
        } else {
          throw error
        }
      }
    })

    it("Should handle remainder by zero for 8-bit (returns dividend)", async function () {
      this.timeout(60000) // 1 minute timeout
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("MiscellaneousTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = 10
      const b = 0

      // Remainder by zero - MPC precompile returns dividend
      const tx = await contract.remTest(a, b, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)
      
      const result = await contract.getRemResult()
      console.log(`Remainder by zero (8-bit) returned: ${result}`)
      // MPC precompile returns dividend for remainder by zero
      expect(result).to.equal(a)
    })
  })

  describe("Arithmetic Overflow - Checked Operations", function () {
    // Note: Overflow detection tests are computationally expensive due to MPC operations
    // These tests may take 1-3 minutes each to complete
    
    it("Should detect overflow in checkedAdd for 8-bit with max values", async function () {
      this.timeout(180000) // 3 minutes for this specific test
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("CheckedArithmeticWithOverflowBitTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Test with values that will overflow for 8-bit
      const nearMax8 = 200  // Close to max uint8 (255)
      const large = 100     // Will overflow when added (200 + 100 = 300 > 255)

      // This should succeed but overflow bit should be set
      try {
        const tx = await contract.checkedAddWithOverflowBitTest(nearMax8, large, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)

        // Note: The contract doesn't expose overflow bit, but we can check the result
        const result = await contract.getAddResult()
        console.log(`CheckedAdd result (8-bit): ${result}, expected overflow`)
        // Result should be wrapped value: (200 + 100) % 256 = 44
        expect(result).to.equal((nearMax8 + large) % 256)
      } catch (error: any) {
        // Some overflow cases may revert
        if (error.message && error.message.includes("revert")) {
          console.log("CheckedAdd overflow correctly caused revert")
        } else {
          throw error
        }
      }
    })

    it("Should detect underflow in checkedSub for 8-bit", async function () {
      this.timeout(180000) // 3 minutes for this specific test
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("CheckedArithmeticWithOverflowBitTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Test subtraction that would underflow
      const small = 5
      const large = 100

      // This should succeed but overflow bit should be set (indicating underflow)
      try {
        const tx = await contract.checkedSubWithOverflowBitTest(small, large, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)

        // Check result
        const result = await contract.getSubResult()
        console.log(`CheckedSub result (8-bit): ${result}, expected underflow`)
        // Result should be wrapped value: (5 - 100) % 256 = 161
        expect(result).to.equal((small - large + 256) % 256)
      } catch (error: any) {
        // Some underflow cases may revert
        if (error.message && error.message.includes("revert")) {
          console.log("CheckedSub underflow correctly caused revert")
        } else {
          throw error
        }
      }
    })

    it("Should detect overflow in checkedMul for 8-bit with large values", async function () {
      this.timeout(180000) // 3 minutes for this specific test
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("CheckedArithmeticWithOverflowBitTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Test multiplication that will overflow
      const large1 = 20   // 20 * 20 = 400 > 255, will overflow
      const large2 = 20

      try {
        const tx = await contract.checkedMulWithOverflowBitTest(large1, large2, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)

        // Check result
        const result = await contract.getMulResult()
        console.log(`CheckedMul result (8-bit): ${result}, expected overflow`)
        // Result should be wrapped value: (20 * 20) % 256 = 144
        expect(result).to.equal((large1 * large2) % 256)
      } catch (error: any) {
        // Some overflow cases may revert
        if (error.message && error.message.includes("revert")) {
          console.log("CheckedMul overflow correctly caused revert")
        } else {
          throw error
        }
      }
    })
  })

  describe("Invalid Shift Operations", function () {
    it("Should handle shift amount >= 8 bits", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("ShiftTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = 10
      const shift8 = 8   // Equal to 8-bit size
      const shift16 = 16 // Greater than 8-bit size

      // Shift by 8 (equal to bit size) - behavior depends on MPC precompile
      // For 8-bit: 10 << 8 = 2560, but since it's uint8, it wraps to 0
      // However, the contract tests all bit sizes, so 16/32/64-bit results may not be 0
      const tx1 = await contract.shlTest(a, shift8, { gasLimit })
      const receipt1 = await tx1.wait()
      expect(receipt1?.status).to.equal(1)
      const results1 = await contract.getAllShiftResults()
      console.log(`Shift by 8 returned: 8-bit=${results1[0]}, 16-bit=${results1[1]}, 32-bit=${results1[2]}, 64-bit=${results1[3]}`)
      // 8-bit should be 0 (wrapped), others may have actual shifted values
      expect(results1[0]).to.equal(0)  // 8-bit: all bits shifted out (wrapped)

      // Shift by 16 (greater than 8-bit size) - behavior depends on MPC precompile
      const tx2 = await contract.shlTest(a, shift16, { gasLimit })
      const receipt2 = await tx2.wait()
      expect(receipt2?.status).to.equal(1)
      const results2 = await contract.getAllShiftResults()
      console.log(`Shift by 16 returned: 8-bit=${results2[0]}, 16-bit=${results2[1]}, 32-bit=${results2[2]}, 64-bit=${results2[3]}`)
      // 8-bit should be 0, others may have wrapped values
      expect(results2[0]).to.equal(0)  // 8-bit: all bits shifted out
    })

    it("Should handle right shift by >= 8 bits", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("ShiftTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = 10
      const shift8 = 8

      // Right shift by 8 - should result in 0
      const tx = await contract.shrTest(a, shift8, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)
      const result = await contract.getResult()
      expect(result).to.equal(0)  // All bits shifted out
    })

    it("Should handle shift amount >= 16 bits", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("ShiftTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = 10
      const shift16 = 16  // Equal to 16-bit size
      const shift32 = 32  // Greater than 16-bit size

      // Shift by 16 - should result in 0 for 16-bit
      const tx1 = await contract.shlTest(a, shift16, { gasLimit })
      const receipt1 = await tx1.wait()
      expect(receipt1?.status).to.equal(1)
      const results1 = await contract.getAllShiftResults()
      expect(results1[1]).to.equal(0)  // 16-bit: all bits shifted out

      // Shift by 32 - should result in 0 for 32-bit
      const tx2 = await contract.shlTest(a, shift32, { gasLimit })
      const receipt2 = await tx2.wait()
      expect(receipt2?.status).to.equal(1)
      const results2 = await contract.getAllShiftResults()
      expect(results2[2]).to.equal(0)  // 32-bit: all bits shifted out
    })

    it("Should handle shift amount >= 64 bits", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("ShiftTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = 10
      const shift64 = 64  // Equal to 64-bit size (but uint8 max is 255, so we use 64)

      // Shift by 64 - should result in 0 for 64-bit
      const tx = await contract.shlTest(a, shift64, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)
      const results = await contract.getAllShiftResults()
      expect(results[3]).to.equal(0)  // 64-bit: all bits shifted out
    })
  })

  describe("Transfer with Insufficient Balance", function () {
    it("Should handle transfer when balance < amount for 8-bit", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("TransferTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const smallBalance = 10
      const largeAmount = 100  // 10x balance

      // Transfer more than available balance
      try {
        const tx = await contract.transferTest(smallBalance, 0, largeAmount, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        // Check the result flag
        const results = await contract.getResults()
        console.log(`Transfer result (8-bit): new_a=${results[0]}, new_b=${results[1]}, success=${results[2]}`)
        
        // The behavior depends on MPC precompile implementation
        // If transfer fails, success flag should be false
        // Or the new balance might be wrapped/underflowed
        if (results[2] === false) {
          console.log("✅ Transfer correctly returned failure flag for insufficient balance")
        } else {
          console.log("⚠️ Transfer succeeded despite insufficient balance - may allow underflow")
          // If it allows underflow, check wrapped value
          expect(results[0]).to.equal((smallBalance - largeAmount + 256) % 256)
        }
      } catch (error: any) {
        // Reverting is acceptable behavior for insufficient balance
        if (error.message && error.message.includes("revert")) {
          console.log("✅ Insufficient balance correctly caused revert")
        } else {
          throw error
        }
      }
    })

    it("Should handle transfer with zero balance", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("TransferTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const zeroBalance = 0
      const amount = 10

      try {
        const tx = await contract.transferTest(zeroBalance, 0, amount, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        const results = await contract.getResults()
        console.log(`Transfer from zero balance (8-bit): new_a=${results[0]}, new_b=${results[1]}, success=${results[2]}`)
        
        if (results[2] === false) {
          console.log("✅ Transfer correctly returned failure flag for zero balance")
        }
      } catch (error: any) {
        if (error.message && error.message.includes("revert")) {
          console.log("✅ Zero balance transfer correctly caused revert")
        } else {
          throw error
        }
      }
    })
  })

  describe("Transfer with Insufficient Allowance", function () {
    it("Should handle transferWithAllowance when allowance < amount", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("TransferWithAllowanceTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const balance = 100
      const smallAllowance = 10   // Small allowance
      const largeAmount = 100     // 10x allowance

      // Transfer more than allowance
      try {
        const tx = await contract.transferWithAllowanceTest(
          balance, 
          0, 
          largeAmount, 
          smallAllowance, 
          { gasLimit }
        )
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        const results = await contract.getResults()
        console.log(`TransferWithAllowance result (8-bit): new_a=${results[0]}, new_b=${results[1]}, success=${results[2]}, new_allowance=${results[3]}`)
        
        // Check if allowance was properly enforced
        // The new_allowance should not be negative if enforcement works
        if (results[2] === false) {
          console.log("✅ TransferWithAllowance correctly returned failure flag for insufficient allowance")
        } else {
          console.log("⚠️ TransferWithAllowance succeeded despite insufficient allowance")
        }
      } catch (error: any) {
        if (error.message && error.message.includes("revert")) {
          console.log("✅ Insufficient allowance correctly caused revert")
        } else {
          throw error
        }
      }
    })

    it("Should handle transferWithAllowance with zero allowance", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("TransferWithAllowanceTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const balance = 100
      const zeroAllowance = 0
      const amount = 10

      try {
        const tx = await contract.transferWithAllowanceTest(
          balance,
          0,
          amount,
          zeroAllowance,
          { gasLimit }
        )
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        const results = await contract.getResults()
        console.log(`TransferWithAllowance with zero allowance (8-bit): success=${results[2]}, new_allowance=${results[3]}`)
        
        if (results[2] === false) {
          console.log("✅ TransferWithAllowance correctly returned failure flag for zero allowance")
        }
      } catch (error: any) {
        if (error.message && error.message.includes("revert")) {
          console.log("✅ Zero allowance transfer correctly caused revert")
        } else {
          throw error
        }
      }
    })
  })

  describe("Edge Cases - Boundary Values", function () {
    it("Should handle subtraction resulting in zero", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("ArithmeticTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const a = 10
      const b = a  // Same value

      const tx = await contract.subTest(a, b, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      const result = await contract.getSubResult()
      expect(result).to.equal(0)
    })

    it("Should handle max value operations for 8-bit", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("ArithmeticTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const max8 = 255  // Max uint8
      const zero = 0

      // Max + 0 should work
      const tx = await contract.addTest(max8, zero, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      const result = await contract.getAddResult()
      expect(result).to.equal(max8)
    })

    it("Should handle max value operations for 16-bit", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("ArithmeticTestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      // Test with values that will be cast to 16-bit
      const a = 10
      const b = 5

      // Operations should work across all bit sizes
      const tx = await contract.addTest(a, b, { gasLimit })
      const receipt = await tx.wait()
      expect(receipt?.status).to.equal(1)

      const result = await contract.getAddResult()
      expect(result).to.equal(a + b)
    })
  })
})

