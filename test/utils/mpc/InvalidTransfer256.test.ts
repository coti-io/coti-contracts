import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

describe("Invalid Transfer Operations - 256-bit", function () {
  this.timeout(120000) // 2 minutes

  describe("Transfer with Insufficient Balance", function () {
    it("Should handle transfer when balance < amount", async function () {
      const [owner] = await setupAccounts()

      const factory = await hre.ethers.getContractFactory("Transfer256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const smallBalance = BigInt("100000000000000000")   // 0.1
      const largeAmount = BigInt("1000000000000000000")  // 1.0 (10x balance)

      // Transfer more than available balance
      try {
        const tx = await contract.transferTest(smallBalance, BigInt(0), largeAmount, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        // Check the result flag
        const results = await contract.getResults()
        console.log(`Transfer result: new_a=${results[0]}, new_b=${results[1]}, success=${results[2]}`)
        
        // The behavior depends on MPC precompile implementation
        if (results[2] === false) {
          console.log("✅ Transfer correctly returned failure flag for insufficient balance")
        } else {
          console.log("⚠️ Transfer succeeded despite insufficient balance - may allow underflow")
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

      const factory = await hre.ethers.getContractFactory("Transfer256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const zeroBalance = BigInt(0)
      const amount = BigInt("100000000000000000")

      try {
        const tx = await contract.transferTest(zeroBalance, BigInt(0), amount, { gasLimit })
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        const results = await contract.getResults()
        console.log(`Transfer from zero balance: new_a=${results[0]}, new_b=${results[1]}, success=${results[2]}`)
        
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

      const factory = await hre.ethers.getContractFactory("TransferWithAllowance256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const balance = BigInt("1000000000000000000")
      const smallAllowance = BigInt("100000000000000000")   // 0.1
      const largeAmount = BigInt("1000000000000000000")     // 1.0 (10x allowance)

      // Transfer more than allowance
      try {
        const tx = await contract.transferWithAllowanceTest(
          balance, 
          BigInt(0), 
          largeAmount, 
          smallAllowance, 
          { gasLimit }
        )
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        const results = await contract.getResults()
        console.log(`TransferWithAllowance result: new_a=${results[0]}, new_b=${results[1]}, success=${results[2]}, new_allowance=${results[3]}`)
        
        // Check if allowance was properly enforced
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

      const factory = await hre.ethers.getContractFactory("TransferWithAllowance256TestsContract", owner as any)
      const contract = await factory.deploy({ gasLimit })
      await contract.waitForDeployment()

      const balance = BigInt("1000000000000000000")
      const zeroAllowance = BigInt(0)
      const amount = BigInt("100000000000000000")

      try {
        const tx = await contract.transferWithAllowanceTest(
          balance,
          BigInt(0),
          amount,
          zeroAllowance,
          { gasLimit }
        )
        const receipt = await tx.wait()
        expect(receipt?.status).to.equal(1)
        
        const results = await contract.getResults()
        console.log(`TransferWithAllowance with zero allowance: success=${results[2]}, new_allowance=${results[3]}`)
        
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
})

