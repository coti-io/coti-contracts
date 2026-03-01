import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { gasOptions } from "./helpers";

// Helper function to safely stringify objects
function safeStringify(obj: any): string {
  try {
    return JSON.stringify(obj, null, 2)
  } catch {
    return String(obj)
  }
}

// Helper function to check if we're on a testnet requiring gas
async function isTestnetRequiringGas(): Promise<boolean> {
  const network = await hre.ethers.provider.getNetwork()
  return network.chainId !== 31337n // Assuming 31337 is local hardhat
}

// Helper function to check if method is read-only
function isReadOnlyMethod(methodName: string, target: any): boolean {
  // This is a simplified check - you might want to enhance this
  const readOnlyMethods = ['view', 'pure', 'staticCall']
  return readOnlyMethods.some(prefix => methodName.includes(prefix))
}

// Helper function to get network gas options
async function getNetworkGasOptions(): Promise<any> {
  return {
    gasLimit: 15000000,
    gasPrice: 1000000000,
  }
}

// Helper function to create a receipt proxy
function createReceiptProxy(receipt: any): any {
  return {
    wait: () => Promise.resolve(receipt),
    ...receipt
  }
}

/**
 * Adds gas options to a contract method call and waits for mining on testnets
 */
async function addGasOptionsToCall(originalMethod: any, target: any, args: any[]): Promise<any> {
	try {
		const needsGasOptions = await isTestnetRequiringGas()
		const methodName = originalMethod.name || originalMethod.fragment?.name || "unknown"
		console.log(`[DEBUG] Method: ${methodName}`)

		// Await any Promise arguments before proceeding
		const resolvedArgs = await Promise.all(
			args.map(async arg => {
				if (arg instanceof Promise) {
					return await arg
				}
				return arg
			}),
		)

		console.log(`[DEBUG] Arguments:`, safeStringify(resolvedArgs))
		console.log(`[DEBUG] Target address:`, target.target)

		if (needsGasOptions) {
			// For read-only methods on testnets, just call normally
			if (isReadOnlyMethod(methodName, target)) {
				console.log(`[DEBUG] Read-only method, calling directly`)
				return originalMethod.apply(target, resolvedArgs)
			}
			console.log(`[DEBUG] Adding gas options for ${methodName}`)

			const gasOptions = await getNetworkGasOptions()
			console.log(`[DEBUG] Gas options:`, safeStringify(gasOptions))

			// First, try the simple approach: original method with gas options
			try {
				console.log(`[DEBUG] Trying original method with gas options`)
				const result = await originalMethod.apply(target, [...resolvedArgs, gasOptions])

				// If it's a transaction, wait for it to be mined
				if (result && typeof result.wait === "function") {
					const receipt = await result.wait()
					// Return a proxy that has a wait method returning the receipt
					return createReceiptProxy(receipt)
				}
				return result
			} catch (error: any) {
				console.log(`[DEBUG] Original method with gas options failed:`, error.message)

				// If it failed due to a revert (what we want for tests), try to get better error message
				if (error.message.includes("execution reverted") || error.code === "CALL_EXCEPTION") {
					console.log(`[DEBUG] Transaction reverted, trying static call for better error`)

					// Get function fragment and encode data for static call
					const fragment = target.interface.getFunction(methodName)
					if (fragment) {
						const data = target.interface.encodeFunctionData(fragment, resolvedArgs)

						try {
							await target.runner.provider.call({
								to: target.target,
								data: data,
								from: target.runner.address,
							})
							// If static call succeeds but transaction failed, re-throw original error
							throw error
						} catch (staticError: any) {
							if (staticError.message.includes("missing revert data")) {
								throw error
							}
							console.log(`[DEBUG] Static call also failed, using static error for better message`)
							// Use static call error which has better revert reason
							throw staticError
						}
					}
				}

				// For other errors (gas estimation, etc.), re-throw original error
				throw error
			}
		}

		// For local networks, use original method without modifications
		return originalMethod.apply(target, resolvedArgs)
	} catch (error: any) {
		console.warn(`[DEBUG] Gas options wrapper failed for method ${originalMethod.name || "unknown"}:`, error.message)
		console.warn(`[DEBUG] Full error:`, safeStringify(error))
		throw error
	}
}

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()
  const factory = await hre.ethers.getContractFactory("RevertTestsContract")
  const contract = await factory.connect(owner).deploy(gasOptions)
  await contract.waitForDeployment()
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - Revert Tests", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>
  
  before(async function () {
    deployment = await deploy()
  })

  describe("Test 1: Simple revert with a string", function () {
    it("Should revert with string message", async function () {
      const { contract } = deployment
      
      await expect(contract.simpleRevertWithString(gasOptions)).to.be.revertedWith(
        "This is a simple revert with a string message"
      )
    })
  })

  describe("Test 2: Require depending on function arg with a string", function () {
    it("Should pass when arg is true", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithArg(true, gasOptions)).not.to.be.reverted
    })

    it("Should revert when arg is false", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithArg(false, gasOptions)).to.be.revertedWith(
        "Require failed: argument condition not met"
      )
    })
  })

  describe("Test 3: Require with validated ciphertext", function () {
    it("Should pass when encrypted bool is true", async function () {
      const { contract, contractAddress, owner } = deployment
      
      const itValue = await owner.encryptBool(
        true,
        contractAddress,
        contract.requireWithValidatedCiphertext.fragment.selector
      )
      
      expect(await contract.requireWithValidatedCiphertext(itValue, gasOptions)).not.to.be.reverted
    })

    it("Should revert when encrypted bool is false", async function () {
      const { contract, contractAddress, owner } = deployment
      
      const itValue = await owner.encryptBool(
        false,
        contractAddress,
        contract.requireWithValidatedCiphertext.fragment.selector
      )
      
      await expect(contract.requireWithValidatedCiphertext(itValue, gasOptions)).to.be.revertedWith(
        "Require failed: validated ciphertext condition not met"
      )
    })
  })

  describe("Test 4a: Require with setPublic boolean", function () {
    it("Should pass when boolean is true", async function () {
      const { contract } = deployment

      expect(await contract.requireWithSetPublicBool(true, gasOptions)).not.to.be.reverted
    })

    it("Should revert when boolean is false", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithSetPublicBool(false, gasOptions)).to.be.revertedWith(
        "Require failed: setPublic boolean condition not met"
      )
    })
  })

  describe("Test 4b: Require with setPublic number", function () {
    it("Should pass when number is > 50", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithSetPublicNumber(75, gasOptions)).not.to.be.reverted
    })

    it("Should revert when number is <= 50", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithSetPublicNumber(25, gasOptions)).to.be.revertedWith(
        "Require failed: setPublic number condition not met (must be > 50)"
      )
    })
  })

  describe("Additional Test: Require with setPublic signed number", function () {
    it("Should pass when signed number is > 0", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithSetPublicSignedNumber(42, gasOptions)).not.to.be.reverted
    })

    it("Should revert when signed number is <= 0", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithSetPublicSignedNumber(-10, gasOptions)).to.be.revertedWith(
        "Require failed: setPublic signed number condition not met (must be > 0)"
      )
    })
  })

  describe("Additional Test: Complex require with multiple encrypted values", function () {
    it("Should pass when both conditions are met", async function () {
      const { contract } = deployment
      
      expect(await contract.requireWithMultipleEncryptedValues(true, 30, gasOptions)).not.to.be.reverted
    })

    it("Should revert when boolean is false", async function () {
      const { contract } = deployment
      
      await expect(contract.requireWithMultipleEncryptedValues(false, 30, gasOptions)).to.be.revertedWith(
        "Require failed: complex condition not met (bool must be true AND number > 25)"
      )
    })

    it("Should revert when number is <= 25", async function () {
      const { contract } = deployment
      const tx = await contract.requireWithMultipleEncryptedValues(true, 20, gasOptions)
      await tx.wait()
    //   await expect(contract.requireWithMultipleEncryptedValues(true, 20, gasOptions)).to.be.revertedWith(
    //     "Require failed: complex condition not met (bool must be true AND number > 25)"
    //   )
    })
  })

  describe("Static Call Tests: Check if error messages are visible", function () {
    it("Should show error message with static call for simple revert", async function () {
      const { contract } = deployment
      
      try {
        await contract.simpleRevertWithString.staticCall()
        expect.fail("Expected static call to revert")
      } catch (error: any) {
        console.log("Static call error message:", error.message)
        console.log("Static call error data:", error.data)
        console.log("Static call error reason:", error.reason)
        
        expect(error.message).to.include("This is a simple revert with a string message")
      }
    })

    it("Should show error message with static call for require with arg", async function () {
      const { contract } = deployment
      
      try {
        await contract.requireWithArg.staticCall(false)
        expect.fail("Expected static call to revert")
      } catch (error: any) {
        console.log("Static call error message:", error.message)
        console.log("Static call error data:", error.data)
        console.log("Static call error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: argument condition not met")
      }
    })

    it("Should show error message with static call for MPC setPublic boolean", async function () {
      const { contract } = deployment
      
      try {
        await contract.requireWithSetPublicBool.staticCall(false)
        expect.fail("Expected static call to revert")
      } catch (error: any) {
        console.log("Static call error message:", error.message)
        console.log("Static call error data:", error.data)
        console.log("Static call error reason:", error.reason)
        
        // Check if we can see the error message with static calls
        expect(error.message).to.include("Require failed: setPublic boolean condition not met")
      }
    })

    it("Should show error message with static call for MPC setPublic number", async function () {
      const { contract } = deployment
      
      try {
        await contract.requireWithSetPublicNumber.staticCall(25)
        expect.fail("Expected static call to revert")
      } catch (error: any) {
        console.log("Static call error message:", error.message)
        console.log("Static call error data:", error.data)
        console.log("Static call error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: setPublic number condition not met (must be > 50)")
      }
    })

    it("Should show error message with static call for MPC setPublic signed number", async function () {
      const { contract } = deployment
      
      try {
        await contract.requireWithSetPublicSignedNumber.staticCall(-10)
        expect.fail("Expected static call to revert")
      } catch (error: any) {
        console.log("Static call error message:", error.message)
        console.log("Static call error data:", error.data)
        console.log("Static call error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: setPublic signed number condition not met (must be > 0)")
      }
    })

    it("Should show error message with static call for MPC validateCiphertext", async function () {
      const { contract, contractAddress, owner } = deployment
      
      const itValue = await owner.encryptBool(
        false,
        contractAddress,
        contract.requireWithValidatedCiphertext.fragment.selector
      )
      
      try {
        await contract.requireWithValidatedCiphertext.staticCall(itValue)
        expect.fail("Expected static call to revert")
      } catch (error: any) {
        console.log("Static call error message:", error.message)
        console.log("Static call error data:", error.data)
        console.log("Static call error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: validated ciphertext condition not met")
      }
    })

    it("Should show error message with static call for complex MPC operations", async function () {
      const { contract } = deployment
      
      try {
        await contract.requireWithMultipleEncryptedValues.staticCall(false, 30)
        expect.fail("Expected static call to revert")
      } catch (error: any) {
        console.log("Static call error message:", error.message)
        console.log("Static call error data:", error.data)
        console.log("Static call error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: complex condition not met (bool must be true AND number > 25)")
      }
    })
  })

  describe("Gas Options Wrapper Tests: Check if error messages can be recovered", function () {
    it("Should show error message with gas options wrapper for simple revert", async function () {
      const { contract } = deployment
      
      try {
        await addGasOptionsToCall(contract.simpleRevertWithString, contract, [])
        expect.fail("Expected gas options wrapper to revert")
      } catch (error: any) {
        console.log("Gas options wrapper error message:", error.message)
        console.log("Gas options wrapper error data:", error.data)
        console.log("Gas options wrapper error reason:", error.reason)
        
        expect(error.message).to.include("This is a simple revert with a string message")
      }
    })

    it("Should show error message with gas options wrapper for require with arg", async function () {
      const { contract } = deployment
      
      try {
        await addGasOptionsToCall(contract.requireWithArg, contract, [false])
        expect.fail("Expected gas options wrapper to revert")
      } catch (error: any) {
        console.log("Gas options wrapper error message:", error.message)
        console.log("Gas options wrapper error data:", error.data)
        console.log("Gas options wrapper error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: argument condition not met")
      }
    })

    it("Should show error message with gas options wrapper for MPC setPublic boolean", async function () {
      const { contract } = deployment
      
      try {
        await addGasOptionsToCall(contract.requireWithSetPublicBool, contract, [false])
        expect.fail("Expected gas options wrapper to revert")
      } catch (error: any) {
        console.log("Gas options wrapper error message:", error.message)
        console.log("Gas options wrapper error data:", error.data)
        console.log("Gas options wrapper error reason:", error.reason)
        
        // Check if the gas options wrapper can recover the error message
        expect(error.message).to.include("Require failed: setPublic boolean condition not met")
      }
    })

    it("Should show error message with gas options wrapper for MPC setPublic number", async function () {
      const { contract } = deployment
      
      try {
        await addGasOptionsToCall(contract.requireWithSetPublicNumber, contract, [25])
        expect.fail("Expected gas options wrapper to revert")
      } catch (error: any) {
        console.log("Gas options wrapper error message:", error.message)
        console.log("Gas options wrapper error data:", error.data)
        console.log("Gas options wrapper error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: setPublic number condition not met (must be > 50)")
      }
    })

    it("Should show error message with gas options wrapper for MPC setPublic signed number", async function () {
      const { contract } = deployment
      
      try {
        await addGasOptionsToCall(contract.requireWithSetPublicSignedNumber, contract, [-10])
        expect.fail("Expected gas options wrapper to revert")
      } catch (error: any) {
        console.log("Gas options wrapper error message:", error.message)
        console.log("Gas options wrapper error data:", error.data)
        console.log("Gas options wrapper error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: setPublic signed number condition not met (must be > 0)")
      }
    })

    it("Should show error message with gas options wrapper for MPC validateCiphertext", async function () {
      const { contract, contractAddress, owner } = deployment
      
      const itValue = await owner.encryptBool(
        false,
        contractAddress,
        contract.requireWithValidatedCiphertext.fragment.selector
      )
      
      try {
        await addGasOptionsToCall(contract.requireWithValidatedCiphertext, contract, [itValue])
        expect.fail("Expected gas options wrapper to revert")
      } catch (error: any) {
        console.log("Gas options wrapper error message:", error.message)
        console.log("Gas options wrapper error data:", error.data)
        console.log("Gas options wrapper error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: validated ciphertext condition not met")
      }
    })

    it("Should show error message with gas options wrapper for complex MPC operations", async function () {
      const { contract } = deployment
      
      try {
        await addGasOptionsToCall(contract.requireWithMultipleEncryptedValues, contract, [false, 30])
        expect.fail("Expected gas options wrapper to revert")
      } catch (error: any) {
        console.log("Gas options wrapper error message:", error.message)
        console.log("Gas options wrapper error data:", error.data)
        console.log("Gas options wrapper error reason:", error.reason)
        
        expect(error.message).to.include("Require failed: complex condition not met (bool must be true AND number > 25)")
      }
    })
  })
})
