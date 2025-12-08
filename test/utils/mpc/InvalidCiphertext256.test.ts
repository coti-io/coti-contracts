import hre from "hardhat"
import { expect } from "chai"
import { Buffer } from "buffer"
import { setupAccounts } from "../accounts"
import { Wallet, itUint256 } from "@coti-io/coti-ethers"
import { ValidateCiphertext256TestsContract } from "../../../typechain-types"

const GAS_LIMIT = 12000000

async function deploy() {
    const [owner] = await setupAccounts()
    const contractFactory = await hre.ethers.getContractFactory("ValidateCiphertext256TestsContract", owner as any)
    const contract = await contractFactory.deploy({ gasLimit: GAS_LIMIT })
    await contract.waitForDeployment()
    return {
        contract,
        contractAddress: await contract.getAddress(),
        owner
    }
}

describe("Invalid Ciphertext Validation - 256-bit", function () {
    this.timeout(120000) // 2 minutes
    let contract: ValidateCiphertext256TestsContract
    let contractAddress: string
    let owner: Wallet

    before(async function () {
        const deployment = await deploy()
        contract = deployment.contract
        contractAddress = deployment.contractAddress
        owner = deployment.owner
    })

    describe("Invalid Signature Tests", function () {
        it("Should reject ciphertext with invalid signature (all zeros)", async function () {
            // Create valid ciphertext
            const testValue = (2n ** 128n) + BigInt("1000000000000000000")  // > 128 bits
            const validItUint = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            // Corrupt the signature - convert to Buffer
            const invalidSignature = Buffer.from("00".repeat(64), "hex")
            
            const invalidItUint: itUint256 = {
                ciphertext: validItUint.ciphertext,
                signature: invalidSignature
            }

            // Should revert or return false
            try {
                const tx = await contract.validateAndStore(invalidItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                
                // Check validation result
                const validationResult = await contract.getValidationResult()
                expect(validationResult).to.equal(false, "Invalid signature should fail validation")
                console.log("✅ Invalid signature correctly failed validation")
            } catch (error: any) {
                // Reverting is also acceptable behavior
                if (error.message && error.message.includes("revert")) {
                    console.log("✅ Invalid signature correctly caused revert")
                } else {
                    throw error
                }
            }
        })

        it("Should reject ciphertext with wrong contract address signature", async function () {
            // Create ciphertext signed for different contract
            const wrongAddress = "0x" + "11".repeat(20)  // Different address
            const testValue = (2n ** 128n) + BigInt("1000000000000000000")
            
            // This should fail because signature is for wrong address
            const itUint = await owner.encryptValue256(
                testValue,
                wrongAddress,  // Wrong address
                contract.validateAndStore.fragment.selector
            )

            // Try to validate with correct contract address
            try {
                const tx = await contract.validateAndStore(itUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                
                // Check validation result
                const validationResult = await contract.getValidationResult()
                expect(validationResult).to.equal(false, "Wrong address signature should fail")
                console.log("✅ Wrong address signature correctly failed validation")
            } catch (error: any) {
                if (error.message && error.message.includes("revert")) {
                    console.log("✅ Wrong address signature correctly caused revert")
                } else {
                    throw error
                }
            }
        })

        it("Should reject ciphertext with corrupted signature", async function () {
            const testValue = (2n ** 128n) + BigInt("1000000000000000000")
            const validItUint = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            // Convert signature to Buffer, corrupt it
            const sigBuffer = Buffer.isBuffer(validItUint.signature) 
                ? Buffer.from(validItUint.signature)
                : Buffer.from(validItUint.signature)
            
            // Flip first byte
            sigBuffer[0] = sigBuffer[0] ^ 0xFF

            const corruptedItUint: itUint256 = {
                ciphertext: validItUint.ciphertext,
                signature: sigBuffer
            }

            try {
                const tx = await contract.validateAndStore(corruptedItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                
                const validationResult = await contract.getValidationResult()
                expect(validationResult).to.equal(false, "Corrupted signature should fail")
                console.log("✅ Corrupted signature correctly failed validation")
            } catch (error: any) {
                if (error.message && error.message.includes("revert")) {
                    console.log("✅ Corrupted signature correctly caused revert")
                } else {
                    throw error
                }
            }
        })
    })

    describe("Corrupted Ciphertext Tests", function () {
        it("Should handle corrupted ciphertext data", async function () {
            const testValue = (2n ** 128n) + BigInt("1000000000000000000")
            const validItUint = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            // Corrupt the ciphertext by modifying high or low parts
            const corruptedItUint: itUint256 = {
                ciphertext: {
                    ciphertextHigh: (BigInt(validItUint.ciphertext.ciphertextHigh) ^ BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")).toString(),
                    ciphertextLow: validItUint.ciphertext.ciphertextLow
                },
                signature: validItUint.signature
            }

            // Should fail validation
            try {
                const tx = await contract.validateAndStore(corruptedItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                
                const validationResult = await contract.getValidationResult()
                expect(validationResult).to.equal(false, "Corrupted ciphertext should fail validation")
                console.log("✅ Corrupted ciphertext correctly failed validation")
            } catch (error: any) {
                if (error.message && error.message.includes("revert")) {
                    console.log("✅ Corrupted ciphertext correctly caused revert")
                } else {
                    throw error
                }
            }
        })

        it("Should handle empty ciphertext", async function () {
            const emptyItUint: itUint256 = {
                ciphertext: {
                    ciphertextHigh: "0",
                    ciphertextLow: "0"
                },
                signature: Buffer.from("00".repeat(64), "hex")
            }

            try {
                const tx = await contract.validateAndStore(emptyItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                
                const validationResult = await contract.getValidationResult()
                expect(validationResult).to.equal(false, "Empty ciphertext should fail validation")
                console.log("✅ Empty ciphertext correctly failed validation")
            } catch (error: any) {
                if (error.message && error.message.includes("revert")) {
                    console.log("✅ Empty ciphertext correctly caused revert")
                } else {
                    throw error
                }
            }
        })
    })
})

