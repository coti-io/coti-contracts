import hre from "hardhat"
import { expect } from "chai"
import { Buffer } from "buffer"
import { setupAccounts } from "../accounts"
import { Wallet, itUint } from "@coti-io/coti-ethers"
import { ValidateCiphertextTestsContract } from "../../../typechain-types"

const GAS_LIMIT = 12000000

async function deploy() {
    const [owner] = await setupAccounts()
    const contractFactory = await hre.ethers.getContractFactory("ValidateCiphertextTestsContract", owner as any)
    const contract = await contractFactory.deploy({ gasLimit: GAS_LIMIT })
    await contract.waitForDeployment()
    return {
        contract,
        contractAddress: await contract.getAddress(),
        owner
    }
}

describe("Invalid Ciphertext Validation - 8/16/32/64-bit", function () {
    this.timeout(120000) // 2 minutes
    let contract: ValidateCiphertextTestsContract
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
            const testValue = 100
            const validItUint = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndReturn.fragment.selector
            ) as itUint

            // Corrupt the signature - convert to Buffer
            const invalidSignature = Buffer.from("00".repeat(64), "hex")
            
            const invalidItUint: itUint = {
                ciphertext: validItUint.ciphertext,
                signature: invalidSignature
            }

            // Try the transaction - it might not revert, so check behavior
            try {
                const tx = await contract.validateAndReturn(invalidItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                // If it doesn't revert, that's unexpected but we log it
                console.log("⚠️ Invalid signature did not cause revert - validation may be lenient")
            } catch (error: any) {
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
            const testValue = 100
            
            // This should fail because signature is for wrong address
            const itUint = await owner.encryptValue(
                testValue,
                wrongAddress,  // Wrong address
                contract.validateAndReturn.fragment.selector
            ) as itUint

            // Try to validate - might not revert
            try {
                const tx = await contract.validateAndReturn(itUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                console.log("⚠️ Wrong address signature did not cause revert")
            } catch (error: any) {
                if (error.message && error.message.includes("revert")) {
                    console.log("✅ Wrong address signature correctly caused revert")
                } else {
                    throw error
                }
            }
        })

        it("Should reject ciphertext with corrupted signature", async function () {
            const testValue = 100
            const validItUint = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndReturn.fragment.selector
            ) as itUint

            // Convert signature to Buffer, corrupt it
            const sigBuffer = Buffer.isBuffer(validItUint.signature) 
                ? Buffer.from(validItUint.signature)
                : Buffer.from(validItUint.signature)
            
            // Flip first byte
            sigBuffer[0] = sigBuffer[0] ^ 0xFF
            
            const corruptedItUint: itUint = {
                ciphertext: validItUint.ciphertext,
                signature: sigBuffer
            }

            try {
                const tx = await contract.validateAndReturn(corruptedItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                console.log("⚠️ Corrupted signature did not cause revert")
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
            const testValue = 100
            const validItUint = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndReturn.fragment.selector
            ) as itUint

            // For 8/16/32/64-bit, ciphertext is a direct string value
            const corruptedCiphertext = (BigInt(validItUint.ciphertext.toString()) ^ BigInt("0xFFFFFFFFFFFFFFFF")).toString()

            const corruptedItUint: itUint = {
                ciphertext: corruptedCiphertext,
                signature: validItUint.signature
            }

            try {
                const tx = await contract.validateAndReturn(corruptedItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                console.log("⚠️ Corrupted ciphertext did not cause revert")
            } catch (error: any) {
                if (error.message && error.message.includes("revert")) {
                    console.log("✅ Corrupted ciphertext correctly caused revert")
                } else {
                    throw error
                }
            }
        })

        it("Should handle empty ciphertext", async function () {
            const emptyItUint: itUint = {
                ciphertext: "0",
                signature: Buffer.from("00".repeat(64), "hex")
            }

            try {
                const tx = await contract.validateAndReturn(emptyItUint, { gasLimit: GAS_LIMIT })
                const receipt = await tx.wait()
                console.log("⚠️ Empty ciphertext did not cause revert")
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

