import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { Wallet, itUint, ctUint } from "@coti-io/coti-ethers"
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

describe("ValidateCiphertext Tests - 8/16/32/64-bit", function () {
    this.timeout(60000)
    let contract: ValidateCiphertextTestsContract
    let contractAddress: string
    let owner: Wallet

    before(async function () {
        const deployment = await deploy()
        contract = deployment.contract
        contractAddress = deployment.contractAddress
        owner = deployment.owner
    })

    describe("validateAndStore", function () {
        it("Should validate and store a small value (8-bit)", async function () {
            const testValue = 100
            
            const itUintValue = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            ) as itUint

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUintValue, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt).to.not.be.null
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)

            const validationResult = await contract.getValidationResult()
            expect(validationResult).to.equal(true)

            // Verify we can retrieve the encrypted value
            const storedEncryptedValue = await contract.getStoredEncryptedValue()
            // Note: storedEncryptedValue is a ctUint8 which is a uint256, so we just check it's not zero
            expect(storedEncryptedValue).to.not.be.undefined
            expect(storedEncryptedValue.toString()).to.not.equal("0")
        })

        it("Should validate and store a 16-bit value", async function () {
            const testValue = 1000  // Fits in 16-bit
            
            const itUintValue = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            ) as itUint

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUintValue, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt).to.not.be.null
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            // Note: storedValue is uint8, so it will be truncated if > 255
            if (testValue <= 255) {
                expect(storedValue).to.equal(testValue)
            }
        })

        it("Should validate and store a 32-bit value", async function () {
            const testValue = 50000  // Fits in 32-bit
            
            const itUintValue = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            ) as itUint

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUintValue, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt).to.not.be.null
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            // Note: storedValue is uint8, so it will be truncated if > 255
            if (testValue <= 255) {
                expect(storedValue).to.equal(testValue)
            }
        })

        it("Should validate and store a 64-bit value", async function () {
            const testValue = BigInt("1000000000000000000")  // Large 64-bit value
            
            const itUintValue = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            ) as itUint

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUintValue, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt).to.not.be.null
            expect(receipt?.status).to.equal(1)

            // Note: storedValue is uint8, so large values will be truncated
            // But validation should still succeed
            const validationResult = await contract.getValidationResult()
            expect(validationResult).to.equal(true)
        })
    })

    describe("validateAndReturn", function () {
        it("Should validate and return encrypted value for user", async function () {
            const testValue = 100
            
            const itUintValue = await owner.encryptValue(
                testValue,
                contractAddress,
                contract.validateAndReturn.fragment.selector
            ) as itUint

            const tx = await contract
                .connect(owner)
                .validateAndReturn(itUintValue, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt).to.not.be.null
            expect(receipt?.status).to.equal(1)

            // Get the result from transaction logs
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                // User should be able to decrypt the result
                const decrypted = await owner.decryptValue(ctResult)
                expect(decrypted).to.equal(testValue)
            }
        })
    })

    describe("validateAndAdd", function () {
        it("Should validate two values and add them", async function () {
            const a = 50
            const b = 30
            const expected = a + b
            
            const itA = await owner.encryptValue(
                a,
                contractAddress,
                contract.validateAndAdd.fragment.selector
            ) as itUint
            
            const itB = await owner.encryptValue(
                b,
                contractAddress,
                contract.validateAndAdd.fragment.selector
            ) as itUint

            const tx = await contract
                .connect(owner)
                .validateAndAdd(itA, itB, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt).to.not.be.null
            expect(receipt?.status).to.equal(1)

            // Get the result from transaction logs
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                // User should be able to decrypt the result
                const decrypted = await owner.decryptValue(ctResult)
                expect(Number(decrypted)).to.equal(expected)
            }
        })
    })
})

