import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { Wallet, ctUint, ctUint256 } from "@coti-io/coti-ethers"
import { ValidateCiphertext128TestsContract } from "../../../typechain-types"
import { MpcOperationsTestContract } from "../../../typechain-types"

const GAS_LIMIT = 12000000

async function deploy128Contract() {
    const [owner] = await setupAccounts()
    const contractFactory = await hre.ethers.getContractFactory("ValidateCiphertext128TestsContract", owner as any)
    const contract = await contractFactory.deploy({ gasLimit: GAS_LIMIT })
    await contract.waitForDeployment()
    return {
        contract,
        contractAddress: await contract.getAddress(),
        owner
    }
}

async function deploy256Contract() {
    const [owner] = await setupAccounts()
    const contractFactory = await hre.ethers.getContractFactory("MpcOperationsTestContract", owner as any)
    const contract = await contractFactory.deploy({ gasLimit: GAS_LIMIT })
    await contract.waitForDeployment()
    return {
        contract,
        contractAddress: await contract.getAddress(),
        owner
    }
}

describe("Wallet Encryption/Decryption Failure Tests with Contract Integration", function () {
    this.timeout(300000) // 5 minutes timeout
    let contract128: ValidateCiphertext128TestsContract
    let contract128Address: string
    let contract256: MpcOperationsTestContract
    let contract256Address: string
    let owner: Wallet
    let walletWithoutAes: Wallet
    let walletWithAutoOnboardOff: Wallet

    before(async function () {
        // Deploy contracts
        const deployment128 = await deploy128Contract()
        contract128 = deployment128.contract
        contract128Address = deployment128.contractAddress
        owner = deployment128.owner

        const deployment256 = await deploy256Contract()
        contract256 = deployment256.contract
        contract256Address = deployment256.contractAddress

        // Get network info and provider from owner's provider
        const networkName = hre.network.name
        const provider = owner.provider as any

        // Create wallet without AES key (auto-onboard enabled)
        const randomWallet = Wallet.createRandom(provider)
        walletWithoutAes = new Wallet(randomWallet.privateKey, provider)
        // Don't onboard - leave AES key undefined

        // Create wallet with auto-onboard disabled
        const randomWallet2 = Wallet.createRandom(provider)
        walletWithAutoOnboardOff = new Wallet(randomWallet2.privateKey, provider)
        walletWithAutoOnboardOff.disableAutoOnboard()
        // Don't set AES key

        const onboardInfo = owner.getUserOnboardInfo()
        if (!onboardInfo || !onboardInfo.aesKey) {
            throw new Error("User AES key not found. Please onboard the user first.")
        }

        console.log("\n" + "=".repeat(80))
        console.log("🧪 WALLET ENCRYPTION/DECRYPTION FAILURE TESTS")
        console.log("=".repeat(80))
        console.log(`Network: ${networkName}`)
        console.log(`128-bit Contract: ${contract128Address}`)
        console.log(`256-bit Contract: ${contract256Address}`)
        console.log(`Owner Address: ${owner.address}`)
        console.log(`Wallet Without AES: ${walletWithoutAes.address}`)
        console.log(`Wallet Auto-Onboard Off: ${walletWithAutoOnboardOff.address}`)
        console.log("=".repeat(80) + "\n")
    })

    describe("encryptValue Failure Scenarios with Contract Integration", function () {
        it("Should fail when encrypting 129-bit value (exceeds 128-bit limit)", async function () {
            // 129-bit value (2^128)
            const value129Bits = 2n ** 128n
            const functionSelector = contract128.validateAndReturn.fragment.selector

            await expect(
                owner.encryptValue(value129Bits, contract128Address, functionSelector)
            ).to.be.rejectedWith("encryptValue: values larger than 128 bits are not supported")
        })

        it("Should fail when encrypting 256-bit value with encryptValue", async function () {
            // 256-bit value
            const value256Bits = 2n ** 255n
            const functionSelector = contract128.validateAndReturn.fragment.selector

            await expect(
                owner.encryptValue(value256Bits, contract128Address, functionSelector)
            ).to.be.rejectedWith("encryptValue: values larger than 128 bits are not supported")
        })

        it("Should succeed with 128-bit value and complete full cycle", async function () {
            // Maximum 128-bit value (2^128 - 1)
            const max128Bits = 2n ** 128n - 1n
            const functionSelector = contract128.validateAndReturn.fragment.selector

            console.log(`\n✅ Testing 128-bit encryption/decryption full cycle`)
            console.log(`   Value: ${max128Bits.toString()}`)

            // Encrypt
            const encrypted = await owner.encryptValue(max128Bits, contract128Address, functionSelector) as any
            expect(encrypted).to.have.property("ciphertext")
            expect(encrypted).to.have.property("signature")
            console.log(`   ✅ Encrypted successfully`)

            // Call contract
            const tx = await contract128.validateAndReturn(encrypted, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ Contract call successful`)

            // Get result from event
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract128.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })

            expect(resultEvent).to.not.be.undefined
            const parsedLog = contract128.interface.parseLog(resultEvent!)
            const ctResult: ctUint = parsedLog?.args.result

            // Decrypt
            const decrypted = await owner.decryptValue(ctResult)
            expect(decrypted).to.equal(max128Bits)
            console.log(`   ✅ Decrypted successfully: ${decrypted.toString()}\n`)
        })

        it("Should fail when encrypting without AES key and auto-onboard is off", async function () {
            const functionSelector = contract128.validateAndReturn.fragment.selector

            await expect(
                walletWithAutoOnboardOff.encryptValue(1000n, contract128Address, functionSelector)
            ).to.be.rejectedWith("user AES key is not defined and auto onboard is off")
        })

        it("Should fail when encrypting without AES key and account has no balance", async function () {
            const functionSelector = contract128.validateAndReturn.fragment.selector

            await expect(
                walletWithoutAes.encryptValue(1000n, contract128Address, functionSelector)
            ).to.be.rejected
        })
    })

    describe("encryptValue256 Failure Scenarios with Contract Integration", function () {
        it("Should fail when encrypting 257-bit value (exceeds 256-bit limit)", async function () {
            // 257-bit value (2^256)
            const value257Bits = 2n ** 256n
            const functionSelector = contract256.add256.fragment.selector

            await expect(
                owner.encryptValue256(value257Bits, contract256Address, functionSelector)
            ).to.be.rejectedWith("encryptValue256: values larger than 256 bits are not supported")
        })

        it("Should succeed with 256-bit value and complete full cycle", async function () {
            // Maximum 256-bit value (2^256 - 1)
            const max256Bits = 2n ** 256n - 1n
            const functionSelector = contract256.add256.fragment.selector

            console.log(`\n✅ Testing 256-bit encryption/decryption full cycle`)
            console.log(`   Value: ${max256Bits.toString().substring(0, 50)}...`)

            // Encrypt
            const encrypted = await owner.encryptValue256(max256Bits, contract256Address, functionSelector)
            expect(encrypted).to.have.property("ciphertext")
            expect(encrypted.ciphertext).to.have.property("ciphertextHigh")
            expect(encrypted.ciphertext).to.have.property("ciphertextLow")
            expect(encrypted).to.have.property("signature")
            console.log(`   ✅ Encrypted successfully`)

            // Call contract (add with zero to get same value back)
            const zero = await owner.encryptValue256(0n, contract256Address, functionSelector)
            const tx = await contract256.add256(encrypted, zero, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ Contract call successful`)

            // Get result from event
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract256.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })

            expect(resultEvent).to.not.be.undefined
            const parsedLog = contract256.interface.parseLog(resultEvent!)
            const ctResult: ctUint256 = parsedLog?.args.result

            // Decrypt
            const decrypted = await owner.decryptValue256({
                ciphertextHigh: ctResult.ciphertextHigh,
                ciphertextLow: ctResult.ciphertextLow
            })
            expect(decrypted).to.equal(max256Bits)
            console.log(`   ✅ Decrypted successfully\n`)
        })

        it("Should succeed with 129-bit value using encryptValue256", async function () {
            // 129-bit value should work with encryptValue256
            const value129Bits = 2n ** 128n
            const functionSelector = contract256.add256.fragment.selector

            console.log(`\n✅ Testing 129-bit value with encryptValue256`)
            console.log(`   Value: ${value129Bits.toString()}`)

            // Encrypt
            const encrypted = await owner.encryptValue256(value129Bits, contract256Address, functionSelector)
            expect(encrypted).to.have.property("ciphertext")
            expect(encrypted.ciphertext).to.have.property("ciphertextHigh")
            expect(encrypted.ciphertext).to.have.property("ciphertextLow")
            console.log(`   ✅ Encrypted successfully`)

            // Call contract
            const zero = await owner.encryptValue256(0n, contract256Address, functionSelector)
            const tx = await contract256.add256(encrypted, zero, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            // Get and decrypt result
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract256.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })

            const parsedLog = contract256.interface.parseLog(resultEvent!)
            const ctResult: ctUint256 = parsedLog?.args.result

            const decrypted = await owner.decryptValue256({
                ciphertextHigh: ctResult.ciphertextHigh,
                ciphertextLow: ctResult.ciphertextLow
            })
            expect(decrypted).to.equal(value129Bits)
            console.log(`   ✅ Full cycle successful\n`)
        })

        it("Should fail when encrypting without AES key and auto-onboard is off", async function () {
            const functionSelector = contract256.add256.fragment.selector

            await expect(
                walletWithAutoOnboardOff.encryptValue256(1000n, contract256Address, functionSelector)
            ).to.be.rejectedWith("user AES key is not defined and auto onboard is off")
        })

        it("Should fail when encrypting without AES key and account has no balance", async function () {
            const functionSelector = contract256.add256.fragment.selector

            await expect(
                walletWithoutAes.encryptValue256(1000n, contract256Address, functionSelector)
            ).to.be.rejected
        })
    })

    describe("Boundary Value Tests with Contract Integration", function () {
        it("Should succeed with 64-bit value using encryptValue and complete full cycle", async function () {
            const value64Bits = 2n ** 64n - 1n // Max 64-bit value
            const functionSelector = contract128.validateAndReturn.fragment.selector

            console.log(`\n✅ Testing 64-bit value full cycle`)
            const encrypted = await owner.encryptValue(value64Bits, contract128Address, functionSelector) as any
            const tx = await contract128.validateAndReturn(encrypted, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()

            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract128.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })

            const parsedLog = contract128.interface.parseLog(resultEvent!)
            const ctResult: ctUint = parsedLog?.args.result
            const decrypted = await owner.decryptValue(ctResult)
            expect(decrypted).to.equal(value64Bits)
            console.log(`   ✅ 64-bit full cycle successful\n`)
        })

        it("Should fail with 129-bit value using encryptValue", async function () {
            const value129Bits = 2n ** 128n // 129-bit value
            const functionSelector = contract128.validateAndReturn.fragment.selector

            await expect(
                owner.encryptValue(value129Bits, contract128Address, functionSelector)
            ).to.be.rejectedWith("encryptValue: values larger than 128 bits are not supported")
        })

        it("Should succeed with 128-bit value using encryptValue", async function () {
            const value128Bits = 2n ** 128n - 1n // Max 128-bit value
            const functionSelector = contract128.validateAndReturn.fragment.selector

            const encrypted = await owner.encryptValue(value128Bits, contract128Address, functionSelector) as any
            const tx = await contract128.validateAndReturn(encrypted, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()

            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract128.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })

            const parsedLog = contract128.interface.parseLog(resultEvent!)
            const ctResult: ctUint = parsedLog?.args.result
            const decrypted = await owner.decryptValue(ctResult)
            expect(decrypted).to.equal(value128Bits)
        })
    })

    describe("Full Cycle Operations with Contract Integration", function () {
        it("Should perform addition with 128-bit values using encryptValue", async function () {
            const a = 2n ** 100n - 1000n
            const b = 2n ** 100n - 2000n
            const expected = a + b
            const functionSelector = contract128.validateAndAdd.fragment.selector

            console.log(`\n✅ Testing 128-bit addition full cycle`)
            console.log(`   A: ${a.toString()}`)
            console.log(`   B: ${b.toString()}`)
            console.log(`   Expected: ${expected.toString()}`)

            const itA = await owner.encryptValue(a, contract128Address, functionSelector) as any
            const itB = await owner.encryptValue(b, contract128Address, functionSelector) as any

            const tx = await contract128.validateAndAdd(itA, itB, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract128.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })

            const parsedLog = contract128.interface.parseLog(resultEvent!)
            const ctResult: ctUint = parsedLog?.args.result
            const decrypted = await owner.decryptValue(ctResult)

            expect(decrypted).to.equal(expected)
            console.log(`   ✅ Addition verified: ${decrypted.toString()}\n`)
        })

        it("Should perform addition with 256-bit values using encryptValue256", async function () {
            const a = 2n ** 130n + 1000n
            const b = 2n ** 129n + 500n
            const expected = a + b
            const functionSelector = contract256.add256.fragment.selector

            console.log(`\n✅ Testing 256-bit addition full cycle`)
            const itA = await owner.encryptValue256(a, contract256Address, functionSelector)
            const itB = await owner.encryptValue256(b, contract256Address, functionSelector)

            const tx = await contract256.add256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract256.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })

            const parsedLog = contract256.interface.parseLog(resultEvent!)
            const ctResult: ctUint256 = parsedLog?.args.result
            const decrypted = await owner.decryptValue256({
                ciphertextHigh: ctResult.ciphertextHigh,
                ciphertextLow: ctResult.ciphertextLow
            })

            expect(decrypted).to.equal(expected)
            console.log(`   ✅ Addition verified\n`)
        })

        it("Should fail when trying to use encryptValue for 129-bit value in contract call", async function () {
            const value129Bits = 2n ** 128n
            const functionSelector = contract128.validateAndReturn.fragment.selector

            // This should fail at encryption stage, before contract call
            await expect(
                owner.encryptValue(value129Bits, contract128Address, functionSelector)
            ).to.be.rejectedWith("encryptValue: values larger than 128 bits are not supported")
        })

        it("Should succeed when using encryptValue256 for 129-bit value in contract call", async function () {
            const value129Bits = 2n ** 128n
            const functionSelector = contract256.add256.fragment.selector

            // Should work with encryptValue256
            const encrypted = await owner.encryptValue256(value129Bits, contract256Address, functionSelector)
            const zero = await owner.encryptValue256(0n, contract256Address, functionSelector)
            const tx = await contract256.add256(encrypted, zero, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract256.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })

            const parsedLog = contract256.interface.parseLog(resultEvent!)
            const ctResult: ctUint256 = parsedLog?.args.result
            const decrypted = await owner.decryptValue256({
                ciphertextHigh: ctResult.ciphertextHigh,
                ciphertextLow: ctResult.ciphertextLow
            })

            expect(decrypted).to.equal(value129Bits)
        })
    })

    describe("Type Conversion Tests with Contract Integration", function () {
        it("Should convert number to bigint in encryptValue and complete full cycle", async function () {
            const value = 1000 // number
            const functionSelector = contract128.validateAndReturn.fragment.selector

            const encrypted = await owner.encryptValue(value, contract128Address, functionSelector) as any
            const tx = await contract128.validateAndReturn(encrypted, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()

            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract128.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })

            const parsedLog = contract128.interface.parseLog(resultEvent!)
            const ctResult: ctUint = parsedLog?.args.result
            const decrypted = await owner.decryptValue(ctResult)

            expect(decrypted).to.equal(BigInt(value))
        })

        it("Should convert number to bigint in encryptValue256 and complete full cycle", async function () {
            const value = 1000 // number
            const functionSelector = contract256.add256.fragment.selector

            const encrypted = await owner.encryptValue256(value, contract256Address, functionSelector)
            const zero = await owner.encryptValue256(0n, contract256Address, functionSelector)
            const tx = await contract256.add256(encrypted, zero, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()

            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract256.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })

            const parsedLog = contract256.interface.parseLog(resultEvent!)
            const ctResult: ctUint256 = parsedLog?.args.result
            const decrypted = await owner.decryptValue256({
                ciphertextHigh: ctResult.ciphertextHigh,
                ciphertextLow: ctResult.ciphertextLow
            })

            expect(decrypted).to.equal(BigInt(value))
        })
    })
})
