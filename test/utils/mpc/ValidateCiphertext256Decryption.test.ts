import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { itUint256, Wallet, ctUint256 } from "@coti-io/coti-ethers"
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

describe("ValidateCiphertext256 - Complete Encryption/Validation/Decryption Cycle", function () {
    this.timeout(120000) // Increased timeout for complete cycle tests
    let contract: ValidateCiphertext256TestsContract
    let contractAddress: string
    let owner: Wallet

    before(async function () {
        const deployment = await deploy()
        contract = deployment.contract
        contractAddress = deployment.contractAddress
        owner = deployment.owner
        
        // Verify the user has AES key for decryption
        const onboardInfo = owner.getUserOnboardInfo()
        if (!onboardInfo || !onboardInfo.aesKey) {
            throw new Error("User AES key not found. Please onboard the user first.")
        }
        
        console.log("\n" + "=".repeat(80))
        console.log("🔐 TEST SETUP")
        console.log("=".repeat(80))
        console.log(`Contract Address: ${contractAddress}`)
        console.log(`Owner Address: ${owner.address}`)
        console.log(`User AES Key: ${onboardInfo.aesKey.substring(0, 8)}...${onboardInfo.aesKey.substring(onboardInfo.aesKey.length - 8)}`)
        console.log("=".repeat(80) + "\n")
    })

    describe("128-bit Values - Complete Cycle", function () {
        it("Should encrypt, user decrypt, validate, and contract decrypt small 128-bit value", async function () {
            const testValue = (2n ** 128n) + BigInt(12345) // > 128 bits
            console.log(`\n🔄 Testing value: ${testValue}`)
            
            // Step 1: User encrypts value
            console.log("📝 Step 1: User encrypts value...")
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )
            
            console.log(`   ✓ Encrypted itUint256 created`)

            // Step 2: User decrypts their own encrypted value to verify
            console.log("📝 Step 2: User decrypts own itUint256 to verify...")
            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)
            console.log(`   ✓ User successfully decrypted: ${userDecrypted}`)

            // Step 3: Send to contract for validation
            console.log("📝 Step 3: Sending to contract for validation...")
            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✓ Transaction confirmed`)

            // Step 4: Verify contract decrypted correctly
            console.log("📝 Step 4: Verifying contract decrypted correctly...")
            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✓ Contract decrypted and stored: ${storedValue}`)
            
            console.log(`   ✅ SUCCESS: Complete cycle verified!\n`)
        })

        it("Should handle 1 ether value (1e18)", async function () {
            const testValue = (2n ** 128n) + BigInt("1000000000000000000") // > 128 bits
            console.log(`\n🔄 Testing 1 ether: ${testValue}`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })

        it("Should handle max uint64 value", async function () {
            const testValue = (2n ** 128n) + (BigInt(2) ** BigInt(64) - BigInt(1)) // > 128 bits
            console.log(`\n🔄 Testing max uint64: ${testValue}`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })

        it("Should handle max uint128 value", async function () {
            const testValue = (2n ** 128n) + BigInt(1) // > 128 bits (129 bits)
            console.log(`\n🔄 Testing max uint128: ${testValue}`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })
    })

    describe("256-bit Values - Complete Cycle", function () {
        it("Should handle value just above 128 bits", async function () {
            const testValue = BigInt(2) ** BigInt(128) + BigInt(1) // 129 bits
            console.log(`\n🔄 Testing 128-bit boundary + 1: ${testValue}`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })

        it("Should handle large 256-bit value", async function () {
            const testValue = BigInt('0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0')
            console.log(`\n🔄 Testing large 256-bit value`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })

        it("Should handle max uint256 value", async function () {
            const testValue = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            console.log(`\n🔄 Testing max uint256`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })
    })

    describe("Edge Cases", function () {
        it("Should handle zero value", async function () {
            const testValue = 2n ** 128n // > 128 bits (129 bits, minimum for itUint256)
            console.log(`\n🔄 Testing minimum 256-bit value: ${testValue}`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })

        it("Should handle value of 1", async function () {
            const testValue = (2n ** 128n) + BigInt(1) // > 128 bits (129 bits)
            console.log(`\n🔄 Testing value of 1`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndStore.fragment.selector
            )

            const userDecrypted = await owner.decryptValue256({
                ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                ciphertextLow: itUint256Value.ciphertext.ciphertextLow
            })
            expect(userDecrypted).to.equal(testValue)

            const tx = await contract
                .connect(owner)
                .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)

            const storedValue = await contract.getStoredValue()
            expect(storedValue).to.equal(testValue)
            console.log(`   ✅ SUCCESS!\n`)
        })
    })

    describe("validateAndIncrement", function () {
        it("Should validate and increment 128-bit value", async function () {
            const testValue = (2n ** 128n) + BigInt("1000000000000000000") // > 128 bits
            console.log(`\n🔄 Testing increment`)
            
            const itUint256Value = await owner.encryptValue256(
                testValue,
                contractAddress,
                contract.validateAndIncrement.fragment.selector
            )

            const tx = await contract
                .connect(owner)
                .validateAndIncrement(itUint256Value, { gasLimit: GAS_LIMIT })
            
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ SUCCESS!\n`)
        })
    })

    describe("Multiple Operations", function () {
        it("Should handle multiple values in sequence", async function () {
            const testValues = [
                (2n ** 128n) + BigInt(100), // > 128 bits
                (2n ** 128n) + BigInt(1000), // > 128 bits
                (2n ** 128n) + BigInt(10000), // > 128 bits
            ]

            console.log(`\n🔄 Testing ${testValues.length} sequential operations`)

            for (let i = 0; i < testValues.length; i++) {
                const testValue = testValues[i]
                
                const itUint256Value = await owner.encryptValue256(
                    testValue,
                    contractAddress,
                    contract.validateAndStore.fragment.selector
                )

                const userDecrypted = await owner.decryptValue256({
                    ciphertextHigh: itUint256Value.ciphertext.ciphertextHigh,
                    ciphertextLow: itUint256Value.ciphertext.ciphertextLow
                })
                expect(userDecrypted).to.equal(testValue)

                const tx = await contract
                    .connect(owner)
                    .validateAndStore(itUint256Value, { gasLimit: GAS_LIMIT })
                
                const receipt = await tx.wait()
                expect(receipt?.status).to.equal(1)

                const storedValue = await contract.getStoredValue()
                expect(storedValue).to.equal(testValue)
                console.log(`   ✓ Cycle ${i + 1} completed`)
            }

            console.log(`   ✅ SUCCESS: All sequential operations completed!\n`)
        })
    })
})
