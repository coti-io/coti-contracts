import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { Wallet, itUint, ctUint } from "@coti-io/coti-ethers"
import { ValidateCiphertext128TestsContract } from "../../../typechain-types"

const GAS_LIMIT = 12000000

async function deploy() {
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

describe("buildInputText 128-bit Full Cycle Test - coti-private", function () {
    this.timeout(300000) // 5 minutes timeout
    let contract: ValidateCiphertext128TestsContract
    let contractAddress: string
    let owner: Wallet

    before(async function () {
        const deployment = await deploy()
        contract = deployment.contract
        contractAddress = deployment.contractAddress
        owner = deployment.owner
        
        const onboardInfo = owner.getUserOnboardInfo()
        if (!onboardInfo || !onboardInfo.aesKey) {
            throw new Error("User AES key not found. Please onboard the user first.")
        }
        
        console.log("\n" + "=".repeat(80))
        console.log("🔐 buildInputText 128-bit FULL CYCLE TEST")
        console.log("=".repeat(80))
        console.log(`Network: ${hre.network.name}`)
        console.log(`Contract Address: ${contractAddress}`)
        console.log(`Owner Address: ${owner.address}`)
        console.log(`User AES Key: ${onboardInfo.aesKey.substring(0, 8)}...${onboardInfo.aesKey.substring(onboardInfo.aesKey.length - 8)}`)
        console.log("=".repeat(80) + "\n")
    })

    describe("Single Value Validation - Testing buildInputText with Large Values", function () {
        it("Should validate and decrypt 80-bit value (>70 bits)", async function () {
            const plaintext = (2n ** 80n) - 1n // 80-bit max value
            const bitSize = plaintext.toString(2).length
            expect(bitSize).to.equal(80)
            
            console.log(`\n📊 Testing 80-bit value`)
            console.log(`   Value: ${plaintext.toString()}`)
            console.log(`   Bit size: ${bitSize} bits`)
            
            // Step 1: Encrypt using Wallet.encryptValue (which uses buildInputText internally)
            const functionSelector = contract.validateAndReturn.fragment.selector
            console.log(`\n🔐 Step 1: Encrypting with Wallet.encryptValue (uses buildInputText internally)...`)
            const itValue = await owner.encryptValue(plaintext, contractAddress, functionSelector) as itUint
            
            console.log(`   ✅ Encrypted: ciphertext = ${itValue.ciphertext.toString()}`)
            console.log(`   ✅ Signature length: ${(itValue.signature as Uint8Array).length} bytes`)
            
            // Step 2: Send to contract for validation
            console.log(`\n📤 Step 2: Sending to contract for validation...`)
            const tx = await contract.validateAndReturn(itValue, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ Transaction confirmed in block ${receipt?.blockNumber}`)
            
            // Step 3: Extract result from event
            const resultEvents = receipt?.logs.filter((log: any) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    return parsed?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            expect(resultEvents).to.not.be.undefined
            expect(resultEvents?.length).to.equal(1, "Expected exactly one ValueOffBoarded128 event")
            
            const parsedLog = contract.interface.parseLog(resultEvents![0])
            const ctResult: ctUint = parsedLog?.args.result
            
            console.log(`\n🔓 Step 3: Decrypting result...`)
            console.log(`   CT value: ${ctResult.toString()}`)
            
            // Step 4: Decrypt using Wallet.decryptValue
            const decrypted = await owner.decryptValue(ctResult)
            
            console.log(`   ✅ Decrypted: ${decrypted.toString()}`)
            console.log(`   ✅ Original:  ${plaintext.toString()}`)
            
            expect(decrypted).to.equal(plaintext)
            console.log(`\n   ✅✅✅ SUCCESS: 80-bit value full cycle verified!\n`)
        })

        it("Should validate and decrypt 100-bit value", async function () {
            const plaintext = (2n ** 100n) - 12345n // 100-bit value
            const bitSize = plaintext.toString(2).length
            expect(bitSize).to.equal(100)
            
            console.log(`\n📊 Testing 100-bit value`)
            console.log(`   Value: ${plaintext.toString()}`)
            console.log(`   Bit size: ${bitSize} bits`)
            
            const functionSelector = contract.validateAndReturn.fragment.selector
            console.log(`\n🔐 Step 1: Encrypting with Wallet.encryptValue...`)
            const itValue = await owner.encryptValue(plaintext, contractAddress, functionSelector) as itUint
            
            console.log(`   ✅ Encrypted successfully`)
            
            console.log(`\n📤 Step 2: Sending to contract...`)
            const tx = await contract.validateAndReturn(itValue, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ Transaction confirmed in block ${receipt?.blockNumber}`)
            console.log(`   📝 Total logs: ${receipt?.logs.length}`)
            
            // Debug: Log all events
            console.log(`\n   🔍 Parsing all events...`)
            receipt?.logs.forEach((log: any, index: number) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    if (parsed) {
                        console.log(`   Event ${index}: ${parsed.name}`)
                        if (parsed.name === "ValueOffBoarded128") {
                            console.log(`      Result: ${parsed.args.result.toString()}`)
                        }
                    }
                } catch (e) {
                    // Not our contract's event
                }
            })
            
            // Find the ValueOffBoarded128 event - there should be exactly one
            const resultEvents = receipt?.logs.filter((log: any) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    return parsed?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            expect(resultEvents).to.not.be.undefined
            expect(resultEvents?.length).to.equal(1, `Expected exactly one ValueOffBoarded128 event, found ${resultEvents?.length}`)
            
            const parsedLog = contract.interface.parseLog(resultEvents![0])
            const ctResult: ctUint = parsedLog?.args.result
            
            console.log(`\n🔓 Step 3: Decrypting...`)
            console.log(`   CT value: ${ctResult.toString()}`)
            const decrypted = await owner.decryptValue(ctResult)
            
            console.log(`   ✅ Decrypted: ${decrypted.toString()}`)
            console.log(`   ✅ Original:  ${plaintext.toString()}`)
            expect(decrypted).to.equal(plaintext)
            console.log(`\n   ✅✅✅ SUCCESS: 100-bit value verified!\n`)
        })

        it("Should validate and decrypt 120-bit value", async function () {
            const plaintext = (2n ** 120n) - 1n // 120-bit max value
            const bitSize = plaintext.toString(2).length
            expect(bitSize).to.equal(120)
            
            console.log(`\n📊 Testing 120-bit value`)
            console.log(`   Value: ${plaintext.toString()}`)
            console.log(`   Bit size: ${bitSize} bits`)
            
            const functionSelector = contract.validateAndReturn.fragment.selector
            const itValue = await owner.encryptValue(plaintext, contractAddress, functionSelector) as itUint
            
            const tx = await contract.validateAndReturn(itValue, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ Transaction confirmed in block ${receipt?.blockNumber}`)
            
            const resultEvents = receipt?.logs.filter((log: any) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    return parsed?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            expect(resultEvents?.length).to.equal(1, "Expected exactly one ValueOffBoarded128 event")
            
            const parsedLog = contract.interface.parseLog(resultEvents![0])
            const ctResult: ctUint = parsedLog?.args.result
            
            console.log(`\n🔓 Decrypting...`)
            console.log(`   CT value: ${ctResult.toString()}`)
            const decrypted = await owner.decryptValue(ctResult)
            
            console.log(`   ✅ Decrypted: ${decrypted.toString()}`)
            console.log(`   ✅ Original:  ${plaintext.toString()}`)
            expect(decrypted).to.equal(plaintext)
            console.log(`\n   ✅✅✅ SUCCESS: 120-bit value verified!\n`)
        })

        it("Should validate and decrypt 128-bit value (maximum)", async function () {
            const plaintext = (2n ** 128n) - 1n // Maximum 128-bit value
            const bitSize = plaintext.toString(2).length
            expect(bitSize).to.equal(128)
            
            console.log(`\n📊 Testing MAXIMUM 128-bit value`)
            console.log(`   Value: ${plaintext.toString()}`)
            console.log(`   Bit size: ${bitSize} bits (MAXIMUM)`)
            
            const functionSelector = contract.validateAndReturn.fragment.selector
            console.log(`\n🔐 Encrypting with Wallet.encryptValue...`)
            const itValue = await owner.encryptValue(plaintext, contractAddress, functionSelector) as itUint
            
            console.log(`   ✅ Encrypted successfully`)
            
            console.log(`\n📤 Sending to contract...`)
            const tx = await contract.validateAndReturn(itValue, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ Transaction confirmed in block ${receipt?.blockNumber}`)
            console.log(`   📝 Total logs: ${receipt?.logs.length}`)
            
            // Debug: Log all events
            console.log(`\n   🔍 Parsing all events...`)
            receipt?.logs.forEach((log: any, index: number) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    if (parsed) {
                        console.log(`   Event ${index}: ${parsed.name}`)
                        if (parsed.name === "ValueOffBoarded128") {
                            console.log(`      Result: ${parsed.args.result.toString()}`)
                        }
                    }
                } catch (e) {
                    // Not our contract's event
                }
            })
            
            const resultEvents = receipt?.logs.filter((log: any) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    return parsed?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            expect(resultEvents?.length).to.equal(1, `Expected exactly one ValueOffBoarded128 event, found ${resultEvents?.length}`)
            
            const parsedLog = contract.interface.parseLog(resultEvents![0])
            const ctResult: ctUint = parsedLog?.args.result
            
            console.log(`\n🔓 Decrypting...`)
            console.log(`   CT value: ${ctResult.toString()}`)
            const decrypted = await owner.decryptValue(ctResult)
            
            console.log(`   ✅ Decrypted: ${decrypted.toString()}`)
            console.log(`   ✅ Original:  ${plaintext.toString()}`)
            expect(decrypted).to.equal(plaintext)
            console.log(`\n   ✅✅✅ SUCCESS: MAXIMUM 128-bit value verified! buildInputText works perfectly!\n`)
        })
    })

    describe("Addition Operation - Testing buildInputText with Operations", function () {
        it("Should add two 100-bit values using buildInputText", async function () {
            const a = (2n ** 100n) - 1000n
            const b = (2n ** 100n) - 2000n
            const expected = a + b
            const bitSizeA = a.toString(2).length
            const bitSizeB = b.toString(2).length
            
            console.log(`\n📊 Testing addition with 100-bit values`)
            console.log(`   A: ${a.toString()} (${bitSizeA} bits)`)
            console.log(`   B: ${b.toString()} (${bitSizeB} bits)`)
            console.log(`   Expected: ${expected.toString()}`)
            
            const functionSelector = contract.validateAndAdd.fragment.selector
            
            console.log(`\n🔐 Encrypting both values with Wallet.encryptValue...`)
            const itA = await owner.encryptValue(a, contractAddress, functionSelector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, functionSelector) as itUint
            
            console.log(`   ✅ Both values encrypted`)
            
            console.log(`\n📤 Sending to contract for addition...`)
            const tx = await contract.validateAndAdd(itA, itB, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvents = receipt?.logs.filter((log: any) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    return parsed?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            expect(resultEvents?.length).to.equal(1, "Expected exactly one ValueOffBoarded128 event")
            
            const parsedLog = contract.interface.parseLog(resultEvents![0])
            const ctResult: ctUint = parsedLog?.args.result
            
            console.log(`\n🔓 Decrypting result...`)
            console.log(`   CT value: ${ctResult.toString()}`)
            const decrypted = await owner.decryptValue(ctResult)
            
            console.log(`   ✅ Decrypted: ${decrypted.toString()}`)
            console.log(`   ✅ Expected:  ${expected.toString()}`)
            expect(decrypted).to.equal(expected)
            console.log(`\n   ✅✅✅ SUCCESS: Addition with 100-bit values verified!\n`)
        })

        it("Should add two 128-bit values using buildInputText", async function () {
            const a = (2n ** 127n) - 1n // Near max
            const b = 1n
            const expected = a + b // Will be 2^127
            
            console.log(`\n📊 Testing addition with near-max 128-bit values`)
            console.log(`   A: ${a.toString()} (127 bits)`)
            console.log(`   B: ${b.toString()}`)
            console.log(`   Expected: ${expected.toString()} (128 bits)`)
            
            const functionSelector = contract.validateAndAdd.fragment.selector
            
            const itA = await owner.encryptValue(a, contractAddress, functionSelector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, functionSelector) as itUint
            
            const tx = await contract.validateAndAdd(itA, itB, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            console.log(`   ✅ Transaction confirmed in block ${receipt?.blockNumber}`)
            console.log(`   📝 Total logs: ${receipt?.logs.length}`)
            
            // Debug: Log all events
            console.log(`\n   🔍 Parsing all events...`)
            receipt?.logs.forEach((log: any, index: number) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    if (parsed) {
                        console.log(`   Event ${index}: ${parsed.name}`)
                        if (parsed.name === "ValueOffBoarded128") {
                            console.log(`      Result: ${parsed.args.result.toString()}`)
                        }
                    }
                } catch (e) {
                    // Not our contract's event
                }
            })
            
            const resultEvents = receipt?.logs.filter((log: any) => {
                try {
                    const parsed = contract.interface.parseLog(log)
                    return parsed?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            expect(resultEvents?.length).to.equal(1, `Expected exactly one ValueOffBoarded128 event, found ${resultEvents?.length}`)
            
            const parsedLog = contract.interface.parseLog(resultEvents![0])
            const ctResult: ctUint = parsedLog?.args.result
            
            console.log(`\n🔓 Decrypting result...`)
            console.log(`   CT value: ${ctResult.toString()}`)
            const decrypted = await owner.decryptValue(ctResult)
            
            console.log(`   ✅ Decrypted: ${decrypted.toString()}`)
            console.log(`   ✅ Expected:  ${expected.toString()}`)
            expect(decrypted).to.equal(expected)
            console.log(`\n   ✅✅✅ SUCCESS: Addition with near-max 128-bit values verified!\n`)
        })
    })

    after(function() {
        console.log("\n" + "=".repeat(80))
        console.log("📋 TEST SUMMARY")
        console.log("=".repeat(80))
        console.log("✅ Wallet.encryptValue (buildInputText) supports 80-bit values (>70 bits)")
        console.log("✅ Wallet.encryptValue (buildInputText) supports 100-bit values")
        console.log("✅ Wallet.encryptValue (buildInputText) supports 120-bit values")
        console.log("✅ Wallet.encryptValue (buildInputText) supports 128-bit values (MAXIMUM)")
        console.log("✅ Full cycle: encrypt → validate → decrypt works perfectly")
        console.log("✅ Operations (addition) work with large values")
        console.log("\n🎉 CONCLUSION: buildInputText 128-bit support via Wallet.encryptValue is FULLY WORKING!")
        console.log("=".repeat(80) + "\n")
    })
})

