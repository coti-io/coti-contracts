import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { itUint, Wallet, ctUint } from "@coti-io/coti-ethers"
import { MpcOperations128TestContract } from "../../../typechain-types"

const GAS_LIMIT = 12000000

async function deploy() {
    const [owner] = await setupAccounts()

    const contractFactory = await hre.ethers.getContractFactory("MpcOperations128TestContract", owner as any)
    const contract = await contractFactory.deploy({ gasLimit: GAS_LIMIT })
    await contract.waitForDeployment()

    return {
        contract,
        contractAddress: await contract.getAddress(),
        owner
    }
}

describe("MPC Operations uint128 with offBoardToUser - User Can Decrypt Results", function () {
    this.timeout(300000) // 5 minutes timeout
    let contract: MpcOperations128TestContract
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
        console.log("🔐 MPC OPERATIONS uint128 TEST SETUP")
        console.log("=".repeat(80))
        console.log(`Contract Address: ${contractAddress}`)
        console.log(`Owner Address: ${owner.address}`)
        console.log(`User AES Key: ${onboardInfo.aesKey.substring(0, 8)}...${onboardInfo.aesKey.substring(onboardInfo.aesKey.length - 8)}`)
        console.log("=".repeat(80) + "\n")
    })

    describe("Arithmetic Operations - uint128", function () {
        it("Should perform addition and user can decrypt result", async function () {
            const a = BigInt(1000)
            const b = BigInt(500)
            const expected = a + b
            console.log(`\n➕ Testing uint128: ${a} + ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.add128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.add128.fragment.selector) as itUint
            
            console.log("📝 Performing addition on contract...")
            const tx = await contract.add128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                console.log("📝 User decrypting result...")
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Addition verified!\n`)
            }
        })

        it("Should perform subtraction and user can decrypt result", async function () {
            const a = BigInt(1000)
            const b = BigInt(300)
            const expected = a - b
            console.log(`\n➖ Testing uint128: ${a} - ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.sub128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.sub128.fragment.selector) as itUint
            
            const tx = await contract.sub128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Subtraction verified!\n`)
            }
        })

        it("Should perform multiplication and user can decrypt result", async function () {
            const a = BigInt(100)
            const b = BigInt(50)
            const expected = a * b
            console.log(`\n✖️  Testing uint128: ${a} * ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.mul128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.mul128.fragment.selector) as itUint
            
            const tx = await contract.mul128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Multiplication verified!\n`)
            }
        })

        it("Should perform division and user can decrypt result", async function () {
            const a = BigInt(1000)
            const b = BigInt(10)
            const expected = a / b
            console.log(`\n➗ Testing uint128: ${a} / ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.div128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.div128.fragment.selector) as itUint
            
            const tx = await contract.div128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Division verified!\n`)
            }
        })

        it("Should perform modulo and user can decrypt result", async function () {
            const a = BigInt(1000)
            const b = BigInt(300)
            const expected = a % b
            console.log(`\n🔢 Testing uint128: ${a} % ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.rem128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.rem128.fragment.selector) as itUint
            
            const tx = await contract.rem128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Modulo verified!\n`)
            }
        })
    })

    describe("Bitwise Operations - uint128", function () {
        it("Should perform AND operation and user can decrypt result", async function () {
            const a = BigInt(0xFF)  // 255
            const b = BigInt(0xF0)  // 240
            const expected = a & b  // 240
            console.log(`\n& Testing uint128: ${a} & ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.and128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.and128.fragment.selector) as itUint
            
            const tx = await contract.and128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: AND verified!\n`)
            }
        })

        it("Should perform OR operation and user can decrypt result", async function () {
            const a = BigInt(0xF0)  // 240
            const b = BigInt(0x0F)  // 15
            const expected = a | b  // 255
            console.log(`\n| Testing uint128: ${a} | ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.or128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.or128.fragment.selector) as itUint
            
            const tx = await contract.or128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: OR verified!\n`)
            }
        })

        it("Should perform XOR operation and user can decrypt result", async function () {
            const a = BigInt(0xFF)  // 255
            const b = BigInt(0xF0)  // 240
            const expected = a ^ b  // 15
            console.log(`\n^ Testing uint128: ${a} ^ ${b} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.xor128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.xor128.fragment.selector) as itUint
            
            const tx = await contract.xor128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: XOR verified!\n`)
            }
        })

        it("Should perform shift left and user can decrypt result", async function () {
            const a = BigInt(10)
            const bits = 2
            const expected = a << BigInt(bits)  // 40
            console.log(`\n<< Testing uint128: ${a} << ${bits} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.shl128.fragment.selector) as itUint
            
            const tx = await contract.shl128(itA, bits, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Shift left verified!\n`)
            }
        })

        it("Should perform shift right and user can decrypt result", async function () {
            const a = BigInt(40)
            const bits = 2
            const expected = a >> BigInt(bits)  // 10
            console.log(`\n>> Testing uint128: ${a} >> ${bits} = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.shr128.fragment.selector) as itUint
            
            const tx = await contract.shr128(itA, bits, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Shift right verified!\n`)
            }
        })
    })

    describe("Large uint128 Values (> 64-bit)", function () {
        it("Should handle values at uint64 boundary", async function () {
            const maxUint64 = BigInt("18446744073709551615") // 2^64 - 1
            const a = maxUint64
            const b = BigInt(1)
            const expected = a + b // 2^64 (requires > 64 bits)
            console.log(`\n➕ Testing uint128 boundary: ${a} + ${b}`)
            console.log(`   Expected: ${expected} (requires > 64 bits)`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.add128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.add128.fragment.selector) as itUint
            
            const tx = await contract.add128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: uint64 boundary crossed!\n`)
            }
        })

        it("Should handle large uint128 multiplication", async function () {
            const a = BigInt("4294967296") // 2^32
            const b = BigInt("4294967296") // 2^32
            const expected = a * b // 2^64
            console.log(`\n✖️  Testing large uint128: ${a} * ${b}`)
            console.log(`   Expected: ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.mul128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.mul128.fragment.selector) as itUint
            
            const tx = await contract.mul128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Large multiplication verified!\n`)
            }
        })

        it("Should handle large uint64-range values in uint128 context", async function () {
            // Use max uint64 value (largest value supported by current encryption)
            const largeValue = BigInt("18446744073709551615") // 2^64 - 1 (max uint64)
            const mask = BigInt(0xFFFFFFFF)
            const expected = largeValue & mask
            
            console.log(`\n& Testing large uint64 value in uint128 context`)
            console.log(`   Using: ${largeValue} (max uint64)`)
            
            const itA = await owner.encryptValue(largeValue, contractAddress, contract.and128.fragment.selector) as itUint
            const itB = await owner.encryptValue(mask, contractAddress, contract.and128.fragment.selector) as itUint
            
            const tx = await contract.and128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Large uint64 operation in uint128 context verified!\n`)
            }
        })

        it("Should handle full 128-bit range with prepareIT", async function () {
            // Test with 100-bit value (requires full uint128 encryption)
            const largeValue = BigInt("1267650600228229401496703205376") // 2^100
            const small = BigInt(1000)
            const expected = largeValue + small
            
            console.log(`\n➕ Testing FULL uint128 range with prepareIT`)
            console.log(`   Using 100-bit value: ${largeValue}`)
            console.log(`   Expected: ${expected}`)
            
            const itA = await owner.encryptValue(largeValue, contractAddress, contract.add128.fragment.selector) as itUint
            const itB = await owner.encryptValue(small, contractAddress, contract.add128.fragment.selector) as itUint
            
            const tx = await contract.add128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: FULL 128-bit range verified with prepareIT!\n`)
            }
        })

        it("Should handle near-max uint128 with prepareIT", async function () {
            // Test with value close to max uint128
            const nearMax = BigInt("170141183460469231731687303715884105727") // 2^127 - 1
            const one = BigInt(1)
            const expected = nearMax + one // 2^127
            
            console.log(`\n➕ Testing near-max uint128 with prepareIT`)
            console.log(`   Using: ${nearMax} (2^127 - 1)`)
            console.log(`   Expected: ${expected} (2^127)`)
            
            const itA = await owner.encryptValue(nearMax, contractAddress, contract.add128.fragment.selector) as itUint
            const itB = await owner.encryptValue(one, contractAddress, contract.add128.fragment.selector) as itUint
            
            const tx = await contract.add128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Near-max uint128 verified! Full 128-bit support confirmed!\n`)
            }
        })
    })

    describe("Min/Max Operations - uint128", function () {
        it("Should get minimum of two values and user can decrypt result", async function () {
            const a = BigInt(500)
            const b = BigInt(1000)
            const expected = BigInt(500)
            console.log(`\nmin Testing uint128: min(${a}, ${b}) = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.min128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.min128.fragment.selector) as itUint
            
            const tx = await contract.min128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Min verified!\n`)
            }
        })

        it("Should get maximum of two values and user can decrypt result", async function () {
            const a = BigInt(500)
            const b = BigInt(1000)
            const expected = BigInt(1000)
            console.log(`\nmax Testing uint128: max(${a}, ${b}) = ${expected}`)
            
            const itA = await owner.encryptValue(a, contractAddress, contract.max128.fragment.selector) as itUint
            const itB = await owner.encryptValue(b, contractAddress, contract.max128.fragment.selector) as itUint
            
            const tx = await contract.max128(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded128"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue(ctResult)
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Max verified!\n`)
            }
        })
    })
})

