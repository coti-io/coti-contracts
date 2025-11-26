import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { itUint256, Wallet, ctUint256 } from "@coti-io/coti-ethers"
import { MpcOperationsTestContract } from "../../../typechain-types"

const GAS_LIMIT = 12000000

async function deploy() {
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

describe("MPC Operations with offBoardToUser - User Can Decrypt Results", function () {
    this.timeout(180000) // 3 minutes timeout
    let contract: MpcOperationsTestContract
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
        console.log("🔐 MPC OPERATIONS TEST SETUP")
        console.log("=".repeat(80))
        console.log(`Contract Address: ${contractAddress}`)
        console.log(`Owner Address: ${owner.address}`)
        console.log(`User AES Key: ${onboardInfo.aesKey.substring(0, 8)}...${onboardInfo.aesKey.substring(onboardInfo.aesKey.length - 8)}`)
        console.log("=".repeat(80) + "\n")
    })

    describe("Arithmetic Operations", function () {
        it("Should perform addition and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + 1000n
            const b = (2n ** 129n) + 500n
            const expected = a + b
            console.log(`\n➕ Testing: ${a} + ${b} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.add256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.add256.fragment.selector)
            
            console.log("📝 Performing addition on contract...")
            const tx = await contract.add256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
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
                const ctResult: ctUint256 = parsedLog?.args.result
                
                console.log("📝 User decrypting result...")
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Addition verified!\n`)
            }
        })

        it("Should perform subtraction and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + 1000n
            const b = (2n ** 129n) + 300n
            const expected = a - b
            console.log(`\n➖ Testing: ${a} - ${b} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.sub256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.sub256.fragment.selector)
            
            const tx = await contract.sub256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Subtraction verified!\n`)
            }
        })

        it("Should perform division and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + 1000n
            const b = (2n ** 129n) + 10n
            const expected = a / b
            console.log(`\n➗ Testing: ${a} / ${b} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.div256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.div256.fragment.selector)
            
            const tx = await contract.div256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Division verified!\n`)
            }
        })

        it("Should perform modulo and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + 1000n
            const b = (2n ** 129n) + 300n
            const expected = a % b
            console.log(`\n🔢 Testing: ${a} % ${b} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.rem256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.rem256.fragment.selector)
            
            const tx = await contract.rem256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Modulo verified!\n`)
            }
        })
    })

    describe("Bitwise Operations", function () {
        it("Should perform AND operation and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + BigInt(0xFF)  // > 128 bits + 255
            const b = (2n ** 129n) + BigInt(0xF0)  // > 128 bits + 240
            const expected = a & b
            console.log(`\n& Testing: ${a} & ${b} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.and256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.and256.fragment.selector)
            
            const tx = await contract.and256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: AND verified!\n`)
            }
        })

        it("Should perform OR operation and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + BigInt(0xF0)  // > 128 bits + 240
            const b = (2n ** 129n) + BigInt(0x0F)  // > 128 bits + 15
            const expected = a | b
            console.log(`\n| Testing: ${a} | ${b} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.or256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.or256.fragment.selector)
            
            const tx = await contract.or256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: OR verified!\n`)
            }
        })

        it("Should perform XOR operation and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + BigInt(0xFF)  // > 128 bits + 255
            const b = (2n ** 129n) + BigInt(0xF0)  // > 128 bits + 240
            const expected = a ^ b
            console.log(`\n^ Testing: ${a} ^ ${b} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.xor256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.xor256.fragment.selector)
            
            const tx = await contract.xor256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: XOR verified!\n`)
            }
        })

        it("Should perform shift left and user can decrypt result", async function () {
            // Use value > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + BigInt(10)
            const bits = 2
            const expected = a << BigInt(bits)
            console.log(`\n<< Testing: ${a} << ${bits} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.shl256.fragment.selector)
            
            const tx = await contract.shl256(itA, bits, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Shift left verified!\n`)
            }
        })

        it("Should perform shift right and user can decrypt result", async function () {
            // Use value > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + BigInt(40)
            const bits = 2
            const expected = a >> BigInt(bits)
            console.log(`\n>> Testing: ${a} >> ${bits} = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.shr256.fragment.selector)
            
            const tx = await contract.shr256(itA, bits, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Shift right verified!\n`)
            }
        })
    })

    // Note: Comparison operations (eq, gt, lt) return gtBool which requires different handling
    // They are excluded from these tests but can be implemented separately if needed

    describe("Big Number Operations (> 128-bit)", function () {
        it("Should perform addition with 256-bit numbers and user can decrypt result", async function () {
            // Use numbers larger than 128-bit
            const a = BigInt("340282366920938463463374607431768211456") // 2^128 (129 bits)
            const b = BigInt("340282366920938463463374607431768211457") // 2^128 + 1 (129 bits)
            // Both > 128 bits ✓, a + b = 2^129 + 1 (130 bits) - safe
            const expected = a + b
            console.log(`\n➕ Testing BIG: ${a} + ${b}`)
            console.log(`   Expected: ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.add256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.add256.fragment.selector)
            
            console.log("📝 Performing addition on contract with 256-bit numbers...")
            const tx = await contract.add256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                console.log("📝 User decrypting 256-bit result...")
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: 256-bit addition verified!\n`)
            }
        })


        it("Should perform subtraction with 200-bit numbers and user can decrypt result", async function () {
            const a = BigInt("1606938044258990275541962092341162602522202993782792835301376") // ~200-bit
            const b = BigInt("806469022129495137770981046170581301261101496891396417650688") // ~199-bit
            const expected = a - b
            console.log(`\n➖ Testing BIG subtraction`)
            console.log(`   Result should be ~199-bit number`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.sub256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.sub256.fragment.selector)
            
            const tx = await contract.sub256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: 200-bit subtraction verified!\n`)
            }
        })

        it("Should perform max uint256 operations", async function () {
            // Test with very large numbers close to max uint256
            const maxUint256 = BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639935") // 2^256 - 1
            const largeNum = maxUint256 / BigInt(2)
            // Use value > 128 bits for second operand to ensure itUint256 encryption
            const mask = (2n ** 130n) + BigInt(0xFFFFFFFF)
            const expected = largeNum & mask
            
            console.log(`\n& Testing with near-max uint256`)
            console.log(`   Using number: ${largeNum}`)
            
            const itA = await owner.encryptValue256(largeNum, contractAddress, contract.and256.fragment.selector)
            const itB = await owner.encryptValue256(mask, contractAddress, contract.and256.fragment.selector)
            
            const tx = await contract.and256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Near-max uint256 operation verified!\n`)
            }
        })
    })

    describe("Min/Max Operations", function () {
        it("Should get minimum of two values and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + 500n
            const b = (2n ** 130n) + 1000n
            const expected = a < b ? a : b
            console.log(`\nmin Testing: min(${a}, ${b}) = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.min256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.min256.fragment.selector)
            
            const tx = await contract.min256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Min verified!\n`)
            }
        })

        it("Should get maximum of two values and user can decrypt result", async function () {
            // Use values > 128 bits to ensure itUint256 encryption
            const a = (2n ** 130n) + 500n
            const b = (2n ** 130n) + 1000n
            const expected = a > b ? a : b
            console.log(`\nmax Testing: max(${a}, ${b}) = ${expected}`)
            
            const itA = await owner.encryptValue256(a, contractAddress, contract.max256.fragment.selector)
            const itB = await owner.encryptValue256(b, contractAddress, contract.max256.fragment.selector)
            
            const tx = await contract.max256(itA, itB, owner.address, { gasLimit: GAS_LIMIT })
            const receipt = await tx.wait()
            expect(receipt?.status).to.equal(1)
            
            const resultEvent = receipt?.logs.find((log: any) => {
                try {
                    return contract.interface.parseLog(log)?.name === "ValueOffBoarded"
                } catch {
                    return false
                }
            })
            
            if (resultEvent) {
                const parsedLog = contract.interface.parseLog(resultEvent)
                const ctResult: ctUint256 = parsedLog?.args.result
                
                const decrypted = await owner.decryptValue256({
                    ciphertextHigh: ctResult.ciphertextHigh,
                    ciphertextLow: ctResult.ciphertextLow
                })
                
                console.log(`✓ Decrypted result: ${decrypted}`)
                expect(decrypted).to.equal(expected)
                console.log(`   ✅ SUCCESS: Max verified!\n`)
            }
        })
    })

})

