import { ethers } from "hardhat"
import { Wallet, ctUint256 } from "@coti-io/coti-ethers"
import { setupAccounts } from "./accounts"

const gasOptions = {
    gasLimit: 60000000,
    gasPrice: 1000000000,
}

describe("Encryption Flow Test", function () {
	let user: Wallet
	let encryptionTest: any

	before(async function () {
		const accounts = await setupAccounts()
		user = accounts[0]

		// Deploy the test contract
		const EncryptionTestFactory = await ethers.getContractFactory("EncryptionTest", user)
		encryptionTest = await EncryptionTestFactory.deploy(gasOptions)
		await encryptionTest.waitForDeployment()
        console.log("EncryptionTest deployed to: ", await encryptionTest.getAddress())
        
        // Set encryption address (normally done by LibAccount, but we need to set it manually)
        const userAddress = await user.getAddress()
        await encryptionTest.connect(user).setEncryptionAddress(userAddress, userAddress, gasOptions)
	})

	it("Should test multiple encryption flow 100 times (like sendQuote)", async function () {
		const priceValue = 1600000000000000000n // 1.6 tokens
		const quantityValue = 100000000000000000000n // 100 tokens
		const iterations = 100
		const mismatches: Array<{
			iteration: number
			type: string
			original: bigint
			decrypted: bigint
			storage: bigint
		}> = []

		for (let i = 0; i < iterations; i++) {
			console.log(`\n=== Multiple Encryption Iteration ${i + 1}/${iterations} ===`)

			// Encrypt both values
			const contractAddress = await encryptionTest.getAddress()
			const selector = encryptionTest.interface.getFunction("testMultipleEncryptionFlow").selector
			const encryptedPrice = await user.encryptUint256(priceValue, contractAddress, selector)
			const encryptedQuantity = await user.encryptUint256(quantityValue, contractAddress, selector)

			// Call the test function
			const tx = await encryptionTest
				.connect(user)
				.testMultipleEncryptionFlow(encryptedPrice, encryptedQuantity, priceValue, quantityValue, gasOptions)
			const receipt = await tx.wait()

			if (!receipt) {
				throw new Error("Transaction receipt is null")
			}

			// Parse all events
			const events = receipt.logs
				.map((log: any) => {
					try {
						const parsed = encryptionTest.interface.parseLog(log)
						return parsed && parsed.name === "TestEncryptionEvent" ? parsed : null
					} catch {
						return null
					}
				})
				.filter((e: any) => e !== null)

			if (events.length < 2) {
				throw new Error(`Expected 2 events, got ${events.length}`)
			}

			// Check price event
			const priceEvent = events[0]
			const priceDecrypted = await user.decryptUint256(priceEvent.args.encryptedValue as ctUint256)
			const priceOriginal = BigInt(priceEvent.args.originalValue.toString())
			const priceStorage = BigInt(priceEvent.args.storageValue.toString())

			console.log(`Price - Original: ${priceOriginal}, Decrypted: ${priceDecrypted}, Storage: ${priceStorage}`)

			if (priceDecrypted !== priceOriginal) {
				console.log(`❌ PRICE MISMATCH in iteration ${i + 1}!`)
				mismatches.push({
					iteration: i + 1,
					type: "price",
					original: priceOriginal,
					decrypted: priceDecrypted,
					storage: priceStorage,
				})
			}

			// Check quantity event
			const quantityEvent = events[1]
			const quantityDecrypted = await user.decryptUint256(quantityEvent.args.encryptedValue as ctUint256)
			const quantityOriginal = BigInt(quantityEvent.args.originalValue.toString())
			const quantityStorage = BigInt(quantityEvent.args.storageValue.toString())

			console.log(`Quantity - Original: ${quantityOriginal}, Decrypted: ${quantityDecrypted}, Storage: ${quantityStorage}`)

			if (quantityDecrypted !== quantityOriginal) {
				console.log(`❌ QUANTITY MISMATCH in iteration ${i + 1}!`)
				mismatches.push({
					iteration: i + 1,
					type: "quantity",
					original: quantityOriginal,
					decrypted: quantityDecrypted,
					storage: quantityStorage,
				})
			}
		}

		// Report results
		console.log(`\n=== Multiple Encryption Test Results ===`)
		console.log(`Total iterations: ${iterations}`)
		console.log(`Mismatches found: ${mismatches.length}`)

		if (mismatches.length > 0) {
			console.log(`\nMismatch details:`)
			mismatches.forEach((m) => {
				console.log(
					`  Iteration ${m.iteration} (${m.type}): Original=${m.original}, Decrypted=${m.decrypted}, Storage=${m.storage}`,
				)
			})
		}
	})
})
