
import { expect } from "chai";
import hre from "hardhat";
import { Wallet } from "@coti-io/coti-ethers";
import type { MinimalProxy, MinimalImplementation } from "../../../typechain-types";

const GAS_LIMIT = 12000000;

/**
 * Test: 200-bit numbers through proxy with offBoardToUser and storage verification
 */
describe("Proxy Validation - 200-bit Numbers Test", function () {
    let proxy: MinimalProxy;
    let implementation: MinimalImplementation;
    let proxyAsImpl: MinimalImplementation;
    let owner: Wallet;

    this.timeout(120000);

    before(async function () {
        // Get only the first account to avoid insufficient funds issue
        const pks = process.env.SIGNING_KEYS ? process.env.SIGNING_KEYS.split(",") : [];
        if (pks.length === 0) {
            throw new Error("No signing keys found in .env");
        }

        const provider = hre.ethers.provider;
        owner = new Wallet(pks[0], provider);
        
        // Check if we need to onboard
        const userKeys = process.env.USER_KEYS ? process.env.USER_KEYS.split(",") : [];
        if (userKeys.length > 0 && userKeys[0]) {
            owner.setAesKey(userKeys[0]);
        } else {
            console.log("************* Onboarding user", owner.address, "*************");
            await owner.generateOrRecoverAes();
            console.log("************* Onboarded! *************");
        }

        if (!owner.getUserOnboardInfo()?.aesKey) {
            throw new Error("Owner AES key not found");
        }

        // Deploy implementation
        const ImplFactory = await hre.ethers.getContractFactory("MinimalImplementation", owner as any);
        implementation = await ImplFactory.deploy({ gasLimit: GAS_LIMIT });
        await implementation.waitForDeployment();
        const implAddress = await implementation.getAddress();

        // Deploy proxy
        const ProxyFactory = await hre.ethers.getContractFactory("MinimalProxy", owner as any);
        proxy = await ProxyFactory.deploy(implAddress, { gasLimit: GAS_LIMIT });
        await proxy.waitForDeployment();
        const proxyAddress = await proxy.getAddress();

        // Create interface to call proxy as implementation
        proxyAsImpl = await hre.ethers.getContractAt(
            "MinimalImplementation",
            proxyAddress,
            owner as any
        ) as MinimalImplementation;

        console.log("\n" + "=".repeat(80));
        console.log("COMPLETE FLOW TEST: Encrypt → Validate → Add → OffBoard → Store → Decrypt");
        console.log("=".repeat(80));
        console.log(`Proxy:          ${proxyAddress}`);
        console.log(`Implementation: ${implAddress}`);
        console.log("=".repeat(80) + "\n");
    });

    it("✅ Full cycle with 200-bit numbers: Encrypt → Add → Store → Decrypt", async function () {
        const proxyAddress = await proxy.getAddress();
        const selector = proxyAsImpl.interface.getFunction("addAndStore")!.selector;
        
        // Use 200-bit numbers (larger than 128-bit but < 256-bit)
        const valueA = (2n ** 199n) + 123456789n; // ~200 bits
        const valueB = (2n ** 198n) + 987654321n; // ~199 bits
        const expected = valueA + valueB;
        
        console.log("=" .repeat(80));
        console.log("STEP 1: ENCRYPT OFFCHAIN");
        console.log("=".repeat(80));
        console.log(`Value A (200-bit): ${valueA.toString()}`);
        console.log(`Bit length:        ${valueA.toString(2).length} bits`);
        console.log(`Value B (199-bit): ${valueB.toString()}`);
        console.log(`Bit length:        ${valueB.toString(2).length} bits`);
        console.log(`Expected A + B:    ${expected.toString()}`);
        console.log(`Bit length:        ${expected.toString(2).length} bits`);
        console.log(`Signed for:        ${proxyAddress} (PROXY)`);
        console.log("");
        
        // Encrypt values offchain
        console.log("Encrypting values offchain using coti-ethers...");
        const encA = await owner.encryptValue(valueA, proxyAddress, selector);
        const encB = await owner.encryptValue(valueB, proxyAddress, selector);
        console.log("✅ Encryption complete");
        console.log(`   encA.ciphertext.high: ${encA.ciphertext.ciphertextHigh.toString()}`);
        console.log(`   encA.ciphertext.low:  ${encA.ciphertext.ciphertextLow.toString()}`);
        console.log(`   encB.ciphertext.high: ${encB.ciphertext.ciphertextHigh.toString()}`);
        console.log(`   encB.ciphertext.low:  ${encB.ciphertext.ciphertextLow.toString()}`);
        console.log("");
        
        console.log("=".repeat(80));
        console.log("STEP 2: SEND TRANSACTION (Validate → Add → OffBoard → Store)");
        console.log("=".repeat(80));
        
        // Send transaction
        const tx = await proxyAsImpl.connect(owner).addAndStore(encA, encB, { gasLimit: GAS_LIMIT });
        console.log(`Transaction hash: ${tx.hash}`);
        console.log("Waiting for confirmation...");
        
        const receipt = await tx.wait();
        console.log(`✅ Transaction confirmed in block ${receipt?.blockNumber}`);
        console.log(`   Gas used: ${receipt?.gasUsed.toString()}`);
        console.log("");
        
        // Check events
        console.log("=".repeat(80));
        console.log("STEP 3: VERIFY EVENTS");
        console.log("=".repeat(80));
        
        let eventCount = 0;
        receipt?.logs.forEach((log: any) => {
            try {
                const parsed = implementation.interface.parseLog({ topics: log.topics as string[], data: log.data });
                if (parsed) {
                    eventCount++;
                    console.log(`✅ Event ${eventCount}: ${parsed.name}`);
                    console.log(`   Message: ${parsed.args[1]}`);
                }
            } catch (e) {}
        });
        console.log("");
        
        expect(eventCount).to.be.greaterThan(0, "No events emitted - validation may have failed");
        
        console.log("=".repeat(80));
        console.log("STEP 4: READ FROM STORAGE");
        console.log("=".repeat(80));
        
        // Read the stored ctUint256 from storage
        console.log("Reading stored result from contract storage...");
        const storedCt = await proxyAsImpl.connect(owner).getStoredResult();
        console.log("✅ Storage read complete");
        console.log(`   Stored CT High: ${storedCt.ciphertextHigh.toString()}`);
        console.log(`   Stored CT Low:  ${storedCt.ciphertextLow.toString()}`);
        console.log("");
        
        console.log("=".repeat(80));
        console.log("STEP 5: DECRYPT OFFCHAIN");
        console.log("=".repeat(80));
        
        // Decrypt the result offchain
        console.log("Decrypting result offchain using coti-ethers...");
        // Explicitly format the struct to ensure correct format
        const decrypted = await owner.decryptValue({
            ciphertextHigh: storedCt.ciphertextHigh,
            ciphertextLow: storedCt.ciphertextLow
        });
        console.log("✅ Decryption complete");
        console.log(`   Decrypted value: ${decrypted.toString()}`);
        console.log("");
        
        console.log("=".repeat(80));
        console.log("STEP 6: VERIFY CORRECTNESS");
        console.log("=".repeat(80));
        console.log(`Original A:      ${valueA.toString()}`);
        console.log(`Original B:      ${valueB.toString()}`);
        console.log(`Expected A + B:  ${expected.toString()}`);
        console.log(`Decrypted result: ${decrypted.toString()}`);
        console.log("");
        
        expect(decrypted).to.equal(expected, "Decrypted result does not match expected");
        
        console.log("✅ VERIFICATION PASSED!");
        console.log("");
        console.log("=".repeat(80));
        console.log("SUMMARY");
        console.log("=".repeat(80));
        console.log("✅ 200-bit numbers encrypted offchain");
        console.log("✅ IT-types validated through proxy");
        console.log("✅ Addition performed on encrypted values");
        console.log("✅ Result offBoarded to user (ctUint256)");
        console.log("✅ Result stored in contract storage");
        console.log("✅ Result read from storage");
        console.log("✅ Result decrypted offchain");
        console.log("✅ Decrypted value matches expected");
        console.log("");
        console.log("CONCLUSION: IT-types + proxy + large numbers = ✅ WORKS PERFECTLY!");
        console.log("=".repeat(80) + "\n");
    });

    // Comment out other tests as requested
    /*
    it("❌ TEST 2: Wrong signing for implementation address", async function () {
        // ... test code ...
    });
    */
});
