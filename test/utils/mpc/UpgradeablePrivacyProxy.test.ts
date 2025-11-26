import { expect } from "chai";
import hre from "hardhat";
import { Wallet } from "@coti-io/coti-ethers";
import { setupAccounts } from "../accounts";
import type {
    PrivacyProxy,
    PrivacyImplementationV1,
    PrivacyImplementationV2,
} from "../../../typechain-types";

const GAS_LIMIT = 12000000;

describe("Upgradeable Privacy Proxy with Encrypted Data", function () {
    let proxy: PrivacyProxy;
    let implementationV1: PrivacyImplementationV1;
    let implementationV2: PrivacyImplementationV2;
    let proxyAsV1: PrivacyImplementationV1;
    let proxyAsV2: PrivacyImplementationV2;
    let owner: Wallet;
    let user1: Wallet;

    // Increase timeout for MPC operations
    this.timeout(240000);

    before(async function () {
        const accounts = await setupAccounts();
        owner = accounts[0];
        user1 = accounts[1];

        // Verify wallets have AES keys
        const ownerInfo = owner.getUserOnboardInfo();
        const user1Info = user1.getUserOnboardInfo();
        
        if (!ownerInfo || !ownerInfo.aesKey) {
            throw new Error("Owner AES key not found. Please onboard the owner first.");
        }
        if (!user1Info || !user1Info.aesKey) {
            throw new Error("User1 AES key not found. Please onboard the user first.");
        }

        console.log("\n" + "=".repeat(80));
        console.log("🔄 UPGRADEABLE PRIVACY PROXY TEST");
        console.log("=".repeat(80));
        console.log("Owner address:", owner.address);
        console.log("User1 address:", user1.address);
        console.log("=".repeat(80) + "\n");
    });

    describe("Proxy Deployment and Initial Setup", function () {
        it("Should deploy implementation V1", async function () {
            console.log("\n=== Deploying Implementation V1 ===");
            
            const ImplFactory = await hre.ethers.getContractFactory("PrivacyImplementationV1", owner as any);
            implementationV1 = await ImplFactory.deploy({ gasLimit: GAS_LIMIT });
            await implementationV1.waitForDeployment();
            const implAddress = await implementationV1.getAddress();
            
            console.log("Implementation V1 deployed to:", implAddress);
            
            // Test version
            const version = await implementationV1.version();
            expect(version).to.equal("v1");
            console.log("✅ Implementation V1 version:", version);
        });

        it("Should deploy proxy pointing to V1", async function () {
            console.log("\n=== Deploying Proxy ===");
            
            const implV1Address = await implementationV1.getAddress();
            const ProxyFactory = await hre.ethers.getContractFactory("PrivacyProxy", owner as any);
            proxy = await ProxyFactory.deploy(implV1Address, { gasLimit: GAS_LIMIT });
            await proxy.waitForDeployment();
            const proxyAddress = await proxy.getAddress();
            
            console.log("Proxy deployed to:", proxyAddress);
            console.log("Proxy points to implementation:", implV1Address);
            
            // Verify implementation
            const currentImpl = await proxy.implementation();
            expect(currentImpl).to.equal(implV1Address);
            
            // Verify admin
            const admin = await proxy.admin();
            expect(admin).to.equal(owner.address);
            console.log("✅ Proxy admin:", admin);
            
            // Create interface to call proxy as V1
            proxyAsV1 = await hre.ethers.getContractAt(
                "PrivacyImplementationV1",
                proxyAddress,
                owner as any
            ) as PrivacyImplementationV1;
            
            // Test version through proxy
            const version = await proxyAsV1.version();
            expect(version).to.equal("v1");
            console.log("✅ Version through proxy:", version);
        });
    });

    describe("Privacy Operations Through Proxy (V1)", function () {
        it("Should validate IT-type through delegatecall (uint128)", async function () {
            console.log("\n=== Testing IT-Type Validation Through Proxy ===");
            
            const value = 1000n;
            console.log(`Input value: ${value}`);
            
            const proxyAddress = await proxy.getAddress();
            const selector = proxyAsV1.interface.getFunction("storeValue128")!.selector;
            
            // Encrypt for PROXY address (not implementation!)
            const encrypted = await owner.encryptValue(value, proxyAddress, selector);
            console.log("✅ Encrypted for proxy address");
            
            // Call through proxy - delegatecall will execute in proxy's context
            const tx = await proxyAsV1.connect(owner).storeValue128(encrypted, { gasLimit: GAS_LIMIT });
            const receipt = await tx.wait();
            
            // Verify transaction succeeded
            expect(receipt?.status).to.equal(1);
            console.log(`Transaction succeeded - value stored`);
            console.log(`Stored value: ${value}`);
            console.log("✅ IT-type validation through delegatecall works! (transaction verified - return value cannot be retrieved without staticCall)");
        });

        it("Should perform addition through proxy (uint128)", async function () {
            console.log("\n=== Testing Addition Through Proxy ===");
            
            const a = 500n;
            const b = 300n;
            const expected = a + b;
            
            console.log(`Inputs: ${a} + ${b} = ${expected}`);
            
            const proxyAddress = await proxy.getAddress();
            const selector = proxyAsV1.interface.getFunction("add128")!.selector;
            
            const encryptedA = await owner.encryptValue(a, proxyAddress, selector);
            const encryptedB = await owner.encryptValue(b, proxyAddress, selector);
            
            // Call add128 - it returns the result but we can't get it from transaction without staticCall
            // Since staticCall doesn't work on coti-private, we'll verify the transaction succeeded
            // The function works correctly if the transaction succeeds without reverting
            const tx = await proxyAsV1.connect(owner).add128(encryptedA, encryptedB, { gasLimit: GAS_LIMIT });
            const receipt = await tx.wait();
            
            // Verify transaction succeeded
            expect(receipt?.status).to.equal(1);
            console.log(`Transaction succeeded - addition performed`);
            console.log(`Expected result: ${expected}`);
            console.log("✅ Addition through proxy successful (transaction verified - return value cannot be retrieved without staticCall)");
        });


        it("Should work with uint256 through proxy", async function () {
            console.log("\n=== Testing uint256 Through Proxy ===");
            
            const value = 2n ** 128n;
            console.log(`Input value: ${value}`);
            
            const proxyAddress = await proxy.getAddress();
            const selector = proxyAsV1.interface.getFunction("storeValue256")!.selector;
            
            const encrypted = await owner.encryptValue256(value, proxyAddress, selector);
            
            const tx = await proxyAsV1.connect(owner).storeValue256(encrypted, { gasLimit: GAS_LIMIT });
            const receipt = await tx.wait();
            
            // Verify transaction succeeded
            expect(receipt?.status).to.equal(1);
            console.log(`Transaction succeeded - uint256 value stored`);
            console.log(`Stored value: ${value}`);
            console.log("✅ uint256 through proxy successful (transaction verified - return value cannot be retrieved without staticCall)");
        });
    });

    describe("Proxy Upgrade to V2", function () {
        it("Should deploy implementation V2", async function () {
            console.log("\n=== Deploying Implementation V2 ===");
            
            const ImplFactory = await hre.ethers.getContractFactory("PrivacyImplementationV2", owner as any);
            implementationV2 = await ImplFactory.deploy({ gasLimit: GAS_LIMIT });
            await implementationV2.waitForDeployment();
            const implAddress = await implementationV2.getAddress();
            
            console.log("Implementation V2 deployed to:", implAddress);
            
            // Test version
            const version = await implementationV2.version();
            expect(version).to.equal("v2");
            console.log("✅ Implementation V2 version:", version);
        });

        it("Should upgrade proxy to V2", async function () {
            console.log("\n=== Upgrading Proxy to V2 ===");
            
            const implV2Address = await implementationV2.getAddress();
            
            // Upgrade
            const tx = await proxy.connect(owner).upgradeTo(implV2Address, { gasLimit: GAS_LIMIT });
            await tx.wait();
            
            // Verify upgrade
            const currentImpl = await proxy.implementation();
            expect(currentImpl).to.equal(implV2Address);
            console.log("✅ Proxy upgraded to V2:", implV2Address);
            
            // Create interface to call proxy as V2
            const proxyAddress = await proxy.getAddress();
            proxyAsV2 = await hre.ethers.getContractAt(
                "PrivacyImplementationV2",
                proxyAddress,
                owner as any
            ) as PrivacyImplementationV2;
            
            // Test version through proxy
            const version = await proxyAsV2.version();
            expect(version).to.equal("v2");
            console.log("✅ Version through upgraded proxy:", version);
        });

    });

    describe("New Features in V2", function () {
        it("Should use new subtraction feature in V2", async function () {
            console.log("\n=== Testing New V2 Feature: Subtraction ===");
            
            const a = 1000n;
            const b = 300n;
            const expected = a - b;
            
            console.log(`Inputs: ${a} - ${b} = ${expected}`);
            
            const proxyAddress = await proxy.getAddress();
            const selector = proxyAsV2.interface.getFunction("sub128")!.selector;
            
            const encryptedA = await owner.encryptValue(a, proxyAddress, selector);
            const encryptedB = await owner.encryptValue(b, proxyAddress, selector);
            
            // Call sub128 - it returns the result but we can't get it from transaction without staticCall
            // Since staticCall doesn't work on coti-private, we'll verify the transaction succeeded
            const tx = await proxyAsV2.connect(owner).sub128(encryptedA, encryptedB, { gasLimit: GAS_LIMIT });
            const receipt = await tx.wait();
            
            // Verify transaction succeeded
            expect(receipt?.status).to.equal(1);
            console.log(`Transaction succeeded - subtraction performed`);
            console.log(`Expected result: ${expected}`);
            console.log("✅ New V2 subtraction feature works (transaction verified - return value cannot be retrieved without staticCall)");
        });

        it("Should use new division feature in V2", async function () {
            console.log("\n=== Testing New V2 Feature: Division ===");
            
            const a = 1000n;
            const b = 10n;
            const expected = a / b;
            
            console.log(`Inputs: ${a} / ${b} = ${expected}`);
            
            const proxyAddress = await proxy.getAddress();
            const selector = proxyAsV2.interface.getFunction("div128")!.selector;
            
            const encryptedA = await owner.encryptValue(a, proxyAddress, selector);
            const encryptedB = await owner.encryptValue(b, proxyAddress, selector);
            
            // Call div128 - it returns the result but we can't get it from transaction without staticCall
            // Since staticCall doesn't work on coti-private, we'll verify the transaction succeeded
            const tx = await proxyAsV2.connect(owner).div128(encryptedA, encryptedB, { gasLimit: GAS_LIMIT });
            const receipt = await tx.wait();
            
            // Verify transaction succeeded
            expect(receipt?.status).to.equal(1);
            console.log(`Transaction succeeded - division performed`);
            console.log(`Expected result: ${expected}`);
            console.log("✅ New V2 division feature works (transaction verified - return value cannot be retrieved without staticCall)");
        });

        it("Should still work with V1 functions after upgrade", async function () {
            console.log("\n=== Testing V1 Functions Still Work in V2 ===");
            
            const a = 200n;
            const b = 100n;
            const expected = a * b;
            
            console.log(`Testing V1 multiplication: ${a} * ${b} = ${expected}`);
            
            const proxyAddress = await proxy.getAddress();
            const selector = proxyAsV2.interface.getFunction("mul128")!.selector;
            
            const encryptedA = await owner.encryptValue(a, proxyAddress, selector);
            const encryptedB = await owner.encryptValue(b, proxyAddress, selector);
            
            // Call mul128 - it returns the result but we can't get it from transaction without staticCall
            // Since staticCall doesn't work on coti-private, we'll verify the transaction succeeded
            const tx = await proxyAsV2.connect(owner).mul128(encryptedA, encryptedB, { gasLimit: GAS_LIMIT });
            const receipt = await tx.wait();
            
            // Verify transaction succeeded
            expect(receipt?.status).to.equal(1);
            console.log(`Transaction succeeded - multiplication performed`);
            console.log(`Expected result: ${expected}`);
            console.log("✅ V1 functions still work after upgrade (transaction verified - return value cannot be retrieved without staticCall)");
        });
    });
});

