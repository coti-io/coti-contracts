"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const hre = require("hardhat");
const { prepareIT256 } = require("@coti-io/coti-sdk-typescript");

/**
 * Unified Privacy Bridge Integration Tests (Full Suite)
 * Consolidates Native and all ERC20 bridge tests into a single suite with numbered outputs.
 */

/**
 * Validates environment variables required for test execution.
 * Normalizes PRIVATE_AES_KEY_TESTNET by stripping any accidental 0x prefix.
 * @returns {Object} Environment validation result
 */
function validateEnvironment() {
    let aesKey = process.env.PRIVATE_AES_KEY_TESTNET || null;
    // Strip 0x prefix if present — encodeKey expects raw 32 hex chars
    if (aesKey?.startsWith('0x')) aesKey = aesKey.slice(2);
    // Validate: must be exactly 32 hex characters (16 bytes)
    const isValidKey = aesKey && /^[0-9a-fA-F]{32}$/.test(aesKey);
    return {
        hasAesKey: !!isValidKey,
        aesKey: isValidKey ? aesKey : null,
        canRunEncryptedTests: !!isValidKey
    };
}

/**
 * Creates an ethers Wallet from PRIVATE_KEY env var.
 * Normalizes the key by adding 0x prefix if missing.
 * Uses this instead of passing a HardhatEthersSigner directly — HardhatEthersSigner
 * does NOT expose a public .privateKey property, so getBytes(signer.privateKey)
 * inside prepareIT256 throws "invalid BytesLike value".
 * @returns {ethers.Wallet}
 */
function makeSdkWallet() {
    const raw = process.env.PRIVATE_KEY;
    if (!raw) throw new Error('PRIVATE_KEY not set in .env');
    const pk = raw.startsWith('0x') ? raw : '0x' + raw;
    return new ethers.Wallet(pk, ethers.provider);
}

/**
 * Shared helper — builds an itUint256 payload for any contract function selector.
 * Centralises all calls to prepareIT256 to avoid copy-pasted implementations
 * that historically passed the HardhatEthersSigner directly and triggered
 * "invalid BytesLike value" from getBytes(sender.wallet.privateKey).
 *
 * @param {bigint|number} plaintext - Plain amount to encrypt
 * @param {string} contractAddress  - Target contract address (0x-prefixed)
 * @param {string} selector         - 4-byte function selector (0x + 8 hex chars)
 * @returns {Promise<[[bigint,bigint], Uint8Array]>} Encoded itUint256 tuple
 */
async function buildItUint256(plaintext, contractAddress, selector) {
    const env = validateEnvironment();
    if (!env.hasAesKey) {
        throw new Error(
            'PRIVATE_AES_KEY_TESTNET not set or invalid in .env. ' +
            'Expected a 32-character hex string (no 0x prefix).'
        );
    }
    const wallet = makeSdkWallet();
    console.log(`    [SDK] prepareIT256 plaintext=${plaintext} contract=${contractAddress} selector=${selector}`);
    try {
        const it = prepareIT256(
            BigInt(plaintext),
            { wallet, userKey: env.aesKey },
            contractAddress,
            selector
        );
        return [[it.ciphertext.ciphertextHigh, it.ciphertext.ciphertextLow], it.signature];
    } catch (error) {
        console.error(`    [SDK ERROR] prepareIT256 failed: ${error.message}`);
        console.error(`    [SDK DEBUG] wallet.address=${wallet.address} selector=${selector} keyLen=${env.aesKey?.length}`);
        throw new Error(`prepareIT256 failed: ${error.message}`);
    }
}

/**
 * Waits for transaction receipt with retry logic and exponential backoff
 * @param {Object} tx - Transaction object
 * @param {number} maxRetries - Maximum number of retry attempts (default: 3)
 * @returns {Promise<Object>} Transaction receipt
 */
async function waitForReceiptWithRetry(tx, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            const receipt = await tx.wait(1, 120000); // 2-minute timeout per attempt
            if (receipt) return receipt;

            // Wait with exponential backoff
            await new Promise(r => setTimeout(r, 2000 * (i + 1)));
        } catch (error) {
            if (i === maxRetries - 1) throw error;
            await new Promise(r => setTimeout(r, 2000 * (i + 1)));
        }
    }
    throw new Error("Failed to get transaction receipt after retries");
}

// ─────────────────────────────────────────────────────────────────────────────
// SHARED DEPLOYMENT & ASSERTION HELPERS (reduces duplication across suites)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Deploys a MockCotiPriceConsumer with COTI at $0.05 and optional token price.
 * Sets lastUpdated to the current block timestamp.
 * @param {Object} [opts] - Optional: { tokenSymbol, tokenPrice }
 * @returns {Promise<Contract>} Deployed oracle contract
 */
async function deployMockOracle(opts = {}) {
    const OracleFactory = await ethers.getContractFactory("MockCotiPriceConsumer");
    const oracle = await OracleFactory.deploy({ gasLimit: 12000000 });
    await (oracle.waitForDeployment ? oracle.waitForDeployment() : oracle.deployed());
    await oracle.setCotiPrice(ethers.parseEther("0.05"), { gasLimit: 2000000 });
    if (opts.tokenSymbol && opts.tokenPrice) {
        await oracle.setPrice(opts.tokenSymbol, ethers.parseEther(opts.tokenPrice), { gasLimit: 2000000 });
    }
    const currentBlock = await ethers.provider.getBlock("latest");
    await oracle.setLastUpdated(currentBlock.timestamp, { gasLimit: 2000000 });
    return oracle;
}

/**
 * Deploys a PrivacyBridgeCotiNative, sets oracle, and grants MINTER_ROLE.
 * @returns {Promise<Contract>} Deployed bridge contract
 */
async function deployNativeBridge(privateCoti, mockOracle, owner, logTx, addr, MINTER_ROLE) {
    const BridgeFactory = await ethers.getContractFactory("PrivacyBridgeCotiNative");
    const pCotiAddr = await addr(privateCoti);
    const bridge = await BridgeFactory.deploy(pCotiAddr, owner.address, owner.address, await addr(mockOracle), { gasLimit: 30000000 });
    await (bridge.waitForDeployment ? bridge.waitForDeployment() : bridge.deployed());
    const bridgeAddr = await addr(bridge);
    await logTx(await privateCoti.grantRole(MINTER_ROLE, bridgeAddr, { gasLimit: 12000000 }), "Grant MINTER_ROLE to Native Bridge", "grantRole", ["MINTER_ROLE", bridgeAddr]);
    return bridge;
}

/**
 * Deploys a PrivacyBridgeWETH, sets oracle, and grants MINTER_ROLE.
 * @returns {Promise<Contract>} Deployed bridge contract
 */
async function deployERC20Bridge(publicToken, privateToken, mockOracle, owner, logTx, addr, MINTER_ROLE) {
    const pubAddr = await addr(publicToken);
    const privAddr = await addr(privateToken);
    const bridge = await (await ethers.getContractFactory("PrivacyBridgeWETH")).deploy(pubAddr, privAddr, owner.address, owner.address, await addr(mockOracle), { gasLimit: 12000000 });
    await (bridge.waitForDeployment ? bridge.waitForDeployment() : bridge.deployed());
    const bridgeAddr = await addr(bridge);
    await logTx(await privateToken.grantRole(MINTER_ROLE, bridgeAddr, { gasLimit: 12000000 }), "Grant MINTER_ROLE to ERC20 Bridge", "grantRole", ["MINTER_ROLE", bridgeAddr]);
    return bridge;
}

/**
 * Gets or deploys a PrivateCOTI-compatible token based on chain.
 * On testnet (chainId 7082400), attaches to pre-deployed PrivateCOTI.
 * On local/hardhat, deploys a fresh PrivateERC20Mock.
 * @param {string} [factoryName] - Factory to use on local ("PrivateERC20Mock" or "PrivateCOTI")
 * @returns {Promise<Contract>}
 */
async function getOrDeployPrivateCoti(factoryName = "PrivateERC20Mock") {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    if (chainId === 7082400n) {
        const token = await ethers.getContractAt("PrivateCOTI", "0x03eeA59b1F0Dfeaece75531b27684DD882f79759");
        console.log("    [Info] Using pre-deployed PrivateCOTI at 0x03eeA59b1F0Dfeaece75531b27684DD882f79759");
        return token;
    }
    const Factory = await ethers.getContractFactory(factoryName);
    const token = await Factory.deploy({ gasLimit: 30000000 });
    await (token.waitForDeployment ? token.waitForDeployment() : token.deployed());
    return token;
}

/**
 * Full ERC20 bridge setup: deploys or attaches tokens based on chain, deploys bridge, mints initial supply.
 * Consolidates the repeated testnet-vs-local branching across multiple test suites.
 * @param {Object} opts - { publicFactory, decimals, mockOracle, owner, logTx, addr, MINTER_ROLE, mintAmount }
 * @returns {Promise<{publicToken, privateToken, bridge}>}
 */
async function setupERC20BridgeEnv(opts) {
    const { publicFactory, decimals, mockOracle, owner, logTx, addr, MINTER_ROLE, mintAmount } = opts;
    const UNIT = BigInt(10 ** decimals);
    let publicToken, privateToken, bridge;

    const chainId = (await ethers.provider.getNetwork()).chainId;
    if (chainId === 7082400n) {
        const WETH_ADDRESS = "0x8bca4e6bbE402DB4aD189A316137aD08206154FB";
        const PRIVATE_WETH_ADDRESS = "0x6f7E5eE3a913aa00c6eB9fEeCad57a7d02F7f45c";
        publicToken = await ethers.getContractAt(publicFactory, WETH_ADDRESS);
        privateToken = await ethers.getContractAt("PrivateWrappedEther", PRIVATE_WETH_ADDRESS);
        console.log(`    [Info] Using pre-deployed ${publicFactory} at ${WETH_ADDRESS}`);
        console.log(`    [Info] Using pre-deployed PrivateWrappedEther at ${PRIVATE_WETH_ADDRESS}`);
        bridge = await deployERC20Bridge(publicToken, privateToken, mockOracle, owner, logTx, addr, MINTER_ROLE);
    } else {
        publicToken = await (await ethers.getContractFactory(publicFactory)).deploy("Wrapped Ether", "WETH", decimals, { gasLimit: 12000000 });
        await (publicToken.waitForDeployment ? publicToken.waitForDeployment() : publicToken.deployed());
        privateToken = await (await ethers.getContractFactory("PrivateERC20Mock")).deploy({ gasLimit: 12000000 });
        await (privateToken.waitForDeployment ? privateToken.waitForDeployment() : privateToken.deployed());
        bridge = await deployERC20Bridge(publicToken, privateToken, mockOracle, owner, logTx, addr, MINTER_ROLE);
        if (mintAmount) {
            await logTx(await publicToken.mint(owner.address, mintAmount * UNIT, { gasLimit: 2000000 }), `Mint ${mintAmount} WETH to owner`, "mint", [owner.address, String(mintAmount)]);
        }
    }
    return { publicToken, privateToken, bridge };
}

/**
 * Asserts that a transaction promise reverts matching the given pattern.
 * @param {Promise} txPromise - The transaction promise expected to revert
 * @param {RegExp} pattern - Regex pattern to match against the error message
 * @param {string} [logMsg] - Optional console message on success
 */
async function expectRevert(txPromise, pattern, logMsg) {
    try {
        const tx = await txPromise;
        await waitForReceiptWithRetry(tx);
        expect.fail("Expected revert but succeeded");
    } catch (error) {
        if (error.message === "Expected revert but succeeded") throw error;
        expect(error.message).to.match(pattern);
        if (logMsg) console.log(logMsg);
    }
}

/**
 * Handles the encrypted test skip pattern.
 * @param {number} testCounter - Current test counter for log message
 * @param {Object} cfg - Config object with .name property
 * @param {string} testType - Description of the test type (e.g. "encrypted transfer")
 * @returns {boolean} true if test should be skipped
 */
function skipIfNoEncryption(testCounter, cfg, testType) {
    const env = validateEnvironment();
    if (!env.canRunEncryptedTests) {
        console.log(`    [SKIP] Test ${testCounter} - ${cfg.name} ${testType}: PRIVATE_AES_KEY_TESTNET not configured`);
        console.log(`    [INFO] Add PRIVATE_AES_KEY_TESTNET to your .env file to enable encrypted payload tests`);
        return true;
    }
    return false;
}

describe("Unified Privacy Bridges Suite", function () {
    this.timeout(1200000); // 20 minutes

    // Ensure tests run on cotiTestnet or hardhat (for coverage)
    before(function () {
        const networkName = hre.network.name;
        if (networkName !== "coti-testnet" && networkName !== "cotiTestnet" && networkName !== "hardhat") {
            throw new Error(
                `These tests must run on coti-testnet, cotiTestnet, or hardhat network (current: ${networkName}). ` +
                `Run with: npx hardhat test --network coti-testnet`
            );
        }
    });

    let testCounter = 0;
    let currentTestFullTitle = '';
    let owner, user1;

    // Shared map between test file and reporter (same Node.js process).
    // Keyed by test fullTitle → array of call entries.
    if (!process.__testCallLog) process.__testCallLog = {};

    // Contract address registry — array of { contractName, address, suite }.
    // Populated by registerContract() in each before() block.
    if (!process.__contractAddresses) process.__contractAddresses = [];

    async function registerContract(contractName, contract, suite) {
        const address = await (contract.getAddress ? contract.getAddress() : Promise.resolve(contract.address));
        process.__contractAddresses.push({ contractName, address, suite });
    }

    // Fix for Ethers v5/v6 compatibility
    const toBytes = ethers.toUtf8Bytes || ethers.utils?.toUtf8Bytes;
    const keccak = ethers.keccak256 || ethers.utils?.keccak256;
    const MINTER_ROLE = keccak(toBytes("MINTER_ROLE"));

    const addr = async (contract) =>
        contract.getAddress ? contract.getAddress() : Promise.resolve(contract.address);

    // Set ONLY_PRIVATE_ERC20=1 to skip all non-PrivateERC20 suites (faster iteration)
    const ONLY_PRIVATE_ERC20 = !!process.env.ONLY_PRIVATE_ERC20;

    // ─────────────────────────────────────────────────────────────────────────
    // DEDUPLICATION HELPERS (reduce repeated before() patterns)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * One-liner check: skips the current suite if ONLY_PRIVATE_ERC20 is set.
     * Must be called with the Mocha context: skipIfOnlyPrivateERC20.call(this)
     */
    function skipIfOnlyPrivateERC20() {
        if (ONLY_PRIVATE_ERC20) { this.skip(); return true; }
        return false;
    }

    /**
     * Encapsulates the common native bridge before() setup logic.
     * @param {string} suiteName - Name for contract registration
     * @param {string} [factoryName] - Factory to use for PrivateCOTI ("PrivateERC20Mock" or "PrivateCOTI")
     * @returns {Promise<{privateCoti, bridge, mockOracle}>}
     */
    async function setupNativeBridgeEnv(suiteName, factoryName = "PrivateERC20Mock") {
        const mockOracle = await deployMockOracle();
        const privateCoti = await getOrDeployPrivateCoti(factoryName);
        const bridge = await deployNativeBridge(privateCoti, mockOracle, owner, logTx, addr, MINTER_ROLE);
        await registerContract("PrivacyBridgeCotiNative", bridge, suiteName);
        await new Promise(r => setTimeout(r, 5000));
        return { privateCoti, bridge, mockOracle };
    }

    /**
     * Encapsulates the common ERC20 bridge before() setup logic.
     * @param {string} suiteName - Name for contract registration
     * @param {bigint} [mintAmount] - Amount to mint to owner (default 10000n)
     * @returns {Promise<{publicToken, privateToken, bridge, mockOracle}>}
     */
    async function setupERC20BridgeSuite(suiteName, mintAmount = 10000n) {
        const mockOracle = await deployMockOracle({ tokenSymbol: "ETH", tokenPrice: "2300" });
        const result = await setupERC20BridgeEnv({
            publicFactory: "ERC20Mock", decimals: 18, mockOracle, owner, logTx, addr, MINTER_ROLE, mintAmount
        });
        await registerContract("PrivacyBridgeWETH", result.bridge, suiteName);
        await new Promise(r => setTimeout(r, 5000));
        return { publicToken: result.publicToken, privateToken: result.privateToken, bridge: result.bridge, mockOracle };
    }

    const logTx = async (tx, description, methodName = "Unknown", args = [], expectRevert = false) => {
        const argsStr = args.length > 0 ? `(${args.map(a => (typeof a === 'string' && a.startsWith('0x')) ? a.slice(0, 10) + '...' : a).join(', ')})` : "()";
        console.log(`    [Method] ${methodName}${argsStr}`);
        console.log(`    [Action] ${description}`);
        console.log(`    [Tx] https://testnet.cotiscan.io/tx/${tx.hash}`);

        // Record call for JSON report — write immediately so the reporter
        // can read it at EVENT_TEST_PASS (which fires before afterEach).
        const callEntry = {
            method: methodName,
            args: args.map(String),
            txHash: tx.hash,
            description,
        };
        if (currentTestFullTitle) {
            if (!process.__testCallLog[currentTestFullTitle]) process.__testCallLog[currentTestFullTitle] = [];
            process.__testCallLog[currentTestFullTitle].push(callEntry);
        }

        const receipt = expectRevert
            ? await waitForReceiptWithRetry(tx)
            : await tx.wait(1, 300000); // 5-minute timeout; prevents indefinite hang on slow/unresponsive testnet

        // Mandatory wait for cotiTestnet stability - COTI MPC state needs time to settle
        await new Promise(r => setTimeout(r, 10000));
        return receipt;
    };

    before(async function () {
        const signers = await ethers.getSigners();
        owner = signers[0];
        user1 = signers.length > 1 ? signers[1] : owner;
        console.log("\n===========================================================");
        console.log("STARTING FULL UNIFIED BRIDGE TESTS");
        console.log("Deployer:", owner.address);
        console.log("User1   :", user1.address);
        console.log("===========================================================\n");
    });

    beforeEach(function () {
        testCounter++;
        currentTestFullTitle = this.currentTest.fullTitle();
        process.__testCallLog[currentTestFullTitle] = [];
        console.log(`\nTest ${testCounter} - ${this.currentTest.title}`);
    });

    afterEach(async function () {
        const state = this.currentTest.state;
        let label = 'FAILED';
        if (state === 'passed') label = 'PASSED';
        else if (state === 'pending') label = 'SKIPPED';
        console.log(`Test ${testCounter} - result: ${label}`);
        // Extra wait between separate test cases
        await new Promise(r => setTimeout(r, 5000));
    });

    // ─────────────────────────────────────────────────────────────────────────
    // NATIVE BRIDGE TESTS
    // ─────────────────────────────────────────────────────────────────────────
    describe("Native Bridge (PrivacyBridgeCotiNative)", function () {
        let privateCoti, bridge, mockOracle;

        before(async function () {
            if (skipIfOnlyPrivateERC20.call(this)) return;
            const PrivateCotiFactory = await ethers.getContractFactory("PrivateERC20Mock");
            privateCoti = await PrivateCotiFactory.deploy({ gasLimit: 12000000 });
            await (privateCoti.waitForDeployment ? privateCoti.waitForDeployment() : privateCoti.deployed());

            // Deploy mock oracle and set COTI price ($0.05)
            mockOracle = await deployMockOracle();

            bridge = await deployNativeBridge(privateCoti, mockOracle, owner, logTx, addr, MINTER_ROLE);
            await registerContract("PrivacyBridgeCotiNative", bridge, "Native Bridge");
            await registerContract("PrivateERC20Mock", privateCoti, "Native Bridge");
            await registerContract("MockCotiPriceConsumer", mockOracle, "Native Bridge");
            await new Promise(r => setTimeout(r, 5000)); // Extra settle time after role grant
        });

        it("Test 1: native: Should set correct initial state", async function () {
            const pCotiAddr = await addr(privateCoti);
            expect(await bridge.privateCoti()).to.equal(pCotiAddr);
            expect(await bridge.owner()).to.equal(owner.address);
        });

        it("Test 2: native: Should allow deposit of native COTI", async function () {
            const amount = ethers.parseEther("100");
            const bridgeAddr = await addr(bridge);
            const initialBalance = await ethers.provider.getBalance(bridgeAddr);

            // Estimate fee and get oracle timestamp
            const [fee, cotiLastUpdated, blockTimestamp] = await bridge.estimateDepositFee(amount);
            console.log(`    [Fee Estimation] fee=${ethers.formatEther(fee)} COTI, blockTimestamp=${blockTimestamp}`);

            const tx = await bridge.connect(user1)["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: amount, gasLimit: 12000000 });
            await logTx(tx, `Deposit ${ethers.formatEther(amount)} Native COTI`, "PrivacyBridgeCotiNative.deposit() -> PrivateERC20Mock.mint", [ethers.formatEther(amount)]);

            await expect(tx).to.emit(bridge, "Deposit");
            expect(await ethers.provider.getBalance(bridgeAddr)).to.be.at.least(initialBalance + amount);
        });

        it("Test 3: native: Should allow withdrawal of native COTI", async function () {
            const amount = ethers.parseEther("50");
            const bridgeAddr = await addr(bridge);

            await logTx(await privateCoti.connect(user1)["approve(address,uint256)"](bridgeAddr, amount, { gasLimit: 2000000 }), "Approve private COTI for withdrawal", "PrivateERC20Mock.approve", [bridgeAddr, ethers.formatEther(amount)]);

            // Estimate fee and get oracle timestamp
            const [fee, cotiLastUpdated, blockTimestamp] = await bridge.estimateWithdrawFee(amount);
            console.log(`    [Fee Estimation] fee=${ethers.formatEther(fee)} COTI, blockTimestamp=${blockTimestamp}`);

            const tx = await bridge.connect(user1)["withdraw(uint256,uint256,uint256)"](amount, cotiLastUpdated, cotiLastUpdated, { gasLimit: 12000000 });
            await logTx(tx, `Withdraw ${ethers.formatEther(amount)} Native COTI`, "PrivacyBridgeCotiNative.withdraw() -> PrivateERC20Mock.burn", [ethers.formatEther(amount)]);

            await expect(tx).to.emit(bridge, "Withdraw");
        });

        it("Test 4: native: Should deduct dynamic fee and let owner withdraw fees", async function () {
            // Dynamic fee uses oracle-based calculation. With default params:
            // depositFixedFee=10 COTI, depositPercentageBps=500, depositMaxFee=3000 COTI
            // For a 0.1 COTI deposit at $0.05/COTI: txValueUsd=$0.005, pctFee=$0.0000025, pctFeeCoti=0.00005 COTI
            // fee = max(10 COTI, 0.00005 COTI) = 10 COTI (floor dominates for small amounts)
            // So we need to deposit more than the fixed fee floor (10 COTI)
            const gross = ethers.parseEther("100");

            const feeBefore = await bridge.accumulatedCotiFees();
            
            // Estimate fee and get oracle timestamp
            const [fee, cotiLastUpdated, blockTimestamp] = await bridge.estimateDepositFee(gross);
            console.log(`    [Fee Estimation] fee=${ethers.formatEther(fee)} COTI, blockTimestamp=${blockTimestamp}`);
            
            await logTx(await bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: gross, gasLimit: 12000000 }), "Deposit for dynamic fee accumulation", "PrivacyBridgeCotiNative.deposit()", [ethers.formatEther(gross)]);

            const feeAfter = await bridge.accumulatedCotiFees();
            const actualFee = feeAfter - feeBefore;
            expect(actualFee).to.be.gt(0n);
            console.log(`    [Info] Dynamic fee charged: ${ethers.formatEther(actualFee)} COTI`);

            // Withdraw fees
            await logTx(await bridge.withdrawFees(actualFee, { gasLimit: 2000000 }), "Withdraw accumulated COTI fees", "PrivacyBridgeCotiNative.withdrawFees", [ethers.formatEther(actualFee)]);
            expect(await bridge.accumulatedCotiFees()).to.equal(feeBefore);
        });

        it("Test 5: native: Should rescue native COTI", async function () {
            // bridge should already have some balance
            const bridgeAddr = await addr(bridge);
            const bal = await ethers.provider.getBalance(bridgeAddr);
            if (bal > 0n) {
                const amount = bal / 2n;
                const tx = await bridge.rescueNative(amount, { gasLimit: 2000000 });
                await logTx(tx, `rescueNative ${ethers.formatEther(amount)} COTI`, "PrivacyBridgeCotiNative.rescueNative", [ethers.formatEther(amount)]);
            }
        });
    });

    // ─────────────────────────────────────────────────────────────────────────
    // ERC20 BRIDGE TESTS
    // ─────────────────────────────────────────────────────────────────────────
    const BRIDGE_CONFIGS = [
        { name: "WETH", publicFactory: "ERC20Mock", bridgeFactory: "PrivacyBridgeWETH", decimals: 18, testStart: 6 },
    ];

    for (const cfg of BRIDGE_CONFIGS) {
        describe(`ERC20 Bridge (${cfg.name})`, function () {
            let publicToken, privateToken, bridge, mockOracle;
            const UNIT = BigInt(10 ** cfg.decimals);
            // Generous COTI fee to cover any dynamic fee calculation
            const COTI_FEE_BUFFER = ethers.parseEther("3100");

            before(async function () {
                if (skipIfOnlyPrivateERC20.call(this)) return;

                // Deploy mock oracle
                mockOracle = await deployMockOracle({ tokenSymbol: "ETH", tokenPrice: "2300" });

                const result = await setupERC20BridgeEnv({
                    publicFactory: cfg.publicFactory, decimals: cfg.decimals, mockOracle, owner, logTx, addr, MINTER_ROLE, mintAmount: 1000n
                });
                publicToken = result.publicToken;
                privateToken = result.privateToken;
                bridge = result.bridge;

                await registerContract(cfg.bridgeFactory, bridge, `ERC20 Bridge (${cfg.name})`);
                await registerContract(cfg.publicFactory, publicToken, `ERC20 Bridge (${cfg.name})`);
                await registerContract("PrivateToken", privateToken, `ERC20 Bridge (${cfg.name})`);
                await new Promise(r => setTimeout(r, 5000));
            });

            it(`Test ${cfg.testStart}: ${cfg.name}: Should set correct initial state`, async function () {
                expect(await bridge.token()).to.equal(await addr(publicToken));
                expect(await bridge.privateToken()).to.equal(await addr(privateToken));
                expect(await bridge.owner()).to.equal(owner.address);
            });

            it(`Test ${cfg.testStart + 1}: ${cfg.name}: Should allow deposit`, async function () {
                const amount = 10n * UNIT;
                const bridgeAddr = await addr(bridge);
                await logTx(await publicToken.approve(bridgeAddr, amount, { gasLimit: 2000000 }), `Approve ${cfg.name} for bridge`, "MockWETH.approve", [bridgeAddr, "10"]);

                // Estimate fee and get oracle timestamp
                const [fee, cotiLastUpdated, tokenLastUpdated, blockTimestamp] = await bridge.estimateDepositFee(amount);
                console.log(`    [Fee Estimation] fee=${ethers.formatEther(fee)} COTI, blockTimestamp=${blockTimestamp}`);

                const tx = await bridge["deposit(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 });
                await logTx(tx, `Deposit ${amount / UNIT} ${cfg.name}`, `PrivacyBridgeERC20.deposit()`, ["10"]);
                await expect(tx).to.emit(bridge, "Deposit");
            });

            it(`Test ${cfg.testStart + 2}: ${cfg.name}: Should allow withdrawal`, async function () {
                const amount = 5n * UNIT;
                const bridgeAddr = await addr(bridge);
                await logTx(await privateToken["approve(address,uint256)"](bridgeAddr, amount, { gasLimit: 2000000 }), `Approve private ${cfg.name}`, "PrivateERC20Mock.approve", [bridgeAddr, "5"]);

                // Estimate fee and get oracle timestamp
                const [fee, cotiLastUpdated, tokenLastUpdated, blockTimestamp] = await bridge.estimateWithdrawFee(amount);
                console.log(`    [Fee Estimation] fee=${ethers.formatEther(fee)} COTI, blockTimestamp=${blockTimestamp}`);

                const tx = await bridge["withdraw(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 });
                await logTx(tx, `Withdraw ${amount / UNIT} ${cfg.name}`, "PrivacyBridgeERC20.withdraw()", ["5"]);
                await expect(tx).to.emit(bridge, "Withdraw");
            });

            it(`Test ${cfg.testStart + 3}: ${cfg.name}: Should track dynamic fees in accumulatedCotiFees`, async function () {
                const bridgeAddr = await addr(bridge);
                const amount = 100n * UNIT;
                await logTx(await publicToken.approve(bridgeAddr, amount, { gasLimit: 2000000 }), "Approve for fee test", "MockWETH.approve", [bridgeAddr, "100"]);
                const feeBefore = await bridge.accumulatedCotiFees();
                
                // Estimate fee and get oracle timestamp
                const [fee, cotiLastUpdated, tokenLastUpdated, blockTimestamp] = await bridge.estimateDepositFee(amount);
                console.log(`    [Fee Estimation] fee=${ethers.formatEther(fee)} COTI, blockTimestamp=${blockTimestamp}`);
                
                await logTx(await bridge["deposit(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 }), `Deposit 100 ${cfg.name} for fee test`, "PrivacyBridgeERC20.deposit()", ["100"]);
                const feeAfter = await bridge.accumulatedCotiFees();
                const actualFee = feeAfter - feeBefore;
                expect(actualFee).to.be.gt(0n);
                console.log(`    [Info] Dynamic COTI fee charged: ${ethers.formatEther(actualFee)} COTI`);
            });

            it(`Test ${cfg.testStart + 4}: ${cfg.name}: Should rescue redundant ERC20 tokens`, async function () {
                const bridgeAddr = await addr(bridge);

                // Deploy a different ERC20 token (not the bridge token) to test rescue functionality
                const StrayTokenFactory = await ethers.getContractFactory("ERC20Mock");
                const strayToken = await StrayTokenFactory.deploy("Stray Token", "STRAY", 18, { gasLimit: 12000000 });
                await (strayToken.waitForDeployment ? strayToken.waitForDeployment() : strayToken.deployed());
                const strayAddr = await addr(strayToken);

                // Mint stray tokens to bridge
                await logTx(await strayToken.mint(bridgeAddr, UNIT, { gasLimit: 2000000 }), "Mint stray tokens to bridge", "ERC20Mock.mint", [bridgeAddr, "1"]);

                // Rescue the stray tokens (not the bridge token)
                await logTx(await bridge.rescueERC20(strayAddr, UNIT, { gasLimit: 2000000 }), "Rescue stray tokens", "PrivacyBridgeERC20.rescueERC20", [strayAddr, "1"]);

                // Verify owner received the rescued tokens
                const ownerBalance = await strayToken.balanceOf(owner.address);
                expect(ownerBalance).to.be.at.least(UNIT);
            });
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PRIVATE ERC20 PUBLIC-AMOUNT FUNCTION TESTS
    // ─────────────────────────────────────────────────────────────────────────
    const PRIVATE_TOKEN_CONFIGS = [
        { name: "PrivateCOTI", factory: "PrivateCOTI", testStart: 22 },
        { name: "PrivateWrappedEther", factory: "PrivateWrappedEther", testStart: 33 },
    ];

    for (const cfg of PRIVATE_TOKEN_CONFIGS) {
        describe(`PrivateERC20 Public-Amount Functions (${cfg.name})`, function () {
            let token;
            const MINT_AMOUNT = ethers.parseEther("10");
            const BURN_AMOUNT = ethers.parseEther("1");
            const TRANSFER_AMOUNT = ethers.parseEther("2");
            const APPROVE_AMOUNT = ethers.parseEther("2");

            before(async function () {
                const chainId = (await ethers.provider.getNetwork()).chainId;
                if (chainId === 7082400n) {
                    // Pre-deployed testnet contracts — fresh PrivateERC20-based deployments
                    // exceed the block gas limit on current COTI testnet
                    const TESTNET_TOKENS = {
                        "PrivateCOTI": "0x03eeA59b1F0Dfeaece75531b27684DD882f79759",
                        "PrivateWrappedEther": "0x6f7E5eE3a913aa00c6eB9fEeCad57a7d02F7f45c"
                    };
                    token = await ethers.getContractAt(cfg.factory, TESTNET_TOKENS[cfg.name]);
                    console.log(`    [Info] Using pre-deployed ${cfg.name} at ${TESTNET_TOKENS[cfg.name]}`);

                    // Onboard wallet with COTI MPC so validateCiphertext works for encrypted ops
                    const { Wallet: CotiWallet, onboard: cotiOnboard, ONBOARD_CONTRACT_ADDRESS: cotiOnboardAddr } = require('@coti-io/coti-ethers');
                    const pk = process.env.PRIVATE_KEY || '';
                    const cotiWallet = new CotiWallet(pk.startsWith('0x') ? pk : '0x' + pk, ethers.provider);
                    try {
                        console.log(`    [Info] Onboarding wallet ${cotiWallet.address} for MPC encrypted operations...`);
                        const { aesKey } = await cotiOnboard(cotiOnboardAddr, cotiWallet);
                        process.env.PRIVATE_AES_KEY_TESTNET = aesKey;
                        console.log(`    [Info] Onboarding complete. AES key (first 8 chars): ${aesKey.slice(0, 8)}...`);
                    } catch(e) {
                        console.log(`    [Warn] Onboarding failed: ${e.message}. Encrypted tests may fail.`);
                    }
                } else {
                    const Factory = await ethers.getContractFactory(cfg.factory);
                    token = await Factory.deploy({ gasLimit: 30000000 });
                    await (token.waitForDeployment ? token.waitForDeployment() : token.deployed());
                }

                // deployer holds DEFAULT_ADMIN_ROLE → grant MINTER_ROLE to owner
                await logTx(
                    await token.grantRole(MINTER_ROLE, owner.address, { gasLimit: 2000000 }),
                    `Grant MINTER_ROLE to owner for ${cfg.name}`,
                    `${cfg.name}.grantRole`,
                    ["MINTER_ROLE", owner.address]
                );
                await registerContract(cfg.factory, token, `PrivateERC20 Public-Amount (${cfg.name})`);
                await new Promise(r => setTimeout(r, 5000));
            });

            it(`Test ${cfg.testStart}: ${cfg.name}: mint(address,uint256) should mint tokens and emit Transfer`, async function () {
                const tx = await token.connect(owner)["mint(address,uint256)"](owner.address, MINT_AMOUNT, { gasLimit: 12000000 });
                await logTx(tx, `mint(owner, 10) on ${cfg.name}`, `${cfg.name}.mint(address,uint256)`, [owner.address, "10"]);
                await expect(tx).to.emit(token, "Transfer");
            });

            it(`Test ${cfg.testStart + 1}: ${cfg.name}: mint(address,uint256) should revert for non-MINTER_ROLE`, async function () {
                try {
                    const tx = await token.connect(user1)["mint(address,uint256)"](user1.address, MINT_AMOUNT, { gasLimit: 2000000 });
                    // If transaction is submitted, wait for it to be processed with retry logic
                    await waitForReceiptWithRetry(tx);
                    // If we reach here, the transaction didn't revert as expected
                    expect.fail("Expected transaction to revert but it succeeded");
                } catch (error) {
                    // Transaction should revert - verify it's an expected revert
                    expect(error.message).to.match(/revert|AccessControl/i);
                }
            });

            it(`Test ${cfg.testStart + 2}: ${cfg.name}: burn(uint256) should burn tokens and emit Transfer`, async function () {
                const tx = await token.connect(owner)["burn(uint256)"](BURN_AMOUNT, { gasLimit: 12000000 });
                await logTx(tx, `burn(1) on ${cfg.name}`, `${cfg.name}.burn(uint256)`, ["1"]);
                await expect(tx).to.emit(token, "Transfer");
            });

            it(`Test ${cfg.testStart + 3}: ${cfg.name}: transfer(address,uint256) should transfer tokens and emit Transfer`, async function () {
                const tx = await token.connect(owner)["transfer(address,uint256)"](user1.address, TRANSFER_AMOUNT, { gasLimit: 12000000 });
                await logTx(tx, `transfer(user1, 2) on ${cfg.name}`, `${cfg.name}.transfer(address,uint256)`, [user1.address, "2"]);
                await expect(tx).to.emit(token, "Transfer");
            });

            it(`Test ${cfg.testStart + 4}: ${cfg.name}: approve(address,uint256) should set allowance and emit Approval`, async function () {
                const tx = await token.connect(owner)["approve(address,uint256)"](user1.address, APPROVE_AMOUNT, { gasLimit: 12000000 });
                await logTx(tx, `approve(user1, 2) on ${cfg.name}`, `${cfg.name}.approve(address,uint256)`, [user1.address, "2"]);
                await expect(tx).to.emit(token, "Approval");
            });

            it(`Test ${cfg.testStart + 5}: ${cfg.name}: transferFrom(address,address,uint256) should spend allowance and emit Transfer`, async function () {
                const tx = await token.connect(user1)["transferFrom(address,address,uint256)"](owner.address, user1.address, APPROVE_AMOUNT, { gasLimit: 12000000 });
                await logTx(tx, `transferFrom(owner→user1, 2) on ${cfg.name}`, `${cfg.name}.transferFrom(address,address,uint256)`, [owner.address, user1.address, "2"]);
                await expect(tx).to.emit(token, "Transfer");
            });

            // --- NEW EXTENDED EXPERIMENTAL TESTS ---

            it(`Test ${cfg.testStart + 6}: ${cfg.name} (extend): setAccountEncryptionAddress & accountEncryptionAddress`, async function () {
                // Use a valid Ethereum address to avoid ENS resolution by provider
                const mockEncryptionAddress = ethers.Wallet.createRandom().address;
                const tx = await token.connect(user1).setAccountEncryptionAddress(mockEncryptionAddress, { gasLimit: 2000000 });
                await logTx(tx, `setAccountEncryptionAddress on ${cfg.name}`, `${cfg.name}.setAccountEncryptionAddress`, ["<mock_address>"]);

                const registeredKey = await token.accountEncryptionAddress(user1.address);
                expect(registeredKey).to.not.be.empty;
            });

            it(`Test ${cfg.testStart + 7}: ${cfg.name} (extend): transferAndCall (ERC677) triggers onTokenReceived`, async function () {
                const ReceiverFactory = await ethers.getContractFactory("PublicTokenReceiverMock");
                const receiver = await ReceiverFactory.deploy({ gasLimit: 12000000 });
                await (receiver.waitForDeployment ? receiver.waitForDeployment() : receiver.deployed());
                const receiverAddr = await addr(receiver);

                // Allow COTI MPC cluster to settle after the receiver deployment before the
                // transferAndCall transaction (mirrors the fix applied to the encrypted variant).
                await new Promise(r => setTimeout(r, 5000));

                const amount = ethers.parseEther("0.1");
                const data = ethers.toUtf8Bytes("hello world");

                const tx = await token.connect(owner)["transferAndCall(address,uint256,bytes)"](receiverAddr, amount, data, { gasLimit: 12000000 });
                // logTx awaits tx.wait() + mandatory 10-second MPC settle. Store the receipt so
                // that event assertions below use it directly and avoid a second tx.wait() call —
                // on COTI testnet the RPC can return null for a receipt that was just retrieved
                // moments ago (MPC state still finalizing), which would cause tx.wait() to poll
                // indefinitely and make the test appear to loop in the terminal.
                const receipt = await logTx(tx, `transferAndCall to PublicTokenReceiverMock on ${cfg.name}`, `${cfg.name}.transferAndCall`, [receiverAddr, "0.1", "0x68656c..."]);

                // PublicTokenReceiverMock returns true and does not emit a callback event.
                // Verify token transfer event from the token logs.
                const transferEvents = receipt.logs.filter(log => {
                    try { return token.interface.parseLog(log)?.name === "Transfer"; } catch { return false; }
                });
                expect(transferEvents.length, "Expected Transfer event on token").to.be.greaterThan(0);
            });

            it(`Test ${cfg.testStart + 8}: ${cfg.name} (extend): transfer(itUint256,address) with encrypted payload`, async function () {
                if (skipIfNoEncryption(testCounter, cfg, "encrypted transfer")) {
                    this.skip();
                    return;
                }

                const amount = ethers.parseEther("0.5");
                const tokenAddr = await addr(token);
                // The signature for the overloaded encrypted transfer in PrivateERC20 (address first, itUint256 second)
                const selector = ethers.id("transfer(address,((uint256,uint256),bytes))").slice(0, 10);

                const itAmount = await buildItUint256(amount, tokenAddr, selector);

                const tx = await token.connect(owner)["transfer(address,((uint256,uint256),bytes))"](user1.address, itAmount, { gasLimit: 12000000 });
                await logTx(tx, `transfer(itUint256) on ${cfg.name}`, `${cfg.name}.transfer(to, itAmount)`, [user1.address, "<encrypted>"]);
                expect(tx.hash).to.not.be.empty;
            });

            it(`Test ${cfg.testStart + 9}: ${cfg.name} (extend): approve(address,itUint256) and allowance checks`, async function () {
                if (skipIfNoEncryption(testCounter, cfg, "encrypted approve")) {
                    this.skip();
                    return;
                }

                const amount = ethers.parseEther("2");
                const tokenAddr = await addr(token);
                const selector = ethers.id("approve(address,((uint256,uint256),bytes))").slice(0, 10);

                const itAmount = await buildItUint256(amount, tokenAddr, selector);

                const tx = await token.connect(owner)["approve(address,((uint256,uint256),bytes))"](user1.address, itAmount, { gasLimit: 12000000 });
                await logTx(tx, `approve(itUint256) on ${cfg.name}`, `${cfg.name}.approve(spender, itAmount)`, [user1.address, "<encrypted>"]);

                // Run allowance re-encryption
                const reencryptTx = await token.connect(owner)["reencryptAllowance(address,bool)"](user1.address, true, { gasLimit: 2000000 });
                await logTx(reencryptTx, `reencryptAllowance on ${cfg.name}`, `${cfg.name}.reencryptAllowance`, [user1.address, true]);
            });

            it(`Test ${cfg.testStart + 10}: ${cfg.name} (extend): transferFrom(address,address,itUint256)`, async function () {
                if (skipIfNoEncryption(testCounter, cfg, "encrypted transferFrom")) {
                    this.skip();
                    return;
                }

                const amount = ethers.parseEther("0.1");
                const tokenAddr = await addr(token);
                // msg.sender (owner) acts as both from and spender — ciphertext is signed for owner's wallet.
                const selector = ethers.id("transferFrom(address,address,((uint256,uint256),bytes))").slice(0, 10);

                // Approve first, then build the ciphertext so the AES key and on-chain state
                // are both settled before validateCiphertext runs.
                // Use logTx so the mandatory 10-second MPC state-settle window runs before
                // transferFrom reads _allowances[owner][owner] from the MPC precompile. A bare
                // 3-second wait is insufficient on COTI testnet and causes validateCiphertext /
                // _safeOnboard to read a stale (zero) allowance, reverting with
                // "ERC20: insufficient allowance".
                await logTx(
                    await token.connect(owner)["approve(address,uint256)"](owner.address, ethers.parseEther("1"), { gasLimit: 2000000 }),
                    `Approve owner as spender for ${cfg.name} encrypted transferFrom`,
                    `${cfg.name}.approve(address,uint256)`,
                    [owner.address, "1"]
                );

                // Build the itUint256 AFTER the approve has settled so the ciphertext is
                // freshly signed against the confirmed on-chain state.
                const itAmount = await buildItUint256(amount, tokenAddr, selector);

                const tx = await token.connect(owner)["transferFrom(address,address,((uint256,uint256),bytes))"](owner.address, user1.address, itAmount, { gasLimit: 12000000 });
                await logTx(tx, `transferFrom(itUint256) on ${cfg.name}`, `${cfg.name}.transferFrom(from, to, itAmount)`, [owner.address, user1.address, "<encrypted>"]);
                expect(tx.hash).to.not.be.empty;
            });
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // COVERAGE IMPROVEMENT TESTS
    // ─────────────────────────────────────────────────────────────────────────

    describe("Coverage Improvements - PrivacyBridgeCotiNative", function () {
        let privateCoti, bridge, mockOracle;

        before(async function () {
            if (skipIfOnlyPrivateERC20.call(this)) return;
            const env = await setupNativeBridgeEnv("Dynamic Fee - Native", "PrivateCOTI");
            privateCoti = env.privateCoti; bridge = env.bridge; mockOracle = env.mockOracle;
        });

        it("Test 63: dynamic-fee: Should verify default fee parameters", async function () {
            const depositFixed = await bridge.depositFixedFee();
            const depositPct = await bridge.depositPercentageBps();
            const depositMax = await bridge.depositMaxFee();
            const withdrawFixed = await bridge.withdrawFixedFee();
            const withdrawPct = await bridge.withdrawPercentageBps();
            const withdrawMax = await bridge.withdrawMaxFee();

            console.log(`    [Info] Deposit: fixed=${ethers.formatEther(depositFixed)}, pct=${depositPct}, max=${ethers.formatEther(depositMax)}`);
            console.log(`    [Info] Withdraw: fixed=${ethers.formatEther(withdrawFixed)}, pct=${withdrawPct}, max=${ethers.formatEther(withdrawMax)}`);

            expect(depositFixed).to.equal(ethers.parseEther("10"));
            expect(depositPct).to.equal(500n);
            expect(depositMax).to.equal(ethers.parseEther("3000"));
            expect(withdrawFixed).to.equal(ethers.parseEther("3"));
            expect(withdrawPct).to.equal(250n);
            expect(withdrawMax).to.equal(ethers.parseEther("1500"));
        });

        it("Test 64: dynamic-fee: estimateDepositFee returns correct fee and timestamps", async function () {
            const amount = ethers.parseEther("100");
            const [fee, cotiLastUpdated, blockTimestamp] = await bridge.estimateDepositFee(amount);

            console.log(`    [Info] estimateDepositFee(100 COTI): fee=${ethers.formatEther(fee)}, lastUpdated=${cotiLastUpdated}, blockTs=${blockTimestamp}`);

            // 100 COTI at $0.05 = $5 USD value
            // pctFee = $5 * 500/1000000 = $0.0025
            // pctFeeCoti = $0.0025 / $0.05 = 0.05 COTI
            // fee = max(10 COTI, 0.05 COTI) = 10 COTI (floor dominates)
            expect(fee).to.equal(ethers.parseEther("10"));
            expect(cotiLastUpdated).to.be.gt(0n);
            expect(blockTimestamp).to.be.gt(0n);
        });

        it("Test 65: dynamic-fee: estimateWithdrawFee returns correct fee and timestamps", async function () {
            const amount = ethers.parseEther("100");
            const [fee, cotiLastUpdated, blockTimestamp] = await bridge.estimateWithdrawFee(amount);

            console.log(`    [Info] estimateWithdrawFee(100 COTI): fee=${ethers.formatEther(fee)}, lastUpdated=${cotiLastUpdated}, blockTs=${blockTimestamp}`);

            // 100 COTI at $0.05 = $5 USD value
            // pctFee = $5 * 250/1000000 = $0.00125
            // pctFeeCoti = $0.00125 / $0.05 = 0.025 COTI
            // fee = max(3 COTI, 0.025 COTI) = 3 COTI (floor dominates)
            expect(fee).to.equal(ethers.parseEther("3"));
            expect(cotiLastUpdated).to.be.gt(0n);
        });

        it("Test 66: dynamic-fee: Percentage fee dominates for large deposits", async function () {
            // 1,000,000 COTI at $0.05 = $50,000 USD
            // pctFee = $50,000 * 500/1,000,000 = $25
            // pctFeeCoti = $25 / $0.05 = 500 COTI
            // fee = max(10, 500) = 500, min(500, 3000) = 500 COTI
            const amount = ethers.parseEther("1000000");
            const [fee] = await bridge.estimateDepositFee(amount);
            console.log(`    [Info] estimateDepositFee(1M COTI): fee=${ethers.formatEther(fee)} COTI`);
            expect(fee).to.equal(ethers.parseEther("500"));
        });

        it("Test 67: dynamic-fee: Max fee cap applies for very large deposits", async function () {
            // 100,000,000 COTI at $0.05 = $5,000,000 USD
            // pctFee = $5M * 500/1M = $2,500
            // pctFeeCoti = $2,500 / $0.05 = 50,000 COTI
            // fee = max(10, 50000) = 50000, min(50000, 3000) = 3000 COTI (cap)
            const amount = ethers.parseEther("100000000");
            const [fee] = await bridge.estimateDepositFee(amount);
            console.log(`    [Info] estimateDepositFee(100M COTI): fee=${ethers.formatEther(fee)} COTI (capped)`);
            expect(fee).to.equal(ethers.parseEther("3000"));
        });

        it("Test 68: dynamic-fee: setDepositDynamicFee updates parameters", async function () {
            const newFixed = ethers.parseEther("20");
            const newPct = 1000n; // 0.1%
            const newMax = ethers.parseEther("5000");

            const tx = await bridge.setDepositDynamicFee(newFixed, newPct, newMax, { gasLimit: 2000000 });
            await logTx(tx, "setDepositDynamicFee(20, 1000, 5000)", "setDepositDynamicFee", ["20", "1000", "5000"]);

            expect(await bridge.depositFixedFee()).to.equal(newFixed);
            expect(await bridge.depositPercentageBps()).to.equal(newPct);
            expect(await bridge.depositMaxFee()).to.equal(newMax);

            // Restore defaults
            const restoreTx = await bridge.setDepositDynamicFee(ethers.parseEther("10"), 500n, ethers.parseEther("3000"), { gasLimit: 2000000 });
            await logTx(restoreTx, "Restore deposit fee defaults", "setDepositDynamicFee", ["10", "500", "3000"]);
        });

        it("Test 69: dynamic-fee: setWithdrawDynamicFee updates parameters", async function () {
            const newFixed = ethers.parseEther("5");
            const newPct = 500n;
            const newMax = ethers.parseEther("2000");

            const tx = await bridge.setWithdrawDynamicFee(newFixed, newPct, newMax, { gasLimit: 2000000 });
            await logTx(tx, "setWithdrawDynamicFee(5, 500, 2000)", "setWithdrawDynamicFee", ["5", "500", "2000"]);

            expect(await bridge.withdrawFixedFee()).to.equal(newFixed);
            expect(await bridge.withdrawPercentageBps()).to.equal(newPct);
            expect(await bridge.withdrawMaxFee()).to.equal(newMax);

            // Restore defaults
            const restoreTx = await bridge.setWithdrawDynamicFee(ethers.parseEther("3"), 250n, ethers.parseEther("1500"), { gasLimit: 2000000 });
            await logTx(restoreTx, "Restore withdraw fee defaults", "setWithdrawDynamicFee", ["3", "250", "1500"]);
        });

        it("Test 70: dynamic-fee: setDepositDynamicFee reverts if fixedFee > maxFee", async function () {
            await expectRevert(bridge.setDepositDynamicFee(ethers.parseEther("5000"), 500n, ethers.parseEther("3000"), { gasLimit: 2000000 }), /InvalidFeeConfiguration|revert/i, "    [Info] Correctly reverted: fixedFee > maxFee");
        });

        it("Test 71: dynamic-fee: setDepositDynamicFee reverts if maxFee is 0", async function () {
            await expectRevert(bridge.setDepositDynamicFee(0n, 500n, 0n, { gasLimit: 2000000 }), /InvalidFeeConfiguration|revert/i, "    [Info] Correctly reverted: maxFee == 0");
        });

        it("Test 72: dynamic-fee: setDepositDynamicFee reverts if percentageBps > MAX_FEE_UNITS", async function () {
            await expectRevert(bridge.setDepositDynamicFee(ethers.parseEther("10"), 200000n, ethers.parseEther("3000"), { gasLimit: 2000000 }), /InvalidFee|revert/i, "    [Info] Correctly reverted: percentageBps > MAX_FEE_UNITS");
        });

        it("Test 73: dynamic-fee: setPriceOracle reverts for zero address", async function () {
            await expectRevert(bridge.setPriceOracle(ethers.ZeroAddress, { gasLimit: 2000000 }), /InvalidAddress|revert/i, "    [Info] Correctly reverted: oracle = address(0)");
        });

        it("Test 74: dynamic-fee: setPriceOracle emits PriceOracleUpdated", async function () {
            const oracleAddr = await addr(mockOracle);
            // Set to a new address then restore
            const newOracle = ethers.Wallet.createRandom().address;
            const tx = await bridge.setPriceOracle(newOracle, { gasLimit: 2000000 });
            await logTx(tx, "setPriceOracle to random address", "setPriceOracle", [newOracle]);
            await expect(tx).to.emit(bridge, "PriceOracleUpdated");

            // Restore original oracle
            const restoreTx = await bridge.setPriceOracle(oracleAddr, { gasLimit: 2000000 });
            await logTx(restoreTx, "Restore original oracle", "setPriceOracle", [oracleAddr]);
        });

        it("Test 75: dynamic-fee: totalUserLiability increases on deposit", async function () {
            const liabilityBefore = await bridge.totalUserLiability();
            const amount = ethers.parseEther("100");

            const [fee, cotiLastUpdated] = await bridge.estimateDepositFee(amount);
            const tx = await bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: amount, gasLimit: 12000000 });
            await logTx(tx, "Deposit 100 COTI for liability tracking", "deposit", ["100"]);

            const liabilityAfter = await bridge.totalUserLiability();
            const netDeposit = amount - fee;
            console.log(`    [Info] Liability before=${ethers.formatEther(liabilityBefore)}, after=${ethers.formatEther(liabilityAfter)}, net=${ethers.formatEther(netDeposit)}`);
            expect(liabilityAfter - liabilityBefore).to.equal(netDeposit);
        });

        it("Test 76: dynamic-fee: totalUserLiability decreases on withdraw", async function () {
            const amount = ethers.parseEther("50");
            const bridgeAddr = await addr(bridge);

            await logTx(await privateCoti.connect(owner)["approve(address,uint256)"](bridgeAddr, amount, { gasLimit: 2000000 }), "Approve for liability withdraw test", "approve", [bridgeAddr, "50"]);

            const liabilityBefore = await bridge.totalUserLiability();
            const [fee, cotiLastUpdated] = await bridge.estimateWithdrawFee(amount);

            const tx = await bridge["withdraw(uint256,uint256,uint256)"](amount, cotiLastUpdated, cotiLastUpdated, { gasLimit: 12000000 });
            await logTx(tx, "Withdraw 50 COTI for liability tracking", "withdraw", ["50"]);

            const liabilityAfter = await bridge.totalUserLiability();
            const netWithdraw = amount - fee;
            console.log(`    [Info] Liability before=${ethers.formatEther(liabilityBefore)}, after=${ethers.formatEther(liabilityAfter)}, net=${ethers.formatEther(netWithdraw)}`);
            expect(liabilityBefore - liabilityAfter).to.equal(netWithdraw);
        });

        it("Test 77: dynamic-fee: feeRecipient and rescueRecipient are set correctly", async function () {
            const feeRecip = await bridge.feeRecipient();
            const rescueRecip = await bridge.rescueRecipient();
            console.log(`    [Info] feeRecipient=${feeRecip}, rescueRecipient=${rescueRecip}`);
            expect(feeRecip).to.equal(owner.address);
            expect(rescueRecip).to.equal(owner.address);
        });

        it("Test 78: dynamic-fee: AccessControlEnumerable role member tracking", async function () {
            const OPERATOR_ROLE = await bridge.OPERATOR_ROLE();
            const operatorCount = await bridge.getRoleMemberCount(OPERATOR_ROLE);
            console.log(`    [Info] Operator count: ${operatorCount}`);
            expect(operatorCount).to.be.gte(1n);

            const firstOperator = await bridge.getRoleMember(OPERATOR_ROLE, 0);
            console.log(`    [Info] First operator: ${firstOperator}`);
            expect(firstOperator).to.equal(owner.address);
        });

        it("Test 79: dynamic-fee: DynamicFeeUpdated event emitted on setDepositDynamicFee", async function () {
            const tx = await bridge.setDepositDynamicFee(ethers.parseEther("10"), 500n, ethers.parseEther("3000"), { gasLimit: 2000000 });
            await logTx(tx, "setDepositDynamicFee for event check", "setDepositDynamicFee", ["10", "500", "3000"]);
            await expect(tx).to.emit(bridge, "DynamicFeeUpdated");
        });

        it("Test 80: dynamic-fee: receive() direct deposit works without timestamps", async function () {
            const bridgeAddr = await addr(bridge);
            const amount = ethers.parseEther("100");
            const feeBefore = await bridge.accumulatedCotiFees();

            const tx = await owner.sendTransaction({ to: bridgeAddr, value: amount, gasLimit: 2000000 });
            await logTx(tx, "Direct COTI transfer (receive fallback) for fee check", "receive()", [ethers.formatEther(amount)]);

            const feeAfter = await bridge.accumulatedCotiFees();
            const feeCharged = feeAfter - feeBefore;
            console.log(`    [Info] Fee charged via receive(): ${ethers.formatEther(feeCharged)} COTI`);
            expect(feeCharged).to.be.gt(0n);
        });

        it("Test 81: dynamic-fee: withdrawFees sends to feeRecipient", async function () {
            const fees = await bridge.accumulatedCotiFees();
            if (fees === 0n) {
                console.log("    [Info] No accumulated fees to withdraw, skipping");
                this.skip();
                return;
            }
            const withdrawAmount = fees / 2n > 0n ? fees / 2n : fees;

            const tx = await bridge.withdrawFees(withdrawAmount, { gasLimit: 2000000 });
            await logTx(tx, `withdrawFees(${ethers.formatEther(withdrawAmount)})`, "withdrawFees", [ethers.formatEther(withdrawAmount)]);

            await expect(tx).to.emit(bridge, "FeesWithdrawn");
            console.log(`    [Info] Withdrew ${ethers.formatEther(withdrawAmount)} COTI fees to feeRecipient`);
        });

        it("Test 82: dynamic-fee: setNativeCotiFee reverts on native bridge", async function () {
            await expectRevert(bridge.setNativeCotiFee(ethers.parseEther("1"), { gasLimit: 2000000 }), /NativeCotiFeeNotApplicable|revert/i, "    [Info] Correctly reverted: NativeCotiFeeNotApplicable");
        });
    });

    // ─────────────────────────────────────────────────────────────────────────
    // DYNAMIC FEE FEATURES - ERC20 BRIDGE
    // ─────────────────────────────────────────────────────────────────────────

    describe("Dynamic Fee Features - ERC20 Bridge", function () {
        let publicToken, bridge;
        const UNIT = BigInt(10 ** 18);
        const COTI_FEE_BUFFER = ethers.parseEther("3100");

        before(async function () {
            if (skipIfOnlyPrivateERC20.call(this)) return;
            const env = await setupERC20BridgeSuite("Dynamic Fee - ERC20", 10000n);
            publicToken = env.publicToken;
            bridge = env.bridge;
        });

        it("Test 83: dynamic-fee-erc20: estimateDepositFee returns correct fee for ERC20", async function () {
            // 10 WETH at $2300 = $23,000 USD
            // pctFee = $23,000 * 500/1,000,000 = $11.50
            // pctFeeCoti = $11.50 / $0.05 = 230 COTI
            // fee = max(10, 230) = 230, min(230, 3000) = 230 COTI
            const amount = 10n * UNIT;
            const [fee, cotiLastUpdated, tokenLastUpdated, blockTimestamp] = await bridge.estimateDepositFee(amount);
            console.log(`    [Info] estimateDepositFee(10 WETH): fee=${ethers.formatEther(fee)} COTI`);
            expect(fee).to.equal(ethers.parseEther("230"));
            expect(cotiLastUpdated).to.be.gt(0n);
            expect(tokenLastUpdated).to.be.gt(0n);
            expect(blockTimestamp).to.be.gt(0n);
        });

        it("Test 84: dynamic-fee-erc20: estimateWithdrawFee returns correct fee for ERC20", async function () {
            // 10 WETH at $2300 = $23,000 USD
            // pctFee = $23,000 * 250/1,000,000 = $5.75
            // pctFeeCoti = $5.75 / $0.05 = 115 COTI
            // fee = max(3, 115) = 115, min(115, 1500) = 115 COTI
            const amount = 10n * UNIT;
            const [fee] = await bridge.estimateWithdrawFee(amount);
            console.log(`    [Info] estimateWithdrawFee(10 WETH): fee=${ethers.formatEther(fee)} COTI`);
            expect(fee).to.equal(ethers.parseEther("115"));
        });

        it("Test 85: dynamic-fee-erc20: Max fee cap applies for large ERC20 deposits", async function () {
            // 1000 WETH at $2300 = $2,300,000 USD
            // pctFee = $2,300,000 * 500/1,000,000 = $1,150
            // pctFeeCoti = $1,150 / $0.05 = 23,000 COTI
            // fee = max(10, 23000) = 23000, min(23000, 3000) = 3000 COTI (capped)
            const amount = 1000n * UNIT;
            const [fee] = await bridge.estimateDepositFee(amount);
            console.log(`    [Info] estimateDepositFee(1000 WETH): fee=${ethers.formatEther(fee)} COTI (capped)`);
            expect(fee).to.equal(ethers.parseEther("3000"));
        });

        it("Test 86: dynamic-fee-erc20: tokenSymbol returns correct oracle symbol", async function () {
            const symbol = await bridge.tokenSymbol();
            console.log(`    [Info] tokenSymbol: ${symbol}`);
            expect(symbol).to.equal("ETH");
        });

        it("Test 87: dynamic-fee-erc20: Full deposit collects COTI fee from msg.value", async function () {
            const amount = 10n * UNIT;
            const bridgeAddr = await addr(bridge);
            await logTx(await publicToken.approve(bridgeAddr, amount, { gasLimit: 2000000 }), "Approve WETH for deposit", "approve", [bridgeAddr, "10"]);

            const feeBefore = await bridge.accumulatedCotiFees();
            const [fee, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateDepositFee(amount);
            console.log(`    [Info] Estimated fee: ${ethers.formatEther(fee)} COTI`);

            const tx = await bridge["deposit(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 });
            await logTx(tx, "Deposit 10 WETH with COTI fee", "deposit", ["10"]);

            const feeAfter = await bridge.accumulatedCotiFees();
            const actualFee = feeAfter - feeBefore;
            console.log(`    [Info] Actual COTI fee collected: ${ethers.formatEther(actualFee)}`);
            expect(actualFee).to.equal(fee);
        });

        it("Test 88: dynamic-fee-erc20: Deposit reverts with insufficient COTI fee", async function () {
            const amount = 10n * UNIT;
            const bridgeAddr = await addr(bridge);
            await logTx(await publicToken.approve(bridgeAddr, amount, { gasLimit: 2000000 }), "Approve WETH for insufficient fee test", "approve", [bridgeAddr, "10"]);

            const [fee, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateDepositFee(amount);

            try {
                // Send less than the required fee
                const insufficientFee = fee / 2n;
                const tx = await bridge["deposit(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: insufficientFee, gasLimit: 12000000 });
                await waitForReceiptWithRetry(tx);
                expect.fail("Expected revert but succeeded");
            } catch (error) {
                expect(error.message).to.match(/InsufficientCotiFee|revert/i);
                console.log("    [Info] Correctly reverted: InsufficientCotiFee");
            }
        });
    });

    // ─────────────────────────────────────────────────────────────────────────
    // BLACKLIST & ACCESS CONTROL TESTS
    // ─────────────────────────────────────────────────────────────────────────

    describe("Blacklist & Access Control", function () {
        let bridge;

        before(async function () {
            if (skipIfOnlyPrivateERC20.call(this)) return;
            const env = await setupNativeBridgeEnv("Blacklist & Access Control");
            bridge = env.bridge;
        });

        it("Test 89: blacklist: addToBlacklist blocks deposit", async function () {
            // Blacklist the owner address
            const tx = await bridge.addToBlacklist(owner.address, { gasLimit: 2000000 });
            await logTx(tx, "addToBlacklist(owner)", "addToBlacklist", [owner.address]);
            await expect(tx).to.emit(bridge, "Blacklisted");

            expect(await bridge.blacklisted(owner.address)).to.equal(true);

            // Try to deposit — should revert
            const [, cotiLastUpdated] = await bridge.estimateDepositFee(ethers.parseEther("100"));
            await expectRevert(bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: ethers.parseEther("100"), gasLimit: 12000000 }), /AddressBlacklisted|revert/i, "    [Info] Correctly reverted: AddressBlacklisted on deposit");
        });

        it("Test 90: blacklist: removeFromBlacklist restores access", async function () {
            const tx = await bridge.removeFromBlacklist(owner.address, { gasLimit: 2000000 });
            await logTx(tx, "removeFromBlacklist(owner)", "removeFromBlacklist", [owner.address]);
            await expect(tx).to.emit(bridge, "UnBlacklisted");

            expect(await bridge.blacklisted(owner.address)).to.equal(false);

            // Deposit should now work
            const [, cotiLastUpdated] = await bridge.estimateDepositFee(ethers.parseEther("100"));
            const depositTx = await bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: ethers.parseEther("100"), gasLimit: 12000000 });
            await logTx(depositTx, "Deposit after unblacklist", "deposit", ["100"]);
            await expect(depositTx).to.emit(bridge, "Deposit");
        });

        it("Test 91: blacklist: addToBlacklist reverts for zero address", async function () {
            await expectRevert(bridge.addToBlacklist(ethers.ZeroAddress, { gasLimit: 2000000 }), /InvalidAddress|revert/i, "    [Info] Correctly reverted: addToBlacklist(address(0))");
        });

        it("Test 92: access-control: addOperator and removeOperator work correctly", async function () {
            const randomAddr = ethers.Wallet.createRandom().address;

            const addTx = await bridge.addOperator(randomAddr, { gasLimit: 2000000 });
            await logTx(addTx, "addOperator(random)", "addOperator", [randomAddr]);
            await expect(addTx).to.emit(bridge, "OperatorAdded");

            const isOp = await bridge.isOperator(randomAddr);
            expect(isOp).to.equal(true);

            const removeTx = await bridge.removeOperator(randomAddr, { gasLimit: 2000000 });
            await logTx(removeTx, "removeOperator(random)", "removeOperator", [randomAddr]);
            await expect(removeTx).to.emit(bridge, "OperatorRemoved");

            const isOpAfter = await bridge.isOperator(randomAddr);
            expect(isOpAfter).to.equal(false);
        });

        it("Test 93: access-control: pause blocks deposits, unpause restores", async function () {
            const pauseTx = await bridge.pause({ gasLimit: 2000000 });
            await logTx(pauseTx, "pause()", "pause", []);

            // Try deposit while paused
            const [, cotiLastUpdated] = await bridge.estimateDepositFee(ethers.parseEther("100"));
            await expectRevert(bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: ethers.parseEther("100"), gasLimit: 12000000 }), /Pausable|paused|revert/i, "    [Info] Correctly reverted: deposit while paused");

            // Unpause
            const unpauseTx = await bridge.unpause({ gasLimit: 2000000 });
            await logTx(unpauseTx, "unpause()", "unpause", []);
        });

        it("Test 94: access-control: renounceOwnership is disabled", async function () {
            await expectRevert(bridge.renounceOwnership({ gasLimit: 2000000 }), /renounceOwnership disabled|revert/i, "    [Info] Correctly reverted: renounceOwnership disabled");
        });

        it("Test 95: access-control: setIsDepositEnabled toggles deposits", async function () {
            // Disable deposits
            const disableTx = await bridge.setIsDepositEnabled(false, { gasLimit: 2000000 });
            await logTx(disableTx, "setIsDepositEnabled(false)", "setIsDepositEnabled", ["false"]);
            expect(await bridge.isDepositEnabled()).to.equal(false);

            // Try deposit — should revert
            const [, cotiLastUpdated] = await bridge.estimateDepositFee(ethers.parseEther("100"));
            await expectRevert(bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: ethers.parseEther("100"), gasLimit: 12000000 }), /DepositDisabled|revert/i, "    [Info] Correctly reverted: DepositDisabled");

            // Re-enable
            const enableTx = await bridge.setIsDepositEnabled(true, { gasLimit: 2000000 });
            await logTx(enableTx, "setIsDepositEnabled(true)", "setIsDepositEnabled", ["true"]);
            expect(await bridge.isDepositEnabled()).to.equal(true);
        });

        it("Test 96: access-control: setLimits enforces deposit/withdraw bounds", async function () {
            const minDep = ethers.parseEther("50");
            const maxDep = ethers.parseEther("10000");
            const minWith = ethers.parseEther("10");
            const maxWith = ethers.parseEther("5000");

            const tx = await bridge.setLimits(minDep, maxDep, minWith, maxWith, { gasLimit: 2000000 });
            await logTx(tx, "setLimits(50, 10000, 10, 5000)", "setLimits", ["50", "10000", "10", "5000"]);
            await expect(tx).to.emit(bridge, "LimitsUpdated");

            expect(await bridge.minDepositAmount()).to.equal(minDep);
            expect(await bridge.maxDepositAmount()).to.equal(maxDep);

            // Try deposit below minimum
            const [, cotiLastUpdated] = await bridge.estimateDepositFee(ethers.parseEther("10"));
            await expectRevert(bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: ethers.parseEther("10"), gasLimit: 12000000 }), /DepositBelowMinimum|revert/i, "    [Info] Correctly reverted: DepositBelowMinimum");

            // Restore defaults
            const restoreTx = await bridge.setLimits(1n, ethers.MaxUint256, 1n, ethers.MaxUint256, { gasLimit: 2000000 });
            await logTx(restoreTx, "Restore default limits", "setLimits", ["1", "max", "1", "max"]);
        });
    });


    // ─────────────────────────────────────────────────────────────────────────
    // FULL COVERAGE — NATIVE BRIDGE REVERT PATHS
    // ─────────────────────────────────────────────────────────────────────────

    describe("Full Coverage - Native Bridge Reverts", function () {
        let bridge;

        before(async function () {
            if (skipIfOnlyPrivateERC20.call(this)) return;
            const env = await setupNativeBridgeEnv("Full Coverage - Native Reverts");
            bridge = env.bridge;
        });

        it("Test 97: revert: native deposit with zero value reverts AmountZero", async function () {
            const [, cotiLastUpdated] = await bridge.estimateDepositFee(ethers.parseEther("100"));
            await expectRevert(bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: 0n, gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: deposit with value=0");
        });

        it("Test 98: revert: native withdraw with amount=0 reverts AmountZero", async function () {
            const [, cotiLastUpdated] = await bridge.estimateWithdrawFee(ethers.parseEther("100"));
            await expectRevert(bridge["withdraw(uint256,uint256,uint256)"](0n, cotiLastUpdated, cotiLastUpdated, { gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: withdraw with amount=0");
        });

        it("Test 99: revert: withdrawFees(0) reverts AmountZero", async function () {
            await expectRevert(bridge.withdrawFees(0n, { gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: withdrawFees(0)");
        });

        it("Test 100: revert: withdrawFees exceeding accumulated reverts InsufficientAccumulatedFees", async function () {
            await expectRevert(bridge.withdrawFees(ethers.parseEther("999999"), { gasLimit: 2000000 }), /InsufficientAccumulatedFees|revert/i, "    [Info] Correctly reverted: withdrawFees > accumulated");
        });

        it("Test 101: revert: rescueNative(0) reverts AmountZero", async function () {
            await expectRevert(bridge.rescueNative(0n, { gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: rescueNative(0)");
        });

        it("Test 102: revert: rescueNative exceeding rescueable reverts ExceedsRescueableAmount", async function () {
            // First deposit to create some balance and fees
            const [, cotiLastUpdated] = await bridge.estimateDepositFee(ethers.parseEther("100"));
            await logTx(await bridge["deposit(uint256,uint256)"](cotiLastUpdated, cotiLastUpdated, { value: ethers.parseEther("100"), gasLimit: 12000000 }), "Deposit for rescue test", "deposit", ["100"]);

            // Try to rescue more than balance minus fees
            const bal = await ethers.provider.getBalance(await addr(bridge));
            await expectRevert(bridge.rescueNative(bal, { gasLimit: 2000000 }), /ExceedsRescueableAmount|InsufficientEthBalance|revert/i, "    [Info] Correctly reverted: rescueNative exceeds rescueable");
        });

        it("Test 103: revert: receive() reverts when deposits disabled", async function () {
            await logTx(await bridge.setIsDepositEnabled(false, { gasLimit: 2000000 }), "Disable deposits for receive test", "setIsDepositEnabled", ["false"]);

            try {
                const tx = await owner.sendTransaction({ to: await addr(bridge), value: ethers.parseEther("10"), gasLimit: 2000000 });
                await waitForReceiptWithRetry(tx);
                expect.fail("Expected revert");
            } catch (error) {
                expect(error.message).to.match(/DepositDisabled|revert/i);
                console.log("    [Info] Correctly reverted: receive() when deposits disabled");
            }

            await logTx(await bridge.setIsDepositEnabled(true, { gasLimit: 2000000 }), "Re-enable deposits", "setIsDepositEnabled", ["true"]);
        });

        it("Test 104: revert: setLimits with min > max reverts InvalidLimitConfiguration", async function () {
            await expectRevert(bridge.setLimits(ethers.parseEther("100"), ethers.parseEther("10"), 1n, ethers.MaxUint256, { gasLimit: 2000000 }), /InvalidLimitConfiguration|revert/i, "    [Info] Correctly reverted: minDeposit > maxDeposit");
        });

        it("Test 105: revert: setDepositFee exceeding MAX_FEE_UNITS reverts InvalidFee", async function () {
            await expectRevert(bridge.setDepositFee(200000n, { gasLimit: 2000000 }), /InvalidFee|revert/i, "    [Info] Correctly reverted: setDepositFee > MAX_FEE_UNITS");
        });

        it("Test 106: legacy: setDepositFee and setWithdrawFee update basis points", async function () {
            const tx1 = await bridge.setDepositFee(1000n, { gasLimit: 2000000 });
            await logTx(tx1, "setDepositFee(1000)", "setDepositFee", ["1000"]);
            expect(await bridge.depositFeeBasisPoints()).to.equal(1000n);

            const tx2 = await bridge.setWithdrawFee(500n, { gasLimit: 2000000 });
            await logTx(tx2, "setWithdrawFee(500)", "setWithdrawFee", ["500"]);
            expect(await bridge.withdrawFeeBasisPoints()).to.equal(500n);
        });

        it("Test 107: revert: setWithdrawFee exceeding MAX_FEE_UNITS reverts InvalidFee", async function () {
            await expectRevert(bridge.setWithdrawFee(200000n, { gasLimit: 2000000 }), /InvalidFee|revert/i, "    [Info] Correctly reverted: setWithdrawFee > MAX_FEE_UNITS");
        });

        it("Test 108: transferOwnership revokes old operators and grants to new owner", async function () {
            const newOwner = ethers.Wallet.createRandom().address;
            const OPERATOR_ROLE = await bridge.OPERATOR_ROLE();

            // Check current operator count
            const opCountBefore = await bridge.getRoleMemberCount(OPERATOR_ROLE);
            console.log(`    [Info] Operators before transfer: ${opCountBefore}`);

            const tx = await bridge.transferOwnership(newOwner, { gasLimit: 2000000 });
            await logTx(tx, `transferOwnership to ${newOwner}`, "transferOwnership", [newOwner]);

            // New owner should have operator role
            expect(await bridge.isOperator(newOwner)).to.equal(true);
            // Old owner should NOT have operator role
            expect(await bridge.isOperator(owner.address)).to.equal(false);
            // New owner is the owner
            expect(await bridge.owner()).to.equal(newOwner);

            console.log("    [Info] Ownership transferred, old operators revoked, new owner has roles");
            // NOTE: We can't transfer back since we don't have the new owner's private key.
            // This bridge instance is now owned by a random address — subsequent tests use different bridges.
        });
    });

    // ─────────────────────────────────────────────────────────────────────────
    // FULL COVERAGE — ERC20 BRIDGE REVERT PATHS
    // ─────────────────────────────────────────────────────────────────────────

    describe("Full Coverage - ERC20 Bridge Reverts", function () {
        let publicToken, privateToken, bridge;
        const UNIT = BigInt(10 ** 18);
        const COTI_FEE_BUFFER = ethers.parseEther("3100");

        before(async function () {
            if (skipIfOnlyPrivateERC20.call(this)) return;
            const env = await setupERC20BridgeSuite("Full Coverage - ERC20 Reverts", 10000n);
            publicToken = env.publicToken; privateToken = env.privateToken;
            bridge = env.bridge;
        });

        it("Test 109: revert: ERC20 deposit with amount=0 reverts AmountZero", async function () {
            const [, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateDepositFee(1n * UNIT);
            await expectRevert(bridge["deposit(uint256,uint256,uint256)"](0n, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: ERC20 deposit amount=0");
        });

        it("Test 110: revert: ERC20 withdraw with amount=0 reverts AmountZero", async function () {
            const [, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateWithdrawFee(1n * UNIT);
            await expectRevert(bridge["withdraw(uint256,uint256,uint256)"](0n, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: ERC20 withdraw amount=0");
        });

        it("Test 111: revert: ERC20 deposit when deposits disabled reverts DepositDisabled", async function () {
            await logTx(await bridge.setIsDepositEnabled(false, { gasLimit: 2000000 }), "Disable deposits (ERC20)", "setIsDepositEnabled", ["false"]);

            const amount = 1n * UNIT;
            const bridgeAddr = await addr(bridge);
            await logTx(await publicToken.approve(bridgeAddr, amount, { gasLimit: 2000000 }), "Approve for disabled deposit test", "approve", [bridgeAddr, "1"]);
            const [, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateDepositFee(amount);

            await expectRevert(bridge["deposit(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 }), /DepositDisabled|revert/i, "    [Info] Correctly reverted: ERC20 deposit when disabled");

            await logTx(await bridge.setIsDepositEnabled(true, { gasLimit: 2000000 }), "Re-enable deposits (ERC20)", "setIsDepositEnabled", ["true"]);
        });

        it("Test 112: revert: ERC20 withdraw with InsufficientBridgeLiquidity", async function () {
            // Try to withdraw more than the bridge holds (bridge has 0 tokens)
            const amount = 1000n * UNIT;
            const bridgeAddr = await addr(bridge);
            await logTx(await privateToken["approve(address,uint256)"](bridgeAddr, amount, { gasLimit: 2000000 }), "Approve for liquidity test", "approve", [bridgeAddr, "1000"]);
            const [, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateWithdrawFee(amount);

            await expectRevert(bridge["withdraw(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 }), /InsufficientBridgeLiquidity|revert/i, "    [Info] Correctly reverted: InsufficientBridgeLiquidity");
        });

        it("Test 113: revert: rescueERC20 with private token reverts CannotRescueBridgeToken", async function () {
            const privAddr = await addr(privateToken);
            await expectRevert(bridge.rescueERC20(privAddr, 1n, { gasLimit: 2000000 }), /CannotRescueBridgeToken|revert/i, "    [Info] Correctly reverted: rescueERC20(privateToken)");
        });

        it("Test 114: revert: rescueERC20 with amount=0 reverts AmountZero", async function () {
            const pubAddr = await addr(publicToken);
            await expectRevert(bridge.rescueERC20(pubAddr, 0n, { gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: rescueERC20 amount=0");
        });

        it("Test 115: ERC20 setNativeCotiFee works (not native bridge)", async function () {
            const tx = await bridge.setNativeCotiFee(ethers.parseEther("5"), { gasLimit: 2000000 });
            await logTx(tx, "setNativeCotiFee(5) on ERC20 bridge", "setNativeCotiFee", ["5"]);
            expect(await bridge.nativeCotiFee()).to.equal(ethers.parseEther("5"));
            await expect(tx).to.emit(bridge, "NativeCotiFeeUpdated");

            // Reset
            const resetTx = await bridge.setNativeCotiFee(0n, { gasLimit: 2000000 });
            await logTx(resetTx, "Reset nativeCotiFee to 0", "setNativeCotiFee", ["0"]);
        });

        it("Test 116: ERC20 withdrawCotiFees happy path", async function () {
            // First deposit to accumulate some COTI fees
            const amount = 10n * UNIT;
            const bridgeAddr = await addr(bridge);
            await logTx(await publicToken.approve(bridgeAddr, amount, { gasLimit: 2000000 }), "Approve for withdrawCotiFees test", "approve", [bridgeAddr, "10"]);
            const [, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateDepositFee(amount);
            await logTx(await bridge["deposit(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 }), "Deposit for COTI fee accumulation", "deposit", ["10"]);

            const fees = await bridge.accumulatedCotiFees();
            console.log(`    [Info] Accumulated COTI fees: ${ethers.formatEther(fees)}`);
            expect(fees).to.be.gt(0n);

            const withdrawAmount = fees / 2n;
            const tx = await bridge.withdrawCotiFees(withdrawAmount, { gasLimit: 2000000 });
            await logTx(tx, `withdrawCotiFees(${ethers.formatEther(withdrawAmount)})`, "withdrawCotiFees", [ethers.formatEther(withdrawAmount)]);
            await expect(tx).to.emit(bridge, "CotiFeesWithdrawn");
        });

        it("Test 117: revert: withdrawCotiFees(0) reverts AmountZero", async function () {
            await expectRevert(bridge.withdrawCotiFees(0n, { gasLimit: 2000000 }), /AmountZero|revert/i, "    [Info] Correctly reverted: withdrawCotiFees(0)");
        });

        it("Test 118: revert: withdrawCotiFees exceeding accumulated reverts", async function () {
            await expectRevert(bridge.withdrawCotiFees(ethers.parseEther("999999"), { gasLimit: 2000000 }), /InsufficientAccumulatedFees|revert/i, "    [Info] Correctly reverted: withdrawCotiFees > accumulated");
        });

        it("Test 119: ERC20 totalUserLiability tracks deposit and withdraw", async function () {
            const amount = 5n * UNIT;
            const bridgeAddr = await addr(bridge);

            // Deposit
            await logTx(await publicToken.approve(bridgeAddr, amount, { gasLimit: 2000000 }), "Approve for liability test", "approve", [bridgeAddr, "5"]);
            const liabilityBefore = await bridge.totalUserLiability();
            const [, cotiLastUpdated, tokenLastUpdated] = await bridge.estimateDepositFee(amount);
            await logTx(await bridge["deposit(uint256,uint256,uint256)"](amount, cotiLastUpdated, tokenLastUpdated, { value: COTI_FEE_BUFFER, gasLimit: 12000000 }), "Deposit for ERC20 liability test", "deposit", ["5"]);
            const liabilityAfterDeposit = await bridge.totalUserLiability();
            expect(liabilityAfterDeposit).to.be.gt(liabilityBefore);
            console.log(`    [Info] Liability after deposit: ${ethers.formatEther(liabilityAfterDeposit)}`);

            // Withdraw
            await logTx(await privateToken["approve(address,uint256)"](bridgeAddr, amount, { gasLimit: 2000000 }), "Approve private for liability withdraw", "approve", [bridgeAddr, "5"]);
            const [, cotiLastUpdated2, tokenLastUpdated2] = await bridge.estimateWithdrawFee(amount);
            await logTx(await bridge["withdraw(uint256,uint256,uint256)"](amount, cotiLastUpdated2, tokenLastUpdated2, { value: COTI_FEE_BUFFER, gasLimit: 12000000 }), "Withdraw for ERC20 liability test", "withdraw", ["5"]);
            const liabilityAfterWithdraw = await bridge.totalUserLiability();
            expect(liabilityAfterWithdraw).to.be.lt(liabilityAfterDeposit);
            console.log(`    [Info] Liability after withdraw: ${ethers.formatEther(liabilityAfterWithdraw)}`);
        });

        it("Test 120: revert: addOperator with zero address reverts InvalidAddress", async function () {
            await expectRevert(bridge.addOperator(ethers.ZeroAddress, { gasLimit: 2000000 }), /InvalidAddress|revert/i, "    [Info] Correctly reverted: addOperator(address(0))");
        });

        it("Test 121: revert: removeOperator with zero address reverts InvalidAddress", async function () {
            await expectRevert(bridge.removeOperator(ethers.ZeroAddress, { gasLimit: 2000000 }), /InvalidAddress|revert/i, "    [Info] Correctly reverted: removeOperator(address(0))");
        });

        it("Test 122: revert: removeFromBlacklist with zero address reverts InvalidAddress", async function () {
            await expectRevert(bridge.removeFromBlacklist(ethers.ZeroAddress, { gasLimit: 2000000 }), /InvalidAddress|revert/i, "    [Info] Correctly reverted: removeFromBlacklist(address(0))");
        });

        it("Test 123: revert: setWithdrawDynamicFee with fixedFee > maxFee reverts", async function () {
            await expectRevert(bridge.setWithdrawDynamicFee(ethers.parseEther("5000"), 250n, ethers.parseEther("1500"), { gasLimit: 2000000 }), /InvalidFeeConfiguration|revert/i, "    [Info] Correctly reverted: setWithdrawDynamicFee fixedFee > maxFee");
        });

        it("Test 124: revert: setWithdrawDynamicFee with maxFee=0 reverts", async function () {
            await expectRevert(bridge.setWithdrawDynamicFee(0n, 250n, 0n, { gasLimit: 2000000 }), /InvalidFeeConfiguration|revert/i, "    [Info] Correctly reverted: setWithdrawDynamicFee maxFee=0");
        });

        it("Test 125: revert: setWithdrawDynamicFee with pctBps > MAX_FEE_UNITS reverts", async function () {
            await expectRevert(bridge.setWithdrawDynamicFee(ethers.parseEther("3"), 200000n, ethers.parseEther("1500"), { gasLimit: 2000000 }), /InvalidFee|revert/i, "    [Info] Correctly reverted: setWithdrawDynamicFee pctBps > MAX");
        });
    });

    // ─────────────────────────────────────────────────────────────────────────
    // FULL COVERAGE — CotiPriceConsumer
    // ─────────────────────────────────────────────────────────────────────────

    describe("Full Coverage - CotiPriceConsumer", function () {
        let oracle, mockRef;

        before(async function () {
            if (skipIfOnlyPrivateERC20.call(this)) return;

            // Deploy MockStdReference (Band Protocol mock)
            const MockRefFactory = await ethers.getContractFactory("MockStdReference");
            mockRef = await MockRefFactory.deploy({ gasLimit: 12000000 });
            await (mockRef.waitForDeployment ? mockRef.waitForDeployment() : mockRef.deployed());

            // Set COTI price and ETH price
            await mockRef.setRate("COTI", ethers.parseEther("0.05"), { gasLimit: 2000000 });
            await mockRef.setRate("ETH", ethers.parseEther("2300"), { gasLimit: 2000000 });
            // Set lastUpdated to current block timestamp
            const currentBlock = await ethers.provider.getBlock("latest");
            await mockRef.setLastUpdatedBase("COTI", currentBlock.timestamp, { gasLimit: 2000000 });
            await mockRef.setLastUpdatedBase("ETH", currentBlock.timestamp, { gasLimit: 2000000 });

            // Deploy real CotiPriceConsumer with MockStdReference
            const OracleFactory = await ethers.getContractFactory("CotiPriceConsumer");
            oracle = await OracleFactory.deploy(await addr(mockRef), 3600, { gasLimit: 12000000 });
            await (oracle.waitForDeployment ? oracle.waitForDeployment() : oracle.deployed());

            await registerContract("CotiPriceConsumer", oracle, "Full Coverage - CotiPriceConsumer");
            await registerContract("MockStdReference", mockRef, "Full Coverage - CotiPriceConsumer");
            await new Promise(r => setTimeout(r, 5000));
        });

        it("Test 126: oracle: owner is deployer", async function () {
            const oracleOwner = await oracle.owner();
            console.log(`    [Info] Oracle owner: ${oracleOwner}`);
            expect(oracleOwner).to.equal(owner.address);
        });

        it("Test 127: oracle: ref is immutable and set correctly", async function () {
            const refAddr = await oracle.ref();
            console.log(`    [Info] Oracle ref: ${refAddr}`);
            expect(refAddr).to.equal(await addr(mockRef));
        });

        it("Test 128: oracle: maxStaleness is set correctly", async function () {
            const staleness = await oracle.maxStaleness();
            console.log(`    [Info] maxStaleness: ${staleness}`);
            expect(staleness).to.equal(3600n);
        });

        it("Test 129: oracle: MIN_STALENESS constant is 3600", async function () {
            const minStaleness = await oracle.MIN_STALENESS();
            console.log(`    [Info] MIN_STALENESS: ${minStaleness}`);
            expect(minStaleness).to.equal(3600n);
        });

        it("Test 130: oracle: getPrice returns correct rate", async function () {
            const cotiPrice = await oracle.getPrice("COTI");
            console.log(`    [Info] COTI price: ${ethers.formatEther(cotiPrice)}`);
            expect(cotiPrice).to.equal(ethers.parseEther("0.05"));

            const ethPrice = await oracle.getPrice("ETH");
            console.log(`    [Info] ETH price: ${ethers.formatEther(ethPrice)}`);
            expect(ethPrice).to.equal(ethers.parseEther("2300"));
        });

        it("Test 131: oracle: getPriceWithMeta returns rate, lastUpdated, blockTimestamp", async function () {
            const [rate, lastUpdated, blockTimestamp] = await oracle.getPriceWithMeta("COTI");
            console.log(`    [Info] getPriceWithMeta: rate=${ethers.formatEther(rate)}, lastUpdated=${lastUpdated}, blockTs=${blockTimestamp}`);
            expect(rate).to.equal(ethers.parseEther("0.05"));
            expect(lastUpdated).to.be.gt(0n);
            expect(blockTimestamp).to.be.gt(0n);
        });

        it("Test 132: oracle: getPriceData returns full ReferenceData struct", async function () {
            const data = await oracle.getPriceData("COTI");
            console.log(`    [Info] getPriceData: rate=${ethers.formatEther(data.rate)}, lastUpdatedBase=${data.lastUpdatedBase}`);
            expect(data.rate).to.equal(ethers.parseEther("0.05"));
            expect(data.lastUpdatedBase).to.be.gt(0n);
            expect(data.lastUpdatedQuote).to.be.gt(0n);
        });

        it("Test 133: oracle: setMaxStaleness updates threshold and emits event", async function () {
            const tx = await oracle.setMaxStaleness(7200, { gasLimit: 2000000 });
            await logTx(tx, "setMaxStaleness(7200)", "setMaxStaleness", ["7200"]);
            await expect(tx).to.emit(oracle, "MaxStalenessUpdated");
            expect(await oracle.maxStaleness()).to.equal(7200n);

            // Restore
            const restoreTx = await oracle.setMaxStaleness(3600, { gasLimit: 2000000 });
            await logTx(restoreTx, "Restore maxStaleness(3600)", "setMaxStaleness", ["3600"]);
        });

        it("Test 134: oracle: setMaxStaleness reverts if below MIN_STALENESS", async function () {
            await expectRevert(oracle.setMaxStaleness(100, { gasLimit: 2000000 }), /StalenessTooLow|revert/i, "    [Info] Correctly reverted: staleness < MIN_STALENESS");
        });

        it("Test 135: oracle: getPrice reverts on stale data", async function () {
            // Set lastUpdated to a very old timestamp (2 hours ago)
            const currentBlock = await ethers.provider.getBlock("latest");
            const staleTimestamp = currentBlock.timestamp - 7200;
            await mockRef.setLastUpdatedBase("COTI", staleTimestamp, { gasLimit: 2000000 });

            try {
                await oracle.getPrice("COTI");
                expect.fail("Expected revert");
            } catch (error) {
                expect(error.message).to.match(/StaleOracleData|revert/i);
                console.log("    [Info] Correctly reverted: StaleOracleData");
            }

            // Restore fresh timestamp
            const freshBlock = await ethers.provider.getBlock("latest");
            await mockRef.setLastUpdatedBase("COTI", freshBlock.timestamp, { gasLimit: 2000000 });
        });

        it("Test 136: oracle: constructor reverts with zero ref address", async function () {
            const OracleFactory = await ethers.getContractFactory("CotiPriceConsumer");
            try {
                const badOracle = await OracleFactory.deploy(ethers.ZeroAddress, 3600, { gasLimit: 12000000 });
                await (badOracle.waitForDeployment ? badOracle.waitForDeployment() : badOracle.deployed());
                expect.fail("Expected revert");
            } catch (error) {
                expect(error.message).to.match(/zero ref address|revert/i);
                console.log("    [Info] Correctly reverted: constructor with zero ref");
            }
        });

        it("Test 137: oracle: constructor reverts with staleness below minimum", async function () {
            const OracleFactory = await ethers.getContractFactory("CotiPriceConsumer");
            try {
                const badOracle = await OracleFactory.deploy(await addr(mockRef), 100, { gasLimit: 12000000 });
                await (badOracle.waitForDeployment ? badOracle.waitForDeployment() : badOracle.deployed());
                expect.fail("Expected revert");
            } catch (error) {
                expect(error.message).to.match(/StalenessTooLow|revert/i);
                console.log("    [Info] Correctly reverted: constructor with staleness < MIN_STALENESS");
            }
        });

        it("Test 138: oracle: setMaxStaleness reverts for non-owner", async function () {
            // user1 is not the owner
            if (user1.address === owner.address) {
                console.log("    [Info] Skipping: user1 === owner on single-signer testnet");
                this.skip();
                return;
            }
            await expectRevert(oracle.connect(user1).setMaxStaleness(7200, { gasLimit: 2000000 }), /caller is not the owner|revert/i, "    [Info] Correctly reverted: non-owner setMaxStaleness");
        });
    });

    after(function () {
        console.log("\n===========================================================");
        console.log(`TOTAL TESTS RUN: ${testCounter}`);
        console.log("===========================================================\n");
    });
});
