import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../../utils/accounts"
import {
    CotiPriceConsumerMock,
    ERC20DecimalsMock,
    PrivacyBridgeERC20Mock,
    PrivateERC20Mock,
} from "../../../typechain-types"
import { Wallet } from "@coti-io/coti-ethers"
import { parseEther, parseUnits, ZeroAddress } from "ethers"
import { txOpts } from "../../utils/privateErc20Helpers"

const GAS_LIMIT = 12000000

describe("PrivacyBridge Fees (dynamic native COTI)", function () {
    let bridge: PrivacyBridgeERC20Mock
    let bridgeAddress: string
    let privateToken: PrivateERC20Mock
    let privateTokenAddress: string
    let publicToken: ERC20DecimalsMock
    let publicTokenAddress: string
    let oracle: CotiPriceConsumerMock
    let owner: Wallet
    let user: Wallet
    let feeRecipient: Wallet

    const INITIAL_SUPPLY = parseUnits("1000000", 6)
    const DEPOSIT_AMOUNT = parseUnits("10000", 6)

    async function syncOracleAndEstimateDepositFee(amount: bigint) {
        await (await oracle.sync()).wait()
        return bridge.estimateDepositFee(amount)
    }

    async function syncOracleAndEstimateWithdrawFee(amount: bigint) {
        await (await oracle.sync()).wait()
        return bridge.estimateWithdrawFee(amount)
    }

    before(async function () {
        ;[owner, user] = await setupAccounts()
        feeRecipient = owner

        const PublicFactory = await hre.ethers.getContractFactory("ERC20DecimalsMock")
        publicToken = await PublicFactory.connect(owner).deploy("Public Token", "PUB", 6, txOpts)
        await publicToken.waitForDeployment()
        publicTokenAddress = await publicToken.getAddress()

        await publicToken.mint(owner.address, INITIAL_SUPPLY, { gasLimit: GAS_LIMIT })
        await publicToken.mint(user.address, INITIAL_SUPPLY, { gasLimit: GAS_LIMIT })

        const PrivateERC20Factory = await hre.ethers.getContractFactory("PrivateERC20Mock")
        privateToken = await PrivateERC20Factory.connect(owner).deploy(txOpts)
        await privateToken.waitForDeployment()
        privateTokenAddress = await privateToken.getAddress()

        const OracleFactory = await hre.ethers.getContractFactory("CotiPriceConsumerMock")
        oracle = await OracleFactory.connect(owner).deploy(txOpts)
        await oracle.waitForDeployment()
        await (await oracle.setRate("COTI", parseEther("1"))).wait()
        await (await oracle.setRate("USDC", parseEther("1"))).wait()
        const oracleAddress = await oracle.getAddress()

        const BridgeFactory = await hre.ethers.getContractFactory("PrivacyBridgeERC20Mock")
        bridge = await BridgeFactory.connect(owner).deploy(
            publicTokenAddress,
            privateTokenAddress,
            "USDC",
            feeRecipient.address,
            feeRecipient.address,
            oracleAddress,
            txOpts
        )
        await bridge.waitForDeployment()
        bridgeAddress = await bridge.getAddress()

        await publicToken.connect(owner).transfer(bridgeAddress, INITIAL_SUPPLY / 2n, { gasLimit: GAS_LIMIT })

        await owner.sendTransaction({ to: user.address, value: parseEther("50") })
    })

    describe("Default dynamic fee parameters", function () {
        it("exposes deposit/withdraw floor, percentage divisor scale, and caps", async function () {
            expect(await bridge.depositFixedFee()).to.equal(parseEther("10"))
            expect(await bridge.depositPercentageBps()).to.equal(500n)
            expect(await bridge.depositMaxFee()).to.equal(parseEther("3000"))
            expect(await bridge.withdrawFixedFee()).to.equal(parseEther("3"))
            expect(await bridge.withdrawPercentageBps()).to.equal(250n)
            expect(await bridge.FEE_DIVISOR()).to.equal(1_000_000n)
        })
    })

    describe("Oracle and estimates", function () {
        it("reverts deploy when price oracle is zero", async function () {
            const freshFactory = await hre.ethers.getContractFactory("PrivacyBridgeERC20Mock")
            await expect(
                freshFactory
                    .connect(owner)
                    .deploy(
                        publicTokenAddress,
                        privateTokenAddress,
                        "USDC",
                        feeRecipient.address,
                        feeRecipient.address,
                        ZeroAddress,
                        txOpts
                    )
            ).to.be.revertedWithCustomError(bridge, "InvalidAddress")
        })

        it("reverts setMaxOracleAge(0)", async function () {
            await expect(bridge.connect(owner).setMaxOracleAge(0n, { gasLimit: GAS_LIMIT })).to.be.revertedWithCustomError(
                bridge,
                "OracleMaxAgeZeroDisallowed"
            )
        })

        it("estimateDepositFee returns fee and timestamps", async function () {
            const [fee, cotiLu, tokenLu] = await syncOracleAndEstimateDepositFee(DEPOSIT_AMOUNT)
            expect(fee).to.be.gt(0n)
            expect(cotiLu).to.equal(tokenLu)
        })
    })

    describe("Operator fee configuration", function () {
        it("allows operator to set deposit dynamic fee and emits DynamicFeeUpdated", async function () {
            const fixedFee = parseEther("2")
            const pct = 1000n
            const maxFee = parseEther("500")
            const tx = await bridge.connect(owner).setDepositDynamicFee(fixedFee, pct, maxFee, { gasLimit: GAS_LIMIT })
            await tx.wait()
            expect(await bridge.depositFixedFee()).to.equal(fixedFee)
            expect(await bridge.depositPercentageBps()).to.equal(pct)
            expect(await bridge.depositMaxFee()).to.equal(maxFee)
            await expect(tx)
                .to.emit(bridge, "DynamicFeeUpdated")
                .withArgs("deposit", fixedFee, pct, maxFee)
        })

        it("reverts when non-operator sets deposit dynamic fee", async function () {
            const opRole = await bridge.OPERATOR_ROLE()
            await expect(
                bridge.connect(user).setDepositDynamicFee(parseEther("1"), 100n, parseEther("100"), {
                    gasLimit: GAS_LIMIT,
                })
            )
                .to.be.revertedWithCustomError(bridge, "AccessControlUnauthorizedAccount")
                .withArgs(user.address, opRole)
        })

        it("reverts InvalidFee when percentage exceeds MAX_FEE_UNITS", async function () {
            const maxUnits = await bridge.MAX_FEE_UNITS()
            await expect(
                bridge.connect(owner).setDepositDynamicFee(parseEther("1"), maxUnits + 1n, parseEther("1000"), {
                    gasLimit: GAS_LIMIT,
                })
            ).to.be.revertedWithCustomError(bridge, "InvalidFee")
        })

        after(async function () {
            await bridge
                .connect(owner)
                .setDepositDynamicFee(parseEther("10"), 500n, parseEther("3000"), { gasLimit: GAS_LIMIT })
        })
    })

    describe("Deposit with native COTI fee", function () {
        it("collects dynamic native fee into accumulatedCotiFees and credits liability", async function () {
            const feesBefore = await bridge.accumulatedCotiFees()
            const liabilityBefore = await bridge.totalUserLiability()

            const [fee, cotiTs, tokenTs] = await syncOracleAndEstimateDepositFee(DEPOSIT_AMOUNT)
            expect(fee).to.be.gt(0n)

            await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            const tx = await bridge
                .connect(user)
                .deposit(DEPOSIT_AMOUNT, cotiTs, tokenTs, { gasLimit: GAS_LIMIT, value: fee })
            await tx.wait()

            expect(await bridge.accumulatedCotiFees()).to.equal(feesBefore + fee)
            expect(await bridge.totalUserLiability()).to.equal(liabilityBefore + DEPOSIT_AMOUNT)
            await expect(tx).to.emit(bridge, "Deposit")
        })

        it("reverts deposit when msg.value is below computed fee", async function () {
            const [, cotiTs, tokenTs] = await syncOracleAndEstimateDepositFee(DEPOSIT_AMOUNT)
            await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            await expect(
                bridge.connect(user).deposit(DEPOSIT_AMOUNT, cotiTs, tokenTs, {
                    gasLimit: GAS_LIMIT,
                    value: 1n,
                })
            ).to.be.revertedWithCustomError(bridge, "InsufficientCotiFee")
        })
    })

    describe("withdrawCotiFees", function () {
        it("allows owner to sweep accumulated native fees to feeRecipient", async function () {
            const accumulated = await bridge.accumulatedCotiFees()
            expect(accumulated).to.be.gt(0n)
            const recipientBalBefore = await hre.ethers.provider.getBalance(feeRecipient.address)
            const tx = await bridge.connect(owner).withdrawCotiFees(accumulated, { gasLimit: GAS_LIMIT })
            await tx.wait()
            const recipientBalAfter = await hre.ethers.provider.getBalance(feeRecipient.address)
            expect(recipientBalAfter - recipientBalBefore).to.equal(accumulated)
            expect(await bridge.accumulatedCotiFees()).to.equal(0n)
        })

        it("reverts withdrawCotiFees for non-owner", async function () {
            await expect(
                bridge.connect(user).withdrawCotiFees(1n, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "OwnableUnauthorizedAccount")
        })

        it("reverts withdrawCotiFees with zero amount", async function () {
            await expect(
                bridge.connect(owner).withdrawCotiFees(0n, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "AmountZero")
        })
    })

    describe("Withdraw path (native fee + public token)", function () {
        before(async function () {
            const [fee, cotiTs, tokenTs] = await syncOracleAndEstimateDepositFee(DEPOSIT_AMOUNT)
            await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            await bridge.connect(user).deposit(DEPOSIT_AMOUNT, cotiTs, tokenTs, {
                gasLimit: GAS_LIMIT,
                value: fee,
            })
        })

        it("withdraw burns private and releases public after paying native fee", async function () {
            const withdrawAmount = parseUnits("1000", 6)
            const [wFee, cotiTs2, tokenTs2] = await syncOracleAndEstimateWithdrawFee(withdrawAmount)

            await privateToken.connect(user).approve(bridgeAddress, withdrawAmount, { gasLimit: GAS_LIMIT })

            const publicBefore = await publicToken.balanceOf(user.address)
            const tx = await bridge.connect(user).withdraw(withdrawAmount, cotiTs2, tokenTs2, {
                gasLimit: GAS_LIMIT,
                value: wFee,
            })
            await tx.wait()
            const publicAfter = await publicToken.balanceOf(user.address)
            expect(publicAfter - publicBefore).to.equal(withdrawAmount)
        })
    })
})
