import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../../utils/accounts"
import { PrivacyBridgeERC20Mock, PrivateERC20Mock } from "../../../typechain-types"
import { Wallet } from "@coti-io/coti-ethers"
import { Contract } from "ethers"

const GAS_LIMIT = 12000000

describe("PrivacyBridge Fees", function () {
    let bridge: PrivacyBridgeERC20Mock
    let bridgeAddress: string
    let privateToken: PrivateERC20Mock
    let privateTokenAddress: string
    let publicToken: Contract
    let publicTokenAddress: string
    let owner: Wallet
    let user: Wallet
    let feeRecipient: Wallet

    const INITIAL_SUPPLY = 1000000n
    const DEPOSIT_AMOUNT = 10000n
    const ONE_PERCENT_FEE = 100n // 100 basis points = 1%
    const TEN_PERCENT_FEE = 1000n // 1000 basis points = 10%
    const MAX_FEE = 1000n

    before(async function () {
        [owner, user, feeRecipient] = await setupAccounts()

        // Deploy public ERC20 token (mock)
        const ERC20Factory = await hre.ethers.getContractFactory("ERC20Mock")
        publicToken = await ERC20Factory.connect(owner).deploy("Public Token", "PUB", { gasLimit: GAS_LIMIT })
        await publicToken.waitForDeployment()
        publicTokenAddress = await publicToken.getAddress()

        // Mint tokens to owner and user
        await publicToken.mint(owner.address, INITIAL_SUPPLY, { gasLimit: GAS_LIMIT })
        await publicToken.mint(user.address, INITIAL_SUPPLY, { gasLimit: GAS_LIMIT })

        // Deploy private ERC20 token
        const PrivateERC20Factory = await hre.ethers.getContractFactory("PrivateERC20Mock")
        privateToken = await PrivateERC20Factory.connect(owner).deploy({ gasLimit: GAS_LIMIT })
        await privateToken.waitForDeployment()
        privateTokenAddress = await privateToken.getAddress()

        // Deploy bridge
        const BridgeFactory = await hre.ethers.getContractFactory("PrivacyBridgeERC20Mock")
        bridge = await BridgeFactory.connect(owner).deploy(publicTokenAddress, privateTokenAddress, { gasLimit: GAS_LIMIT })
        await bridge.waitForDeployment()
        bridgeAddress = await bridge.getAddress()

        // Fund bridge with public tokens for withdrawals
        await publicToken.connect(owner).transfer(bridgeAddress, INITIAL_SUPPLY / 2n, { gasLimit: GAS_LIMIT })
    })

    describe("Fee Configuration", function () {
        it("should have zero fees by default", async function () {
            expect(await bridge.depositFeeBasisPoints()).to.equal(0n)
            expect(await bridge.withdrawFeeBasisPoints()).to.equal(0n)
        })

        it("should allow owner to set deposit fee", async function () {
            const tx = await bridge.connect(owner).setDepositFee(ONE_PERCENT_FEE, { gasLimit: GAS_LIMIT })
            await tx.wait()

            expect(await bridge.depositFeeBasisPoints()).to.equal(ONE_PERCENT_FEE)
            await expect(tx).to.emit(bridge, "FeeUpdated").withArgs("deposit", ONE_PERCENT_FEE)
        })

        it("should allow owner to set withdrawal fee", async function () {
            const tx = await bridge.connect(owner).setWithdrawFee(ONE_PERCENT_FEE, { gasLimit: GAS_LIMIT })
            await tx.wait()

            expect(await bridge.withdrawFeeBasisPoints()).to.equal(ONE_PERCENT_FEE)
            await expect(tx).to.emit(bridge, "FeeUpdated").withArgs("withdraw", ONE_PERCENT_FEE)
        })

        it("should allow setting fee to zero", async function () {
            const tx = await bridge.connect(owner).setDepositFee(0n, { gasLimit: GAS_LIMIT })
            await tx.wait()

            expect(await bridge.depositFeeBasisPoints()).to.equal(0n)
        })

        it("should allow setting fee to maximum (10%)", async function () {
            const tx = await bridge.connect(owner).setDepositFee(MAX_FEE, { gasLimit: GAS_LIMIT })
            await tx.wait()

            expect(await bridge.depositFeeBasisPoints()).to.equal(MAX_FEE)
        })

        it("should revert when fee exceeds maximum", async function () {
            await expect(
                bridge.connect(owner).setDepositFee(MAX_FEE + 1n, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "InvalidFee")
        })

        it("should revert when non-owner tries to set deposit fee", async function () {
            await expect(
                bridge.connect(user).setDepositFee(ONE_PERCENT_FEE, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "OwnableUnauthorizedAccount")
        })

        it("should revert when non-owner tries to set withdraw fee", async function () {
            await expect(
                bridge.connect(user).setWithdrawFee(ONE_PERCENT_FEE, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "OwnableUnauthorizedAccount")
        })

        // Reset fees to zero for next tests
        after(async function () {
            await bridge.connect(owner).setDepositFee(0n, { gasLimit: GAS_LIMIT })
            await bridge.connect(owner).setWithdrawFee(0n, { gasLimit: GAS_LIMIT })
        })
    })

    describe("Deposit with Fees", function () {
        it("should deposit without fee when fee is zero", async function () {
            const balanceBefore = await publicToken.balanceOf(user.address)

            await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            const tx = await bridge.connect(user).deposit(DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            await tx.wait()

            const balanceAfter = await publicToken.balanceOf(user.address)
            expect(balanceBefore - balanceAfter).to.equal(DEPOSIT_AMOUNT)

            // User should receive full amount in private tokens
            const ctBalance = await privateToken["balanceOf(address)"](user.address)
            const privateBalance = await user.decryptValue256(ctBalance)
            expect(privateBalance).to.equal(DEPOSIT_AMOUNT)

            expect(await bridge.accumulatedFees()).to.equal(0n)
        })

        it("should deduct 1% fee on deposit", async function () {
            // Set 1% fee
            await bridge.connect(owner).setDepositFee(ONE_PERCENT_FEE, { gasLimit: GAS_LIMIT })

            const expectedFee = (DEPOSIT_AMOUNT * ONE_PERCENT_FEE) / 10000n
            const expectedAmount = DEPOSIT_AMOUNT - expectedFee

            await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            const tx = await bridge.connect(user).deposit(DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            await tx.wait()

            // User should receive amount minus fee
            const ctBalance = await privateToken["balanceOf(address)"](user.address)
            const privateBalance = await user.decryptValue256(ctBalance)
            expect(privateBalance).to.equal(DEPOSIT_AMOUNT + expectedAmount) // Previous deposit + this one

            expect(await bridge.accumulatedFees()).to.equal(expectedFee)
        })

        it("should deduct 10% fee on deposit", async function () {
            // Set 10% fee
            await bridge.connect(owner).setDepositFee(TEN_PERCENT_FEE, { gasLimit: GAS_LIMIT })

            const previousFees = await bridge.accumulatedFees()
            const expectedFee = (DEPOSIT_AMOUNT * TEN_PERCENT_FEE) / 10000n
            const expectedAmount = DEPOSIT_AMOUNT - expectedFee

            await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            const tx = await bridge.connect(user).deposit(DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            await tx.wait()

            expect(await bridge.accumulatedFees()).to.equal(previousFees + expectedFee)
        })

        // Reset fee to zero
        after(async function () {
            await bridge.connect(owner).setDepositFee(0n, { gasLimit: GAS_LIMIT })
        })
    })

    describe("Withdraw with Fees (via onTokenReceived)", function () {
        const WITHDRAW_AMOUNT = 5000n

        before(async function () {
            // Ensure user has private tokens to withdraw
            const ctBalance = await privateToken["balanceOf(address)"](user.address)
            const balance = await user.decryptValue256(ctBalance)
            if (balance < WITHDRAW_AMOUNT) {
                await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
                await bridge.connect(user).deposit(DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            }
        })

        it("should withdraw without fee when fee is zero", async function () {
            const publicBalanceBefore = await publicToken.balanceOf(user.address)

            const tx = await privateToken.connect(user).transferAndCall(
                bridgeAddress,
                WITHDRAW_AMOUNT,
                "0x",
                { gasLimit: GAS_LIMIT }
            )
            await tx.wait()

            const publicBalanceAfter = await publicToken.balanceOf(user.address)
            expect(publicBalanceAfter - publicBalanceBefore).to.equal(WITHDRAW_AMOUNT)

            // No fees accumulated
            expect(await bridge.accumulatedFees()).to.be.greaterThan(0n) // From previous deposit tests
        })

        it("should deduct 1% fee on withdrawal", async function () {
            // Set 1% fee
            await bridge.connect(owner).setWithdrawFee(ONE_PERCENT_FEE, { gasLimit: GAS_LIMIT })

            const previousFees = await bridge.accumulatedFees()
            const expectedFee = (WITHDRAW_AMOUNT * ONE_PERCENT_FEE) / 10000n
            const expectedAmount = WITHDRAW_AMOUNT - expectedFee

            const publicBalanceBefore = await publicToken.balanceOf(user.address)

            const tx = await privateToken.connect(user).transferAndCall(
                bridgeAddress,
                WITHDRAW_AMOUNT,
                "0x",
                { gasLimit: GAS_LIMIT }
            )
            await tx.wait()

            const publicBalanceAfter = await publicToken.balanceOf(user.address)
            expect(publicBalanceAfter - publicBalanceBefore).to.equal(expectedAmount)

            expect(await bridge.accumulatedFees()).to.equal(previousFees + expectedFee)
        })

        it("should deduct 10% fee on withdrawal", async function () {
            // Set 10% fee
            await bridge.connect(owner).setWithdrawFee(TEN_PERCENT_FEE, { gasLimit: GAS_LIMIT })

            const previousFees = await bridge.accumulatedFees()
            const expectedFee = (WITHDRAW_AMOUNT * TEN_PERCENT_FEE) / 10000n
            const expectedAmount = WITHDRAW_AMOUNT - expectedFee

            const publicBalanceBefore = await publicToken.balanceOf(user.address)

            const tx = await privateToken.connect(user).transferAndCall(
                bridgeAddress,
                WITHDRAW_AMOUNT,
                "0x",
                { gasLimit: GAS_LIMIT }
            )
            await tx.wait()

            const publicBalanceAfter = await publicToken.balanceOf(user.address)
            expect(publicBalanceAfter - publicBalanceBefore).to.equal(expectedAmount)

            expect(await bridge.accumulatedFees()).to.equal(previousFees + expectedFee)
        })

        // Reset fee to zero
        after(async function () {
            await bridge.connect(owner).setWithdrawFee(0n, { gasLimit: GAS_LIMIT })
        })
    })

    describe("Fee Withdrawal", function () {
        it("should allow owner to withdraw accumulated fees", async function () {
            const accumulatedFees = await bridge.accumulatedFees()
            expect(accumulatedFees).to.be.greaterThan(0n)

            const recipientBalanceBefore = await publicToken.balanceOf(feeRecipient.address)

            const tx = await bridge.connect(owner).withdrawFees(
                feeRecipient.address,
                accumulatedFees,
                { gasLimit: GAS_LIMIT }
            )
            await tx.wait()

            const recipientBalanceAfter = await publicToken.balanceOf(feeRecipient.address)
            expect(recipientBalanceAfter - recipientBalanceBefore).to.equal(accumulatedFees)

            expect(await bridge.accumulatedFees()).to.equal(0n)
            await expect(tx).to.emit(bridge, "FeesWithdrawn").withArgs(feeRecipient.address, accumulatedFees)
        })

        it("should allow partial withdrawal of fees", async function () {
            // Accumulate some fees first
            await bridge.connect(owner).setDepositFee(ONE_PERCENT_FEE, { gasLimit: GAS_LIMIT })
            await publicToken.connect(user).approve(bridgeAddress, DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })
            await bridge.connect(user).deposit(DEPOSIT_AMOUNT, { gasLimit: GAS_LIMIT })

            const accumulatedFees = await bridge.accumulatedFees()
            const withdrawAmount = accumulatedFees / 2n

            await bridge.connect(owner).withdrawFees(feeRecipient.address, withdrawAmount, { gasLimit: GAS_LIMIT })

            expect(await bridge.accumulatedFees()).to.equal(accumulatedFees - withdrawAmount)

            // Reset
            await bridge.connect(owner).setDepositFee(0n, { gasLimit: GAS_LIMIT })
        })

        it("should revert when non-owner tries to withdraw fees", async function () {
            await expect(
                bridge.connect(user).withdrawFees(feeRecipient.address, 100n, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "OwnableUnauthorizedAccount")
        })

        it("should revert when withdrawing to zero address", async function () {
            await expect(
                bridge.connect(owner).withdrawFees(hre.ethers.ZeroAddress, 100n, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "InvalidAddress")
        })

        it("should revert when withdrawing zero amount", async function () {
            await expect(
                bridge.connect(owner).withdrawFees(feeRecipient.address, 0n, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "AmountZero")
        })

        it("should revert when withdrawing more than accumulated fees", async function () {
            const accumulatedFees = await bridge.accumulatedFees()
            await expect(
                bridge.connect(owner).withdrawFees(feeRecipient.address, accumulatedFees + 1n, { gasLimit: GAS_LIMIT })
            ).to.be.revertedWithCustomError(bridge, "InsufficientAccumulatedFees")
        })
    })
})
