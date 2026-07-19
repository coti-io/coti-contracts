import hre from "hardhat"
import { expect } from "chai"
import { parseUnits } from "ethers"

describe("PrivacyPortal failed-request recovery", function () {
    async function deployPortalFixture() {
        const [owner, user, other] = await hre.ethers.getSigners()

        const MockFactory = await hre.ethers.getContractFactory("MockPrivacyPortalFactory")
        const factory = await MockFactory.deploy(owner.address, owner.address)
        await factory.waitForDeployment()

        const MockERC20 = await hre.ethers.getContractFactory("MockERC20")
        const underlying = await MockERC20.deploy("Mock USD", "mUSD", 6)
        await underlying.waitForDeployment()

        const MockPToken = await hre.ethers.getContractFactory("MockPodERC20ForPortal")
        const pToken = await MockPToken.deploy()
        await pToken.waitForDeployment()

        const PortalImpl = await hre.ethers.getContractFactory("PrivacyPortal")
        const portalImpl = await PortalImpl.deploy()
        await portalImpl.waitForDeployment()

        const CloneHelper = await hre.ethers.getContractFactory("CloneHelper")
        const cloneHelper = await CloneHelper.deploy()
        await cloneHelper.waitForDeployment()

        await cloneHelper.clone(await portalImpl.getAddress())
        const portalAddress = await cloneHelper.lastClone()
        const portal = PortalImpl.attach(portalAddress) as Awaited<ReturnType<typeof PortalImpl.deploy>>

        await portal.initialize(
            await underlying.getAddress(),
            await pToken.getAddress(),
            6,
            false,
            await factory.getAddress()
        )

        const amount = parseUnits("100", 6)
        await underlying.mint(user.address, amount * 2n)
        await underlying.connect(user).approve(await portal.getAddress(), amount * 2n)

        return { owner, user, other, factory, underlying, pToken, portal, amount }
    }

    it("refunds locked underlying after a system-failed mint", async function () {
        const { user, other, underlying, pToken, portal, amount } = await deployPortalFixture()

        const tx = await portal.connect(user).deposit(user.address, amount, 0, 100, {
            value: 1000,
        })
        const receipt = await tx.wait()
        const depositLog = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "DepositRequested")
        const requestId = depositLog!.args.mintRequestId as string

        const feesLog = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "OperationFeesPaid")
        expect(feesLog).to.not.equal(undefined)
        expect(feesLog!.args.payer).to.equal(user.address)
        expect(feesLog!.args.correlationId).to.equal(requestId)
        expect(feesLog!.args.isDeposit).to.equal(true)
        expect(feesLog!.args.isNativeWrap).to.equal(false)
        expect(feesLog!.args.portalFee).to.equal(0n)
        expect(feesLog!.args.podFee).to.equal(1000n)
        expect(feesLog!.args.podCallbackFee).to.equal(100n)
        expect(feesLog!.args.amount).to.equal(amount)

        expect(await underlying.balanceOf(await portal.getAddress())).to.equal(amount)
        await expect(portal.connect(user).refundFailedDeposit(requestId)).to.be.revertedWithCustomError(
            portal,
            "DepositMintNotFailed"
        )

        await pToken.markLastMintRaised()
        await expect(portal.connect(user).refundFailedDeposit(requestId)).to.be.revertedWithCustomError(
            portal,
            "DepositMintNotFailed"
        )

        await pToken.markLastMintFailed()
        const before = await underlying.balanceOf(user.address)
        // Permissionless: a third party may trigger; funds still return to the depositor.
        await expect(portal.connect(other).refundFailedDeposit(requestId))
            .to.emit(portal, "DepositRefunded")
            .withArgs(user.address, requestId, amount)

        expect(await underlying.balanceOf(user.address)).to.equal(before + amount)
        expect(await underlying.balanceOf(await portal.getAddress())).to.equal(0n)
        await expect(portal.connect(user).refundFailedDeposit(requestId)).to.be.revertedWithCustomError(
            portal,
            "DepositEscrowInvalid"
        )
    })

    it("marks withdrawal Failed when the pToken transfer request fails", async function () {
        const { user, portal, pToken, amount } = await deployPortalFixture()

        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600)
        const tx = await portal.connect(user).requestWithdrawWithPermit(
            user.address,
            amount,
            0,
            1000,
            100,
            deadline,
            27,
            hre.ethers.ZeroHash,
            hre.ethers.ZeroHash,
            { value: 1000 }
        )
        const receipt = await tx.wait()
        const withdrawLog = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "WithdrawalRequested")
        const withdrawalId = withdrawLog!.args.withdrawalId as string
        const transferRequestId = withdrawLog!.args.transferRequestId as string

        await expect(portal.cancelFailedWithdrawal(withdrawalId)).to.be.revertedWithCustomError(
            portal,
            "WithdrawTransferNotFailed"
        )

        await pToken.markLastTransferFailed()
        await expect(portal.cancelFailedWithdrawal(withdrawalId))
            .to.emit(portal, "WithdrawalFailed")
            .withArgs(withdrawalId, transferRequestId)

        const feesLog = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "OperationFeesPaid")
        expect(feesLog).to.not.equal(undefined)
        expect(feesLog!.args.correlationId).to.equal(withdrawalId)
        expect(feesLog!.args.isDeposit).to.equal(false)
        expect(feesLog!.args.portalFee).to.equal(0n)
        expect(feesLog!.args.podFee).to.equal(1000n)
        expect(feesLog!.args.podCallbackFee).to.equal(100n)

        const withdrawal = await portal.withdrawals(withdrawalId)
        expect(withdrawal.status).to.equal(3n) // WithdrawalStatus.Failed
        await expect(portal.cancelFailedWithdrawal(withdrawalId)).to.be.revertedWithCustomError(
            portal,
            "WithdrawalNotPending"
        )
        await expect(portal.triggerWithdrawalRelease(withdrawalId)).to.be.revertedWithCustomError(
            portal,
            "WithdrawalNotPending"
        )
    })

    it("cancels withdrawal after a system-failed pToken transfer", async function () {
        const { user, portal, pToken, amount } = await deployPortalFixture()

        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600)
        const tx = await portal.connect(user).requestWithdrawWithPermit(
            user.address,
            amount,
            0,
            1000,
            100,
            deadline,
            27,
            hre.ethers.ZeroHash,
            hre.ethers.ZeroHash,
            { value: 1000 }
        )
        const receipt = await tx.wait()
        const withdrawLog = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "WithdrawalRequested")
        const withdrawalId = withdrawLog!.args.withdrawalId as string
        const transferRequestId = withdrawLog!.args.transferRequestId as string

        await pToken.markLastTransferSystemFailed()
        await expect(portal.cancelFailedWithdrawal(withdrawalId))
            .to.emit(portal, "WithdrawalFailed")
            .withArgs(withdrawalId, transferRequestId)

        const withdrawal = await portal.withdrawals(withdrawalId)
        expect(withdrawal.status).to.equal(3n) // WithdrawalStatus.Failed
    })

    it("rescues native and ERC20 to the factory rescue recipient while paused", async function () {
        const { owner, other, factory, underlying, portal, pToken } = await deployPortalFixture()
        const rescueTo = other.address
        await factory.setRescueRecipient(rescueTo)

        await owner.sendTransaction({ to: await portal.getAddress(), value: parseUnits("1", 18) })
        await underlying.mint(await portal.getAddress(), parseUnits("50", 6))

        await expect(portal.connect(owner).rescueNative(parseUnits("1", 18))).to.be.revertedWithCustomError(
            portal,
            "ExpectedPause"
        )

        await portal.connect(owner).pause()
        const rescueNativeAmount = parseUnits("0.4", 18)
        await expect(portal.connect(owner).rescueNative(rescueNativeAmount))
            .to.emit(portal, "NativeRescued")
            .withArgs(rescueTo, rescueNativeAmount)

        const rescueErc20Amount = parseUnits("25", 6)
        await expect(portal.connect(owner).rescueERC20(await underlying.getAddress(), rescueErc20Amount))
            .to.emit(portal, "ERC20Rescued")
            .withArgs(await underlying.getAddress(), rescueTo, rescueErc20Amount)

        await expect(
            portal.connect(owner).rescueERC20(await pToken.getAddress(), 1)
        ).to.be.revertedWithCustomError(portal, "CannotRescuePToken")
    })

    it("sweeps portal fees to the factory fee recipient", async function () {
        const { owner, user, factory, portal, underlying, amount } = await deployPortalFixture()
        expect(await factory.feeRecipient()).to.equal(owner.address)

        await portal.connect(owner).setDepositFee(100, 0, parseUnits("1", 18))
        await underlying.connect(user).approve(await portal.getAddress(), amount)
        await portal.connect(user).deposit(user.address, amount, 100, 100, { value: 1100 })

        expect(await portal.accumulatedPortalFees()).to.equal(100n)
        const before = await hre.ethers.provider.getBalance(owner.address)
        const tx = await portal.connect(owner).withdrawPortalFees(100)
        const receipt = await tx.wait()
        const gas = receipt!.gasUsed * receipt!.gasPrice
        const after = await hre.ethers.provider.getBalance(owner.address)
        expect(after + gas - before).to.equal(100n)
        expect(await portal.accumulatedPortalFees()).to.equal(0n)
    })
})
