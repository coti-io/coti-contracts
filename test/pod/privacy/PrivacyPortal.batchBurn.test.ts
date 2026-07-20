import hre from "hardhat"
import { expect } from "chai"
import { parseUnits } from "ethers"

describe("PrivacyPortal batch burn accounting (PP-07)", function () {
    async function releasedPendingBurnFixture() {
        const [owner, user] = await hre.ethers.getSigners()

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
        await underlying.mint(await portal.getAddress(), amount)

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

        await pToken.markLastTransferSuccessful()
        await portal.triggerWithdrawalRelease(withdrawalId)

        return { owner, user, factory, underlying, pToken, portal, amount, withdrawalId }
    }

    it("keeps pendingBurnAmount accounted while a burn is in flight, decrements only on Success", async function () {
        const { owner, pToken, portal, amount } = await releasedPendingBurnFixture()

        const pendingBefore = await portal.pendingBurnAmount()
        expect(pendingBefore).to.equal(amount)

        const tx = await portal.connect(owner).burnAccumulatedPTokens(amount, 100, { value: 1000 })
        const receipt = await tx.wait()
        const burnLog = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "BatchBurnSubmitted")
        const burnRequestId = burnLog!.args.burnRequestId as string

        // Submission does not decrement pendingBurnAmount; it only reserves it via burnInFlightTotal.
        expect(await portal.pendingBurnAmount()).to.equal(pendingBefore)
        expect(await portal.burnInFlightTotal()).to.equal(amount)
        expect(await portal.burnInFlight(burnRequestId)).to.equal(amount)

        await expect(portal.finalizeBatchBurn(burnRequestId)).to.be.revertedWithCustomError(
            portal,
            "BatchBurnNotResolved"
        )

        await pToken.markLastBurnSuccessful()
        await expect(portal.finalizeBatchBurn(burnRequestId))
            .to.emit(portal, "BatchBurnFinalized")
            .withArgs(burnRequestId, amount, true)

        expect(await portal.pendingBurnAmount()).to.equal(pendingBefore - amount)
        expect(await portal.burnInFlightTotal()).to.equal(0n)
        expect(await portal.burnInFlight(burnRequestId)).to.equal(0n)

        await expect(portal.finalizeBatchBurn(burnRequestId)).to.be.revertedWithCustomError(
            portal,
            "UnknownBatchBurn"
        )
    })

    it("restores burn availability without losing pendingBurnAmount after a Failed burn", async function () {
        const { owner, pToken, portal, amount } = await releasedPendingBurnFixture()
        const pendingBefore = await portal.pendingBurnAmount()

        const tx = await portal.connect(owner).burnAccumulatedPTokens(amount, 100, { value: 1000 })
        const receipt = await tx.wait()
        const burnRequestId = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "BatchBurnSubmitted")!.args.burnRequestId as string

        await pToken.markLastBurnFailed()
        await expect(portal.finalizeBatchBurn(burnRequestId))
            .to.emit(portal, "BatchBurnFinalized")
            .withArgs(burnRequestId, amount, false)

        // pendingBurnAmount is untouched by a failed burn — no accounting is lost.
        expect(await portal.pendingBurnAmount()).to.equal(pendingBefore)
        expect(await portal.burnInFlightTotal()).to.equal(0n)

        // The full amount is available again for a fresh submission.
        await expect(portal.connect(owner).burnAccumulatedPTokens(amount, 100, { value: 1000 })).to.not.be
            .reverted
    })

    it("rejects submitting more than the amount not already reserved in flight", async function () {
        const { owner, portal, amount } = await releasedPendingBurnFixture()
        const pendingBefore = await portal.pendingBurnAmount()

        await portal.connect(owner).burnAccumulatedPTokens(pendingBefore, 100, { value: 1000 })

        await expect(
            portal.connect(owner).burnAccumulatedPTokens(1, 100, { value: 1000 })
        ).to.be.revertedWithCustomError(portal, "PendingBurnTooLow")
    })

    it("rejects finalizing an unknown batch burn id", async function () {
        const { portal } = await releasedPendingBurnFixture()
        await expect(portal.finalizeBatchBurn(hre.ethers.ZeroHash)).to.be.revertedWithCustomError(
            portal,
            "UnknownBatchBurn"
        )
    })
})
