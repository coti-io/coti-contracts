import hre from "hardhat"
import { expect } from "chai"
import { parseUnits, ZeroAddress, ZeroHash } from "ethers"

describe("PrivacyPortalFactory same-factory portal remount", function () {
    async function deployFixture() {
        const [owner, user] = await hre.ethers.getSigners()

        const MockInbox = await hre.ethers.getContractFactory("MockInbox")
        const inbox = await MockInbox.deploy()
        await inbox.waitForDeployment()

        const PortalImpl = await hre.ethers.getContractFactory("PrivacyPortal")
        const portalImpl = await PortalImpl.deploy()
        await portalImpl.waitForDeployment()

        const PTokenImpl = await hre.ethers.getContractFactory("MockPodErc20MintableForPortal")
        const pTokenImpl = await PTokenImpl.deploy()
        await pTokenImpl.waitForDeployment()

        const Factory = await hre.ethers.getContractFactory("PrivacyPortalFactory")
        const factory = await Factory.deploy(
            owner.address,
            await inbox.getAddress(),
            7082400,
            owner.address,
            await pTokenImpl.getAddress(),
            await portalImpl.getAddress(),
            owner.address,
            owner.address,
            owner.address,
            hre.ethers.ZeroAddress,
            0,
            0,
            2n ** 128n - 1n,
            0,
            0,
            2n ** 128n - 1n
        )
        await factory.waitForDeployment()

        const MockERC20 = await hre.ethers.getContractFactory("MockERC20")
        const underlying = await MockERC20.deploy("Mock USD", "mUSD", 6)
        await underlying.waitForDeployment()

        const amount = parseUnits("100", 6)
        await underlying.mint(user.address, amount * 10n)

        return {
            owner,
            user,
            inbox,
            factory,
            portalImpl,
            pTokenImpl,
            underlying,
            amount,
            PortalImpl,
        }
    }

    async function createCleanPair(fixture: Awaited<ReturnType<typeof deployFixture>>) {
        const { factory, underlying } = fixture
        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const portalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())
        const portal = await hre.ethers.getContractAt("PrivacyPortal", portalAddr)
        const pToken = await hre.ethers.getContractAt("MockPodErc20MintableForPortal", pTokenAddr)
        return { portal, pToken, portalAddr, pTokenAddr }
    }

    async function remountPaused(
        fixture: Awaited<ReturnType<typeof deployFixture>>,
        oldPortal: { pause: () => Promise<unknown>; getAddress?: () => Promise<string> },
        pTokenAddr: string
    ) {
        const { factory, underlying, PortalImpl, portalImpl } = fixture
        await oldPortal.pause()

        const portalImplV2 = await PortalImpl.deploy()
        await portalImplV2.waitForDeployment()
        await expect(factory.setPortalImplementation(await portalImplV2.getAddress()))
            .to.emit(factory, "PortalImplementationUpdated")
            .withArgs(await portalImpl.getAddress(), await portalImplV2.getAddress())

        const remountTx = await factory.createPortalWithExistingPToken(
            await underlying.getAddress(),
            pTokenAddr,
            false
        )
        await expect(remountTx).to.emit(factory, "PortalCreated")
        await expect(remountTx).to.emit(factory, "PortalReplaced")

        const newPortalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        const newPortal = await hre.ethers.getContractAt("PrivacyPortal", newPortalAddr)
        return { newPortal, newPortalAddr, portalImplV2 }
    }

    it("reverts remount when old portal is not paused", async function () {
        const fixture = await deployFixture()
        const { factory, underlying, PortalImpl } = fixture
        const { portalAddr: oldPortalAddr, pTokenAddr } = await createCleanPair(fixture)

        const portalImplV2 = await PortalImpl.deploy()
        await portalImplV2.waitForDeployment()
        await factory.setPortalImplementation(await portalImplV2.getAddress())

        await expect(
            factory.createPortalWithExistingPToken(await underlying.getAddress(), pTokenAddr, false)
        )
            .to.be.revertedWithCustomError(factory, "OldPortalNotPaused")
            .withArgs(oldPortalAddr)
    })

    it("remounts only when paused: new starts paused; after migrate+unpause holders withdraw on new", async function () {
        const fixture = await deployFixture()
        const { factory, underlying, user, amount, owner } = fixture
        const [, , other] = await hre.ethers.getSigners()

        const { portal: oldPortal, pToken, portalAddr: oldPortalAddr, pTokenAddr } =
            await createCleanPair(fixture)

        await underlying.connect(user).approve(oldPortalAddr, amount)
        await expect(oldPortal.connect(user).deposit(user.address, amount, 0, 100, { value: 1000 }))
            .to.emit(oldPortal, "DepositRequested")
        expect(await underlying.balanceOf(oldPortalAddr)).to.equal(amount)

        const { newPortal, newPortalAddr } = await remountPaused(fixture, oldPortal, pTokenAddr)

        expect(newPortalAddr).to.not.equal(oldPortalAddr)
        expect(await factory.pTokenForUnderlying(await underlying.getAddress())).to.equal(pTokenAddr)
        expect(await factory.portalForPToken(pTokenAddr)).to.equal(newPortalAddr)
        expect(await pToken.minter()).to.equal(newPortalAddr)
        expect(await oldPortal.isDepositEnabled()).to.equal(false)
        expect(await oldPortal.factory()).to.equal(ZeroAddress)
        expect(await oldPortal.bindingFactory()).to.equal(await factory.getAddress())
        expect(await oldPortal.paused()).to.equal(true)
        expect(await newPortal.paused()).to.equal(true)

        // Soft close: no user activity on new until admin opens it.
        await underlying.mint(other.address, amount)
        await underlying.connect(other).approve(newPortalAddr, amount)
        await expect(
            newPortal.connect(other).deposit(other.address, amount, 0, 100, { value: 1000 })
        ).to.be.revertedWithCustomError(newPortal, "DepositsPaused")

        // Admin migrates collateral old → new (rescue requires pause; already paused).
        const oldBal = await underlying.balanceOf(oldPortalAddr)
        await oldPortal.connect(owner).rescueERC20(await underlying.getAddress(), oldBal)
        // rescue sends to rescueRecipient (== owner in fixture); fund the new portal.
        await underlying.connect(owner).transfer(newPortalAddr, oldBal)
        expect(await underlying.balanceOf(oldPortalAddr)).to.equal(0n)
        expect(await underlying.balanceOf(newPortalAddr)).to.equal(amount)

        await newPortal.connect(owner).unpause()
        expect(await newPortal.paused()).to.equal(false)

        // Pre-remount pToken holder withdraws successfully on the new portal.
        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600)
        const withdrawTx = await newPortal.connect(user).requestWithdrawWithPermit(
            user.address,
            amount,
            0,
            1000,
            100,
            deadline,
            27,
            ZeroHash,
            ZeroHash,
            { value: 1000 }
        )
        const withdrawReceipt = await withdrawTx.wait()
        const withdrawLog = withdrawReceipt!.logs
            .map((log) => {
                try {
                    return newPortal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "WithdrawalRequested")
        const withdrawalId = withdrawLog!.args.withdrawalId as string

        await pToken.markLastTransferSuccessful()
        const before = await underlying.balanceOf(user.address)
        await expect(newPortal.triggerWithdrawalRelease(withdrawalId))
            .to.emit(newPortal, "WithdrawalReleased")
            .withArgs(withdrawalId, user.address, amount)
        expect(await underlying.balanceOf(user.address)).to.equal(before + amount)
        expect(await underlying.balanceOf(newPortalAddr)).to.equal(0n)
    })

    it("createPortalWithExistingPToken creates when unmapped (paused) and remounts when same pToken mapped", async function () {
        const fixture = await deployFixture()
        const { factory, underlying } = fixture

        const MockERC20 = await hre.ethers.getContractFactory("MockERC20")
        const underlying2 = await MockERC20.deploy("Mock USD 2", "mUSD2", 6)
        await underlying2.waitForDeployment()

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())
        const oldPortalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        const oldPortal = await hre.ethers.getContractAt("PrivacyPortal", oldPortalAddr)

        await expect(
            factory.createPortalWithExistingPToken(await underlying2.getAddress(), pTokenAddr, false)
        )
            .to.be.revertedWithCustomError(factory, "UnderlyingPTokenMismatch")
            .withArgs(await underlying2.getAddress(), ZeroAddress, pTokenAddr)

        const { newPortal, newPortalAddr } = await remountPaused(fixture, oldPortal, pTokenAddr)
        expect(newPortalAddr).to.not.equal(oldPortalAddr)
        expect(await factory.portalForPToken(pTokenAddr)).to.equal(newPortalAddr)
        expect(await newPortal.paused()).to.equal(true)
    })

    it("setPortalImplementation / setPodTokenImplementation reject zero and non-admin", async function () {
        const { factory, stranger } = await deployFixture().then(async (f) => {
            const [, , strangerSigner] = await hre.ethers.getSigners()
            return { ...f, stranger: strangerSigner }
        })

        await expect(factory.setPortalImplementation(ZeroAddress)).to.be.revertedWithCustomError(
            factory,
            "InvalidAddress"
        )
        await expect(factory.setPodTokenImplementation(ZeroAddress)).to.be.revertedWithCustomError(
            factory,
            "InvalidAddress"
        )
        await expect(factory.connect(stranger).setPortalImplementation(factory.target)).to.be.reverted
    })

    it("after remount, failed-mint refund still works on paused old portal", async function () {
        const fixture = await deployFixture()
        const { underlying, user, amount } = fixture

        const { portal: oldPortal, pToken, portalAddr: oldPortalAddr, pTokenAddr } =
            await createCleanPair(fixture)

        await underlying.connect(user).approve(oldPortalAddr, amount)
        const depositTx = await oldPortal
            .connect(user)
            .deposit(user.address, amount, 0, 100, { value: 1000 })
        const depositReceipt = await depositTx.wait()
        const depositLog = depositReceipt!.logs
            .map((log) => {
                try {
                    return oldPortal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "DepositRequested")
        const mintRequestId = depositLog!.args.mintRequestId as string

        await remountPaused(fixture, oldPortal, pTokenAddr)

        expect(await fixture.factory.portalForUnderlying(await underlying.getAddress())).to.not.equal(
            oldPortalAddr
        )

        // refundFailedDeposit is not gated on pause — still available on retired/paused old portal.
        await pToken.markLastMintFailed()
        const before = await underlying.balanceOf(user.address)
        await expect(oldPortal.refundFailedDeposit(mintRequestId))
            .to.emit(oldPortal, "DepositRefunded")
            .withArgs(user.address, mintRequestId, amount)
        expect(await underlying.balanceOf(user.address)).to.equal(before + amount)
        expect(await underlying.balanceOf(oldPortalAddr)).to.equal(0n)
    })

    it("retireDepositsForUpgrade clears factory; setIsDepositEnabled cannot re-enable", async function () {
        const fixture = await deployFixture()
        const { factory, underlying } = fixture
        const { portal: oldPortal, pTokenAddr } = await createCleanPair(fixture)

        await remountPaused(fixture, oldPortal, pTokenAddr)

        expect(await oldPortal.factory()).to.equal(ZeroAddress)
        expect(await oldPortal.bindingFactory()).to.equal(await factory.getAddress())
        expect(await oldPortal.isDepositEnabled()).to.equal(false)

        await expect(oldPortal.setIsDepositEnabled(true)).to.be.revertedWithCustomError(
            oldPortal,
            "FactoryNotConfigured"
        )
        expect(await oldPortal.isDepositEnabled()).to.equal(false)
        await expect(oldPortal.unpause()).to.be.revertedWithCustomError(
            oldPortal,
            "FactoryNotConfigured"
        )
        // Rescue/admin still works via bindingFactory after detach.
        expect(await oldPortal.paused()).to.equal(true)
        void underlying
    })

    it("rejects remount of native portal as non-native (ERC20 WETH mode)", async function () {
        const fixture = await deployFixture()
        const { factory, owner, PortalImpl } = fixture

        const MockWrappedNative = await hre.ethers.getContractFactory("MockWrappedNative")
        const wavax = await MockWrappedNative.deploy("Wrapped AVAX", "WAVAX")
        await wavax.waitForDeployment()

        // Redeploy factory with nativeToken = wavax so native portal is coherent.
        const MockInbox = await hre.ethers.getContractFactory("MockInbox")
        const inbox = await MockInbox.deploy()
        await inbox.waitForDeployment()
        const portalImpl = await PortalImpl.deploy()
        await portalImpl.waitForDeployment()
        const pTokenImpl = await (
            await hre.ethers.getContractFactory("MockPodErc20MintableForPortal")
        ).deploy()
        await pTokenImpl.waitForDeployment()

        const Factory = await hre.ethers.getContractFactory("PrivacyPortalFactory")
        const nativeFactory = await Factory.deploy(
            owner.address,
            await inbox.getAddress(),
            7082400,
            owner.address,
            await pTokenImpl.getAddress(),
            await portalImpl.getAddress(),
            owner.address,
            owner.address,
            await wavax.getAddress(),
            hre.ethers.ZeroAddress,
            0,
            0,
            2n ** 128n - 1n,
            0,
            0,
            2n ** 128n - 1n
        )
        await nativeFactory.waitForDeployment()

        await nativeFactory.createPortal(await wavax.getAddress(), "pWAVAX", "pWAVAX", 18, true)
        const pTokenAddr = await nativeFactory.pTokenForUnderlying(await wavax.getAddress())
        const oldPortalAddr = await nativeFactory.portalForUnderlying(await wavax.getAddress())
        const oldPortal = await hre.ethers.getContractAt("PrivacyPortal", oldPortalAddr)
        await oldPortal.pause()

        const portalImplV2 = await PortalImpl.deploy()
        await portalImplV2.waitForDeployment()
        await nativeFactory.setPortalImplementation(await portalImplV2.getAddress())

        await expect(
            nativeFactory.createPortalWithExistingPToken(await wavax.getAddress(), pTokenAddr, false)
        )
            .to.be.revertedWithCustomError(nativeFactory, "NativePortalRequiresNative")
            .withArgs(oldPortalAddr)

        await expect(
            nativeFactory.createPortalWithExistingPToken(await wavax.getAddress(), pTokenAddr, true)
        ).to.emit(nativeFactory, "PortalReplaced")

        void factory
    })

    it("rejects remount flipping non-native portal into native wrap mode", async function () {
        const fixture = await deployFixture()
        const { factory, underlying, PortalImpl } = fixture
        const { portal: oldPortal, pTokenAddr, portalAddr: oldPortalAddr } =
            await createCleanPair(fixture)

        await oldPortal.pause()
        const portalImplV2 = await PortalImpl.deploy()
        await portalImplV2.waitForDeployment()
        await factory.setPortalImplementation(await portalImplV2.getAddress())

        await expect(
            factory.createPortalWithExistingPToken(await underlying.getAddress(), pTokenAddr, true)
        )
            .to.be.revertedWithCustomError(factory, "NativeWrapMismatch")
            .withArgs(oldPortalAddr, false, true)
    })

    it("completes in-flight TransferPending withdraw on old portal after remount", async function () {
        const fixture = await deployFixture()
        const { factory, underlying, user, amount, owner } = fixture
        const { portal: oldPortal, pToken, portalAddr: oldPortalAddr, pTokenAddr } =
            await createCleanPair(fixture)

        await underlying.connect(user).approve(oldPortalAddr, amount)
        await oldPortal.connect(user).deposit(user.address, amount, 0, 100, { value: 1000 })

        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600)
        const withdrawTx = await oldPortal.connect(user).requestWithdrawWithPermit(
            user.address,
            amount,
            0,
            1000,
            100,
            deadline,
            27,
            ZeroHash,
            ZeroHash,
            { value: 1000 }
        )
        const withdrawReceipt = await withdrawTx.wait()
        const withdrawLog = withdrawReceipt!.logs
            .map((log) => {
                try {
                    return oldPortal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "WithdrawalRequested")
        const withdrawalId = withdrawLog!.args.withdrawalId as string

        // Remount while withdraw is still TransferPending on the old portal.
        const { newPortalAddr } = await remountPaused(fixture, oldPortal, pTokenAddr)
        expect(newPortalAddr).to.not.equal(oldPortalAddr)
        expect(await underlying.balanceOf(oldPortalAddr)).to.equal(amount)

        await pToken.markLastTransferSuccessful()
        const before = await underlying.balanceOf(user.address)
        await expect(oldPortal.triggerWithdrawalRelease(withdrawalId))
            .to.emit(oldPortal, "WithdrawalReleased")
            .withArgs(withdrawalId, user.address, amount)
        expect(await underlying.balanceOf(user.address)).to.equal(before + amount)
        expect(await underlying.balanceOf(oldPortalAddr)).to.equal(0n)

        // New portal stays paused / empty until admin migrates (nothing left to migrate here).
        const newPortal = await hre.ethers.getContractAt("PrivacyPortal", newPortalAddr)
        expect(await newPortal.paused()).to.equal(true)
        void factory
        void owner
    })

    it("exposes remount/admin entrypoints via IPrivacyPortalFactoryAdmin", async function () {
        const fixture = await deployFixture()
        const { factory, underlying } = fixture
        const { portal: oldPortal, pTokenAddr } = await createCleanPair(fixture)

        const admin = await hre.ethers.getContractAt("IPrivacyPortalFactoryAdmin", await factory.getAddress())
        await oldPortal.pause()

        const portalImplV2 = await fixture.PortalImpl.deploy()
        await portalImplV2.waitForDeployment()
        await admin.setPortalImplementation(await portalImplV2.getAddress())

        await expect(
            admin.createPortalWithExistingPToken(await underlying.getAddress(), pTokenAddr, false)
        ).to.emit(factory, "PortalReplaced")

        const newPortalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        expect(newPortalAddr).to.not.equal(ZeroAddress)
        expect(await factory.portalForPToken(pTokenAddr)).to.equal(newPortalAddr)
    })
})
