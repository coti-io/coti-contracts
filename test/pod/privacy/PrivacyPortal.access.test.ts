import hre from "hardhat"
import { expect } from "chai"
import { parseEther, parseUnits } from "ethers"

describe("PrivacyPortal access controls", function () {
    async function deployPortalFixture() {
        const [owner, user, operator] = await hre.ethers.getSigners()
        const other = operator

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
            owner.address,
            await underlying.getAddress(),
            await pToken.getAddress(),
            6,
            false,
            await factory.getAddress()
        )

        const depositAmount = parseUnits("100", 6)
        await underlying.mint(user.address, depositAmount)

        return {
            owner,
            user,
            operator,
            other,
            factory,
            underlying,
            pToken,
            portal,
            depositAmount,
        }
    }

    async function deployFactoryFixture() {
        const [owner, operator, other] = await hre.ethers.getSigners()

        const PortalImpl = await hre.ethers.getContractFactory("PrivacyPortal")
        const portalImpl = await PortalImpl.deploy()
        await portalImpl.waitForDeployment()

        const PTokenImpl = await hre.ethers.getContractFactory("MockPodERC20ForPortal")
        const pTokenImpl = await PTokenImpl.deploy()
        await pTokenImpl.waitForDeployment()

        const Factory = await hre.ethers.getContractFactory("PrivacyPortalFactory")
        const factory = await Factory.deploy(
            owner.address,
            owner.address,
            7082400,
            other.address,
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

        return { owner, operator, other, factory }
    }

    async function deployNativePortalFixture() {
        const [owner, user] = await hre.ethers.getSigners()

        const MockFactory = await hre.ethers.getContractFactory("MockPrivacyPortalFactory")
        const wrappedNative = await hre.ethers.getContractFactory("MockWrappedNative")
        const weth = await wrappedNative.deploy("Wrapped Ether", "WETH")
        await weth.waitForDeployment()
        const wethAddress = await weth.getAddress()

        const factory = await MockFactory.deploy(owner.address, wethAddress)
        await factory.waitForDeployment()

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

        await portal.initialize(owner.address, wethAddress, await pToken.getAddress(), 18, true, await factory.getAddress())

        const depositAmount = parseEther("1")

        return { owner, user, factory, portal, depositAmount }
    }

    describe("portal per-tx limits", function () {
        it("reverts deposits below the configured minimum", async function () {
            const { owner, user, portal, underlying, factory, depositAmount } =
                await deployPortalFixture()

            await portal.connect(owner).setLimits(parseUnits("200", 6), parseUnits("1000", 6), 1, parseUnits("1000", 6))

            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, {
                    value: 1000,
                })
            ).to.be.revertedWithCustomError(portal, "DepositBelowMinimum")
        })

        it("reverts deposits above the configured maximum", async function () {
            const { owner, user, portal, underlying, factory, depositAmount } =
                await deployPortalFixture()

            await portal.connect(owner).setLimits(1, parseUnits("50", 6), 1, depositAmount)

            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, {
                    value: 1000,
                })
            ).to.be.revertedWithCustomError(portal, "DepositExceedsMaximum")
        })

        it("reverts withdrawals above the configured maximum", async function () {
            const { owner, user, portal, factory, depositAmount } = await deployPortalFixture()

            await portal.connect(owner).setLimits(1, depositAmount, 1, parseUnits("50", 6))

            await expect(
                portal.connect(user).requestWithdrawWithPermit(
                    user.address,
                    depositAmount,
                    0,
                    1000,
                    100,
                    Math.floor(Date.now() / 1000) + 3600,
                    27,
                    hre.ethers.ZeroHash,
                    hre.ethers.ZeroHash,
                    { value: 1000 }
                )
            ).to.be.revertedWithCustomError(portal, "WithdrawExceedsMaximum")
        })

        it("allows only the portal owner to update limits", async function () {
            const { owner, user, portal } = await deployPortalFixture()

            await expect(
                portal.connect(user).setLimits(1, 2, 3, 4)
            ).to.be.revertedWithCustomError(portal, "OwnableUnauthorizedAccount")

            await expect(portal.connect(owner).setLimits(1, 2, 3, 4)).to.not.be.reverted
        })

        it("reverts withdrawals below the configured minimum", async function () {
            const { owner, user, portal, depositAmount } = await deployPortalFixture()

            await portal.connect(owner).setLimits(1, depositAmount, parseUnits("200", 6), parseUnits("1000", 6))

            await expect(
                portal.connect(user).requestWithdrawWithPermit(
                    user.address,
                    depositAmount,
                    0,
                    1000,
                    100,
                    Math.floor(Date.now() / 1000) + 3600,
                    27,
                    hre.ethers.ZeroHash,
                    hre.ethers.ZeroHash,
                    { value: 1000 }
                )
            ).to.be.revertedWithCustomError(portal, "WithdrawBelowMinimum")
        })

        it("reverts native deposits below the configured minimum", async function () {
            const { owner, user, portal, depositAmount } = await deployNativePortalFixture()

            await portal.connect(owner).setLimits(parseEther("2"), parseEther("10"), 1, parseEther("10"))

            await expect(
                portal.connect(user).depositNative(user.address, depositAmount, 0, 100, {
                    value: depositAmount + 1000n,
                })
            ).to.be.revertedWithCustomError(portal, "DepositBelowMinimum")
        })

        it("reverts native deposits above the configured maximum", async function () {
            const { owner, user, portal, depositAmount } = await deployNativePortalFixture()

            await portal.connect(owner).setLimits(1, parseEther("0.5"), 1, parseEther("10"))

            await expect(
                portal.connect(user).depositNative(user.address, depositAmount, 0, 100, {
                    value: depositAmount + 1000n,
                })
            ).to.be.revertedWithCustomError(portal, "DepositExceedsMaximum")
        })
    })

    describe("factory blacklist", function () {
        it("blocks blacklisted users from depositing", async function () {
            const { owner, user, portal, underlying, factory, depositAmount } =
                await deployPortalFixture()

            await factory.connect(owner).setBlacklisted(user.address, true)
            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)

            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, {
                    value: 1000,
                })
            ).to.be.revertedWithCustomError(portal, "AddressBlacklisted")
        })

        it("allows the factory owner to add and remove blacklist entries", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()

            await factory.connect(owner).addToBlacklist(operator.address)
            expect(await factory.blacklisted(operator.address)).to.equal(true)

            await factory.connect(owner).removeFromBlacklist(operator.address)
            expect(await factory.blacklisted(operator.address)).to.equal(false)
        })

        it("allows deposits again after blacklist removal", async function () {
            const { owner, user, portal, underlying, factory, depositAmount } =
                await deployPortalFixture()

            await factory.connect(owner).setBlacklisted(user.address, true)
            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, {
                    value: 1000,
                })
            ).to.be.revertedWithCustomError(portal, "AddressBlacklisted")

            await factory.connect(owner).setBlacklisted(user.address, false)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, {
                    value: 1000,
                })
            ).to.not.be.reverted
        })
    })

    describe("factory admin vs operator", function () {
        it("lets operators update default fee configs", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()
            const operatorRole = await factory.OPERATOR_ROLE()

            await factory.connect(owner).grantRole(operatorRole, operator.address)
            await expect(
                factory.connect(operator).setDefaultDepositFee(1, 0, 100)
            ).to.not.be.reverted

            const config = await factory.getFeeConfig(true)
            expect(config.fixedFee).to.equal(1)
            expect(config.maxFee).to.equal(100)
        })

        it("lets operators update default withdraw fee configs", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()
            const operatorRole = await factory.OPERATOR_ROLE()

            await factory.connect(owner).grantRole(operatorRole, operator.address)
            await expect(
                factory.connect(operator).setDefaultWithdrawFee(2, 0, 200)
            ).to.not.be.reverted

            const config = await factory.getFeeConfig(false)
            expect(config.fixedFee).to.equal(2)
            expect(config.maxFee).to.equal(200)
        })

        it("rejects non-operators from updating default fee configs", async function () {
            const { other, factory } = await deployFactoryFixture()

            await expect(
                factory.connect(other).setDefaultDepositFee(1, 0, 100)
            ).to.be.revertedWithCustomError(factory, "AccessControlUnauthorizedAccount")
        })

        it("keeps blacklist management admin-only", async function () {
            const { owner, operator, other, factory } = await deployFactoryFixture()
            const operatorRole = await factory.OPERATOR_ROLE()

            await factory.connect(owner).grantRole(operatorRole, operator.address)
            await expect(
                factory.connect(operator).addToBlacklist(other.address)
            ).to.be.revertedWithCustomError(factory, "AccessControlUnauthorizedAccount")
        })

        it("exposes owner() as the primary DEFAULT_ADMIN_ROLE holder", async function () {
            const { owner, factory } = await deployFactoryFixture()

            expect(await factory.owner()).to.equal(owner.address)
        })

        it("lets admin set fee and rescue recipients", async function () {
            const { owner, operator, other, factory } = await deployFactoryFixture()

            await expect(factory.connect(owner).setFeeRecipient(other.address))
                .to.emit(factory, "FeeRecipientUpdated")
                .withArgs(owner.address, other.address)
            expect(await factory.feeRecipient()).to.equal(other.address)

            await expect(factory.connect(owner).setRescueRecipient(operator.address))
                .to.emit(factory, "RescueRecipientUpdated")
                .withArgs(owner.address, operator.address)
            expect(await factory.rescueRecipient()).to.equal(operator.address)

            await expect(
                factory.connect(operator).setRescueRecipient(other.address)
            ).to.be.revertedWithCustomError(factory, "AccessControlUnauthorizedAccount")
        })

        it("returns the first DEFAULT_ADMIN_ROLE holder when multiple admins exist", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()
            const adminRole = await factory.DEFAULT_ADMIN_ROLE()

            await factory.connect(owner).grantRole(adminRole, operator.address)
            expect(await factory.owner()).to.equal(owner.address)
        })
    })
})
