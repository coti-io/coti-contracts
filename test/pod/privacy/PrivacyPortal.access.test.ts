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

        await portal.initialize(wethAddress, await pToken.getAddress(), 18, true, await factory.getAddress())

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

        it("allows only the factory admin to update limits", async function () {
            const { owner, user, portal } = await deployPortalFixture()

            await expect(
                portal.connect(user).setLimits(1, 2, 3, 4)
            ).to.be.revertedWithCustomError(portal, "OnlyFactoryAdmin")

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

        it("lets admin set rescue recipient (fee recipient is immutable)", async function () {
            const { owner, operator, other, factory } = await deployFactoryFixture()

            expect(await factory.feeRecipient()).to.equal(owner.address)

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

    describe("pause (instance then factory)", function () {
        it("lets portal owner pause only that instance", async function () {
            const { owner, user, portal, underlying, depositAmount } = await deployPortalFixture()

            await portal.connect(owner).pause()
            expect(await portal.paused()).to.equal(true)

            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.be.revertedWithCustomError(portal, "DepositsPaused")

            await expect(
                portal.connect(user).requestWithdrawWithPermit(
                    user.address,
                    1,
                    0,
                    1000,
                    100,
                    999_999_999,
                    27,
                    hre.ethers.ZeroHash,
                    hre.ethers.ZeroHash,
                    { value: 1000 }
                )
            ).to.be.revertedWithCustomError(portal, "WithdrawalsPaused")
        })

        it("rejects non-admin portal pause", async function () {
            const { user, portal } = await deployPortalFixture()
            await expect(portal.connect(user).pause()).to.be.revertedWithCustomError(
                portal,
                "OnlyFactoryAdmin"
            )
        })

        it("factory pause pauses deposits and withdrawals on portals", async function () {
            const { owner, user, portal, underlying, factory, depositAmount } =
                await deployPortalFixture()

            await factory.connect(owner).pause()
            expect(await factory.paused()).to.equal(true)
            expect(await factory.depositsPaused()).to.equal(true)
            expect(await factory.withdrawalsPaused()).to.equal(true)

            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.be.revertedWithCustomError(portal, "DepositsPaused")

            await expect(
                portal.connect(user).requestWithdrawWithPermit(
                    user.address,
                    1,
                    0,
                    1000,
                    100,
                    999_999_999,
                    27,
                    hre.ethers.ZeroHash,
                    hre.ethers.ZeroHash,
                    { value: 1000 }
                )
            ).to.be.revertedWithCustomError(portal, "WithdrawalsPaused")
        })

        it("rejects non-admin factory pause", async function () {
            const { operator, factory } = await deployFactoryFixture()
            await expect(factory.connect(operator).pause()).to.be.revertedWithCustomError(
                factory,
                "AccessControlUnauthorizedAccount"
            )
        })

        it("unpausing the instance restores entry points when factory is not paused", async function () {
            const { owner, user, portal, underlying, depositAmount } = await deployPortalFixture()

            await portal.connect(owner).pause()
            await portal.connect(owner).unpause()
            expect(await portal.paused()).to.equal(false)

            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.not.be.reverted
        })

        it("instance unpause does not clear factory pause", async function () {
            const { owner, user, portal, underlying, factory, depositAmount } =
                await deployPortalFixture()

            await factory.connect(owner).pause()
            await portal.connect(owner).pause()
            await portal.connect(owner).unpause()

            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.be.revertedWithCustomError(portal, "DepositsPaused")
        })
    })

    describe("portal fee overrides", function () {
        it("requires factory operator for portal fee overrides", async function () {
            const { owner, user, operator, portal, factory } = await deployPortalFixture()

            await expect(
                portal.connect(user).setDepositFee(1, 0, 100)
            ).to.be.revertedWithCustomError(portal, "OnlyFactoryOperator")

            await factory.connect(owner).setOperator(operator.address, true)
            await expect(portal.connect(operator).setDepositFee(1, 0, 100)).to.not.be.reverted

            const config = await portal.getFeeConfig(true)
            expect(config.fixedFee).to.equal(1)
            expect(config.maxFee).to.equal(100)
        })

        it("overrides deposit and withdraw fees and clears back to factory defaults", async function () {
            const { owner, operator, portal, factory } = await deployPortalFixture()
            await factory.connect(owner).setDefaultDepositFee(5, 0, 50)
            await factory.connect(owner).setDefaultWithdrawFee(7, 0, 70)
            await factory.connect(owner).setOperator(operator.address, true)

            await portal.connect(operator).setDepositFee(11, 0, 110)
            await portal.connect(operator).setWithdrawFee(13, 0, 130)

            expect((await portal.getFeeConfig(true)).fixedFee).to.equal(11)
            expect((await portal.getFeeConfig(false)).fixedFee).to.equal(13)

            const [depositOverride, depositSet] = await portal.getFeeConfigOverride(true)
            expect(depositSet).to.equal(true)
            expect(depositOverride.fixedFee).to.equal(11)

            await portal.connect(operator).clearDepositFeeOverride()
            await portal.connect(operator).clearWithdrawFeeOverride()

            expect((await portal.getFeeConfig(true)).fixedFee).to.equal(5)
            expect((await portal.getFeeConfig(false)).fixedFee).to.equal(7)
            const [, cleared] = await portal.getFeeConfigOverride(true)
            expect(cleared).to.equal(false)
        })

        it("lets factory operator toggle soft deposit enable", async function () {
            const { owner, user, operator, portal, underlying, factory, depositAmount } =
                await deployPortalFixture()

            await factory.connect(owner).setOperator(operator.address, true)
            await portal.connect(operator).setIsDepositEnabled(false)

            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.be.revertedWithCustomError(portal, "DepositDisabled")

            await portal.connect(operator).setIsDepositEnabled(true)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.not.be.reverted
        })
    })

    describe("factory configs", function () {
        it("updates default deposit and withdraw fee configs as operator", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()
            const operatorRole = await factory.OPERATOR_ROLE()
            await factory.connect(owner).grantRole(operatorRole, operator.address)

            await factory.connect(operator).setDefaultDepositFee(3, 100, 300)
            await factory.connect(operator).setDefaultWithdrawFee(4, 200, 400)

            const deposit = await factory.getFeeConfig(true)
            expect(deposit.fixedFee).to.equal(3)
            expect(deposit.percentageBps).to.equal(100)
            expect(deposit.maxFee).to.equal(300)

            const withdraw = await factory.getFeeConfig(false)
            expect(withdraw.fixedFee).to.equal(4)
            expect(withdraw.percentageBps).to.equal(200)
            expect(withdraw.maxFee).to.equal(400)
        })

        it("updates rescue recipient as admin only; fee recipient is immutable", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()

            expect(await factory.feeRecipient()).to.equal(owner.address)
            await factory.connect(owner).setRescueRecipient(operator.address)
            expect(await factory.rescueRecipient()).to.equal(operator.address)

            await expect(
                factory.connect(operator).setRescueRecipient(owner.address)
            ).to.be.revertedWithCustomError(factory, "AccessControlUnauthorizedAccount")
        })

        it("updates price oracle as admin", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()

            await expect(factory.connect(owner).setPriceOracle(operator.address))
                .to.emit(factory, "PriceOracleUpdated")
            expect(await factory.priceOracle()).to.equal(operator.address)
        })

        it("exposes isOperator for factory OPERATOR_ROLE", async function () {
            const { owner, operator, factory } = await deployFactoryFixture()
            expect(await factory.isOperator(owner.address)).to.equal(true)
            expect(await factory.isOperator(operator.address)).to.equal(false)

            const operatorRole = await factory.OPERATOR_ROLE()
            await factory.connect(owner).grantRole(operatorRole, operator.address)
            expect(await factory.isOperator(operator.address)).to.equal(true)
        })
    })

    describe("factory roles propagate to all portals", function () {
        async function deployTwoPortalsFixture() {
            const [owner, user, operator, newAdmin] = await hre.ethers.getSigners()

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
                newAdmin.address,
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
            const underlyingA = await MockERC20.deploy("Token A", "AAA", 6)
            await underlyingA.waitForDeployment()
            const underlyingB = await MockERC20.deploy("Token B", "BBB", 6)
            await underlyingB.waitForDeployment()

            const pTokenA = await PTokenImpl.deploy()
            await pTokenA.waitForDeployment()
            const pTokenB = await PTokenImpl.deploy()
            await pTokenB.waitForDeployment()

            const CloneHelper = await hre.ethers.getContractFactory("CloneHelper")
            const cloneHelper = await CloneHelper.deploy()
            await cloneHelper.waitForDeployment()

            await cloneHelper.clone(await portalImpl.getAddress())
            const portalA = PortalImpl.attach(await cloneHelper.lastClone()) as Awaited<
                ReturnType<typeof PortalImpl.deploy>
            >
            await portalA.initialize(
                await underlyingA.getAddress(),
                await pTokenA.getAddress(),
                6,
                false,
                await factory.getAddress()
            )

            await cloneHelper.clone(await portalImpl.getAddress())
            const portalB = PortalImpl.attach(await cloneHelper.lastClone()) as Awaited<
                ReturnType<typeof PortalImpl.deploy>
            >
            await portalB.initialize(
                await underlyingB.getAddress(),
                await pTokenB.getAddress(),
                6,
                false,
                await factory.getAddress()
            )

            return { owner, user, operator, newAdmin, factory, portalA, portalB }
        }

        it("respects factory admin on every portal and updates after admin transfer", async function () {
            const { owner, user, newAdmin, factory, portalA, portalB } = await deployTwoPortalsFixture()
            const adminRole = await factory.DEFAULT_ADMIN_ROLE()

            expect(await factory.isAdmin(owner.address)).to.equal(true)
            expect(await factory.isAdmin(newAdmin.address)).to.equal(false)

            // Non-admin cannot pause either portal.
            await expect(portalA.connect(user).pause()).to.be.revertedWithCustomError(
                portalA,
                "OnlyFactoryAdmin"
            )
            await expect(portalB.connect(user).pause()).to.be.revertedWithCustomError(
                portalB,
                "OnlyFactoryAdmin"
            )

            // Current factory admin can admin both portals.
            await portalA.connect(owner).setLimits(1, 100, 1, 100)
            await portalB.connect(owner).setLimits(2, 200, 2, 200)
            expect(await portalA.minDepositAmount()).to.equal(1)
            expect(await portalB.minDepositAmount()).to.equal(2)

            // Grant + revoke DEFAULT_ADMIN_ROLE on the factory — both portals follow immediately.
            await factory.connect(owner).grantRole(adminRole, newAdmin.address)
            await factory.connect(owner).revokeRole(adminRole, owner.address)
            expect(await factory.isAdmin(owner.address)).to.equal(false)
            expect(await factory.isAdmin(newAdmin.address)).to.equal(true)

            await expect(portalA.connect(owner).pause()).to.be.revertedWithCustomError(
                portalA,
                "OnlyFactoryAdmin"
            )
            await expect(portalB.connect(owner).setLimits(9, 99, 9, 99)).to.be.revertedWithCustomError(
                portalB,
                "OnlyFactoryAdmin"
            )

            await portalA.connect(newAdmin).pause()
            await portalB.connect(newAdmin).pause()
            expect(await portalA.paused()).to.equal(true)
            expect(await portalB.paused()).to.equal(true)

            await portalA.connect(newAdmin).unpause()
            await portalB.connect(newAdmin).unpause()
            await portalA.connect(newAdmin).addToBlacklist(user.address)
            await portalB.connect(newAdmin).addToBlacklist(user.address)
            expect(await portalA.blacklisted(user.address)).to.equal(true)
            expect(await portalB.blacklisted(user.address)).to.equal(true)
        })

        it("respects factory operator on every portal and updates after operator revoke/grant", async function () {
            const { owner, user, operator, factory, portalA, portalB } = await deployTwoPortalsFixture()
            const operatorRole = await factory.OPERATOR_ROLE()

            // Initial operator is constructor admin (owner); outsider cannot toggle soft deposits.
            await expect(
                portalA.connect(user).setIsDepositEnabled(false)
            ).to.be.revertedWithCustomError(portalA, "OnlyFactoryOperator")
            await expect(
                portalB.connect(operator).setDepositFee(1, 0, 10)
            ).to.be.revertedWithCustomError(portalB, "OnlyFactoryOperator")

            await factory.connect(owner).grantRole(operatorRole, operator.address)
            expect(await factory.isOperator(operator.address)).to.equal(true)

            await portalA.connect(operator).setIsDepositEnabled(false)
            await portalB.connect(operator).setIsDepositEnabled(false)
            expect(await portalA.isDepositEnabled()).to.equal(false)
            expect(await portalB.isDepositEnabled()).to.equal(false)

            await portalA.connect(operator).setDepositFee(5, 0, 50)
            await portalB.connect(operator).setWithdrawFee(7, 0, 70)
            expect((await portalA.getFeeConfigOverride(true))[1]).to.equal(true)
            expect((await portalB.getFeeConfigOverride(false))[1]).to.equal(true)

            // Revoke OPERATOR_ROLE — both portals reject the former operator immediately.
            await factory.connect(owner).revokeRole(operatorRole, operator.address)
            expect(await factory.isOperator(operator.address)).to.equal(false)

            await expect(
                portalA.connect(operator).setIsDepositEnabled(true)
            ).to.be.revertedWithCustomError(portalA, "OnlyFactoryOperator")
            await expect(
                portalB.connect(operator).clearDepositFeeOverride()
            ).to.be.revertedWithCustomError(portalB, "OnlyFactoryOperator")

            // Owner (still OPERATOR_ROLE from constructor) can clear overrides on both.
            await portalA.connect(owner).clearDepositFeeOverride()
            await portalB.connect(owner).clearWithdrawFeeOverride()
            expect((await portalA.getFeeConfigOverride(true))[1]).to.equal(false)
            expect((await portalB.getFeeConfigOverride(false))[1]).to.equal(false)
        })
    })

    describe("portal factory-admin actions", function () {
        it("lets factory admin manage portal blacklist independently of factory blacklist", async function () {
            const { owner, user, portal, underlying, depositAmount } = await deployPortalFixture()

            await portal.connect(owner).addToBlacklist(user.address)
            await underlying.connect(user).approve(await portal.getAddress(), depositAmount)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.be.revertedWithCustomError(portal, "AddressBlacklisted")

            await portal.connect(owner).removeFromBlacklist(user.address)
            await expect(
                portal.connect(user).deposit(user.address, depositAmount, 0, 100, { value: 1000 })
            ).to.not.be.reverted
        })
    })
})
