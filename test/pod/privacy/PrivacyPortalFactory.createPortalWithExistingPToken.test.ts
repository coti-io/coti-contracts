import hre from "hardhat"
import { expect } from "chai"
import { ZeroAddress } from "ethers"

describe("PrivacyPortalFactory.createPortalWithExistingPToken", function () {
    async function deployFactoryFixture() {
        const [owner, other, stranger] = await hre.ethers.getSigners()

        const MockInbox = await hre.ethers.getContractFactory("MockInbox")
        const inbox = await MockInbox.deploy()
        await inbox.waitForDeployment()

        const PortalImpl = await hre.ethers.getContractFactory("PrivacyPortal")
        const portalImpl = await PortalImpl.deploy()
        await portalImpl.waitForDeployment()

        const PTokenImpl = await hre.ethers.getContractFactory("PodErc20MintableInitializable")
        const pTokenImpl = await PTokenImpl.deploy()
        await pTokenImpl.waitForDeployment()

        const Factory = await hre.ethers.getContractFactory("PrivacyPortalFactory")
        const factory = await Factory.deploy(
            owner.address,
            await inbox.getAddress(),
            7082400,
            other.address, // cotiMother placeholder
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

        return {
            owner,
            stranger,
            inbox,
            factory,
            portalImpl,
            pTokenImpl,
            underlying,
            Factory,
            other,
        }
    }

    async function deploySecondFactory(
        fixture: Awaited<ReturnType<typeof deployFactoryFixture>>
    ) {
        const factory2 = await fixture.Factory.deploy(
            fixture.owner.address,
            await fixture.inbox.getAddress(),
            7082400,
            fixture.other.address,
            await fixture.pTokenImpl.getAddress(),
            await fixture.portalImpl.getAddress(),
            fixture.owner.address,
            fixture.owner.address,
            fixture.owner.address,
            hre.ethers.ZeroAddress,
            0,
            0,
            2n ** 128n - 1n,
            0,
            0,
            2n ** 128n - 1n
        )
        await factory2.waitForDeployment()
        return factory2
    }

    it("attaches an existing pToken to a new portal without TokenRegistrationRequested", async function () {
        const fixture = await deployFactoryFixture()
        const { factory, underlying } = fixture
        const factory2 = await deploySecondFactory(fixture)

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const oldPortal = await factory.portalForUnderlying(await underlying.getAddress())
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())
        expect(oldPortal).to.not.equal(ZeroAddress)
        expect(pTokenAddr).to.not.equal(ZeroAddress)

        const pToken = await hre.ethers.getContractAt("PodErc20MintableInitializable", pTokenAddr)
        expect(await pToken.minter()).to.equal(oldPortal)
        expect(await pToken.owner()).to.equal(await factory.getAddress())

        await factory.transferPTokenOwnership(pTokenAddr, await factory2.getAddress())
        expect(await pToken.owner()).to.equal(await factory2.getAddress())

        const tx = await factory2.createPortalWithExistingPToken(
            await underlying.getAddress(),
            pTokenAddr,
            false
        )
        await expect(tx).to.emit(factory2, "PortalCreated")
        await expect(tx).to.not.emit(factory2, "TokenRegistrationRequested")

        const newPortal = await factory2.portalForUnderlying(await underlying.getAddress())
        expect(newPortal).to.not.equal(ZeroAddress)
        expect(newPortal).to.not.equal(oldPortal)
        expect(await factory2.pTokenForUnderlying(await underlying.getAddress())).to.equal(pTokenAddr)
        expect(await factory2.portalForPToken(pTokenAddr)).to.equal(newPortal)
        expect(await pToken.minter()).to.equal(newPortal)

        const portal = await hre.ethers.getContractAt("PrivacyPortal", newPortal)
        expect(await portal.pToken()).to.equal(pTokenAddr)
        expect(await portal.underlyingToken()).to.equal(await underlying.getAddress())
        expect(await portal.factory()).to.equal(await factory2.getAddress())
        // First attach on factory2 still opens paused until admin migrates/opens.
        expect(await portal.paused()).to.equal(true)
    })

    it("reverts when caller is not admin", async function () {
        const fixture = await deployFactoryFixture()
        const { factory, underlying, stranger } = fixture
        const factory2 = await deploySecondFactory(fixture)

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())
        await factory.transferPTokenOwnership(pTokenAddr, await factory2.getAddress())

        await expect(
            factory2
                .connect(stranger)
                .createPortalWithExistingPToken(await underlying.getAddress(), pTokenAddr, false)
        ).to.be.reverted
    })

    it("reverts when factory does not own the pToken", async function () {
        const fixture = await deployFactoryFixture()
        const { factory, underlying } = fixture
        const factory2 = await deploySecondFactory(fixture)

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())

        await expect(
            factory2.createPortalWithExistingPToken(await underlying.getAddress(), pTokenAddr, false)
        )
            .to.be.revertedWithCustomError(factory2, "PTokenNotOwnedByFactory")
            .withArgs(pTokenAddr, await factory.getAddress())
    })

    it("remounts when underlying already has the same pToken paired", async function () {
        const fixture = await deployFactoryFixture()
        const { factory, underlying } = fixture

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())
        const oldPortalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        const oldPortal = await hre.ethers.getContractAt("PrivacyPortal", oldPortalAddr)

        const portalImplV2 = await (
            await hre.ethers.getContractFactory("PrivacyPortal")
        ).deploy()
        await portalImplV2.waitForDeployment()
        await factory.setPortalImplementation(await portalImplV2.getAddress())

        await expect(
            factory.createPortalWithExistingPToken(await underlying.getAddress(), pTokenAddr, false)
        )
            .to.be.revertedWithCustomError(factory, "OldPortalNotPaused")
            .withArgs(oldPortalAddr)

        await oldPortal.pause()
        await expect(
            factory.createPortalWithExistingPToken(await underlying.getAddress(), pTokenAddr, false)
        ).to.emit(factory, "PortalReplaced")

        const newPortalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        expect(newPortalAddr).to.not.equal(oldPortalAddr)
        expect(await factory.portalForPToken(pTokenAddr)).to.equal(newPortalAddr)
        const newPortal = await hre.ethers.getContractAt("PrivacyPortal", newPortalAddr)
        expect(await newPortal.paused()).to.equal(true)
    })

    it("reverts when pToken is paired but underlying does not match", async function () {
        const fixture = await deployFactoryFixture()
        const { factory, underlying } = fixture

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())

        const MockERC20 = await hre.ethers.getContractFactory("MockERC20")
        const underlying2 = await MockERC20.deploy("Mock USD 2", "mUSD2", 6)
        await underlying2.waitForDeployment()

        await expect(
            factory.createPortalWithExistingPToken(await underlying2.getAddress(), pTokenAddr, false)
        )
            .to.be.revertedWithCustomError(factory, "UnderlyingPTokenMismatch")
            .withArgs(await underlying2.getAddress(), ZeroAddress, pTokenAddr)
    })
})

describe("PodErc20Mintable.setMinter", function () {
    async function deployMintable() {
        const [owner, minter, newMinter, stranger] = await hre.ethers.getSigners()

        const MockInbox = await hre.ethers.getContractFactory("MockInbox")
        const inbox = await MockInbox.deploy()
        await inbox.waitForDeployment()

        const Token = await hre.ethers.getContractFactory("PodErc20Mintable")
        const token = await Token.deploy(
            minter.address,
            7082400,
            await inbox.getAddress(),
            stranger.address,
            "pMock",
            "pM"
        )
        await token.waitForDeployment()

        return { owner, minter, newMinter, stranger, token }
    }

    it("rotates minter when called by owner", async function () {
        const { owner, minter, newMinter, token } = await deployMintable()
        expect(await token.owner()).to.equal(owner.address)
        expect(await token.minter()).to.equal(minter.address)

        await expect(token.setMinter(newMinter.address))
            .to.emit(token, "MinterUpdated")
            .withArgs(minter.address, newMinter.address)
        expect(await token.minter()).to.equal(newMinter.address)
    })

    it("reverts setMinter for non-owner", async function () {
        const { stranger, newMinter, token } = await deployMintable()
        await expect(token.connect(stranger).setMinter(newMinter.address)).to.be.reverted
    })

    it("reverts setMinter to zero address", async function () {
        const { token } = await deployMintable()
        await expect(token.setMinter(ZeroAddress)).to.be.revertedWithCustomError(
            token,
            "PodErc20MintableInvalidMinter"
        )
    })
})
