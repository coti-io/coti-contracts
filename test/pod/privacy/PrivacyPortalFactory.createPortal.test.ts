import hre from "hardhat"
import { expect } from "chai"

describe("PrivacyPortalFactory.createPortal decimals validation (PP-13)", function () {
    async function deployFixture() {
        const [owner, other] = await hre.ethers.getSigners()

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
            other.address, // cotiMotherContract placeholder; never called in this suite.
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
        const underlying6 = await MockERC20.deploy("Mock USD", "mUSD", 6)
        await underlying6.waitForDeployment()

        return { owner, other, factory, underlying6 }
    }

    it("reverts when the requested decimals do not match the underlying token", async function () {
        const { factory, underlying6 } = await deployFixture()

        await expect(
            factory.createPortal(await underlying6.getAddress(), "pMockUSD", "pmUSD", 18, false)
        ).to.be.revertedWithCustomError(factory, "DecimalsMismatch").withArgs(6, 18)
    })

    it("reverts when the requested decimals exceed the supported maximum", async function () {
        const { factory, underlying6 } = await deployFixture()
        const maxDecimals = await factory.MAX_DECIMALS()

        await expect(
            factory.createPortal(await underlying6.getAddress(), "pMockUSD", "pmUSD", 19, false)
        ).to.be.revertedWithCustomError(factory, "DecimalsExceedsMaximum").withArgs(19, maxDecimals)
    })

    it("creates the portal when decimals match the underlying token", async function () {
        const { factory, underlying6 } = await deployFixture()

        const tx = await factory.createPortal(await underlying6.getAddress(), "pMockUSD", "pmUSD", 6, false)
        await expect(tx).to.emit(factory, "PortalCreated")

        const portalAddress = await factory.portalForUnderlying(await underlying6.getAddress())
        expect(portalAddress).to.not.equal(hre.ethers.ZeroAddress)
    })
})
