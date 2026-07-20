import hre from "hardhat"
import { expect } from "chai"
import { parseUnits } from "ethers"

describe("PrivacyPortal measured-received mint (PP-06)", function () {
    async function deployFixture() {
        const [owner, user] = await hre.ethers.getSigners()

        const MockFactory = await hre.ethers.getContractFactory("MockPrivacyPortalFactory")
        const factory = await MockFactory.deploy(owner.address, owner.address)
        await factory.waitForDeployment()

        const MockFeeOnTransferERC20 = await hre.ethers.getContractFactory("MockFeeOnTransferERC20")
        // 5% fee taken on every transferFrom.
        const underlying = await MockFeeOnTransferERC20.deploy("Fee Token", "FEE", 6, 500)
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

        return { owner, user, factory, underlying, pToken, portal, amount }
    }

    it("mints the measured received amount, not the requested amount, for a fee-on-transfer underlying", async function () {
        const { user, underlying, pToken, portal, amount } = await deployFixture()

        const feeBps = await underlying.feeBps()
        const expectedReceived = amount - (amount * feeBps) / 10_000n
        expect(expectedReceived).to.be.lessThan(amount)

        const tx = await portal.connect(user).deposit(user.address, amount, 0, 100, { value: 1000 })
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

        expect(depositLog!.args.amount).to.equal(expectedReceived)
        expect(await pToken.lastMintAmount()).to.equal(expectedReceived)
        expect(await underlying.balanceOf(await portal.getAddress())).to.equal(expectedReceived)

        const escrow = await portal.depositEscrows(requestId)
        expect(escrow.amount).to.equal(expectedReceived)

        const feesLog = receipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "OperationFeesPaid")
        expect(feesLog!.args.amount).to.equal(expectedReceived)
    })

    it("reverts with NoUnderlyingReceived when the fee-on-transfer token swallows the entire deposit", async function () {
        const { user, underlying, portal, amount } = await deployFixture()

        await underlying.setFeeBps(10_000) // 100% fee: portal receives nothing.

        await expect(
            portal.connect(user).deposit(user.address, amount, 0, 100, { value: 1000 })
        ).to.be.revertedWithCustomError(portal, "NoUnderlyingReceived")
    })
})
