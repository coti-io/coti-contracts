import hre from "hardhat"
import { expect } from "chai"
import { ZeroAddress } from "ethers"

describe("PrivacyPortalFactory pToken admin forwarders", function () {
    async function deployFactoryFixture() {
        const [owner, stranger] = await hre.ethers.getSigners()

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

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false)
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())
        const portalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        const pToken = await hre.ethers.getContractAt("PodErc20MintableInitializable", pTokenAddr)

        return { owner, stranger, factory, pToken, pTokenAddr, portalAddr, inbox }
    }

    it("admin can setPTokenMinter; non-admin and unknown pToken revert", async function () {
        const { factory, stranger, pToken, pTokenAddr, portalAddr } = await deployFactoryFixture()
        expect(await pToken.minter()).to.equal(portalAddr)

        const portal = await hre.ethers.getContractAt("PrivacyPortal", portalAddr)
        await expect(factory.setPTokenMinter(pTokenAddr, stranger.address))
            .to.be.revertedWithCustomError(factory, "OldPortalNotPaused")
            .withArgs(portalAddr)

        await portal.pause()
        const newMinter = stranger.address
        await factory.setPTokenMinter(pTokenAddr, newMinter)
        expect(await pToken.minter()).to.equal(newMinter)

        await expect(factory.connect(stranger).setPTokenMinter(pTokenAddr, portalAddr)).to.be.reverted
        await expect(factory.setPTokenMinter(ZeroAddress, portalAddr))
            .to.be.revertedWithCustomError(factory, "UnknownPToken")
            .withArgs(ZeroAddress)
    })

    it("admin can setPTokenRequestKillMinAge; non-admin and unknown pToken revert", async function () {
        const { factory, stranger, pToken, pTokenAddr } = await deployFactoryFixture()
        expect(await pToken.requestKillMinAge()).to.equal(86400n)

        await factory.setPTokenRequestKillMinAge(pTokenAddr, 0)
        expect(await pToken.requestKillMinAge()).to.equal(0n)

        await expect(factory.connect(stranger).setPTokenRequestKillMinAge(pTokenAddr, 1)).to.be.reverted
        await expect(factory.setPTokenRequestKillMinAge(ZeroAddress, 1))
            .to.be.revertedWithCustomError(factory, "UnknownPToken")
            .withArgs(ZeroAddress)
    })

    it("admin can killPTokenStaleRequest after age gate; direct onlyOwner and non-admin fail", async function () {
        const { owner, stranger, factory, pToken, pTokenAddr } = await deployFactoryFixture()

        // Direct EOA call fails while factory owns the token.
        await expect(pToken.connect(owner).setRequestKillMinAge(0)).to.be.reverted

        await factory.setPTokenRequestKillMinAge(pTokenAddr, 0)

        await owner.sendTransaction({ to: pTokenAddr, value: 1000n })
        const syncTx = await pToken.syncBalances([owner.address], 100n, { value: 1000n })
        const syncReceipt = await syncTx.wait()
        const syncLog = syncReceipt!.logs
            .map((log) => {
                try {
                    return pToken.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "SyncBalancesRequested")
        const requestId = syncLog!.args.requestId as string

        expect((await pToken.requests(requestId)).status).to.equal(1n) // Pending

        await expect(pToken.connect(owner).killStaleRequest(requestId)).to.be.reverted
        await expect(factory.connect(stranger).killPTokenStaleRequest(pTokenAddr, requestId)).to.be
            .reverted

        await expect(factory.killPTokenStaleRequest(pTokenAddr, requestId))
            .to.emit(pToken, "StaleRequestKilled")
            .withArgs(requestId, ZeroAddress, ZeroAddress)

        expect((await pToken.requests(requestId)).status).to.equal(3n) // Failed

        await expect(factory.killPTokenStaleRequest(ZeroAddress, requestId))
            .to.be.revertedWithCustomError(factory, "UnknownPToken")
            .withArgs(ZeroAddress)
    })

    it("honors requestKillMinAge before factory kill", async function () {
        const { owner, factory, pToken, pTokenAddr } = await deployFactoryFixture()
        // Default min age is 1 day.
        await owner.sendTransaction({ to: pTokenAddr, value: 1000n })
        const syncTx = await pToken.syncBalances([owner.address], 100n, { value: 1000n })
        const syncReceipt = await syncTx.wait()
        const syncLog = syncReceipt!.logs
            .map((log) => {
                try {
                    return pToken.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "SyncBalancesRequested")
        const requestId = syncLog!.args.requestId as string

        await expect(factory.killPTokenStaleRequest(pTokenAddr, requestId)).to.be.revertedWithCustomError(
            pToken,
            "RequestNotAged"
        )

        await hre.network.provider.send("evm_increaseTime", [86400])
        await hre.network.provider.send("evm_mine")

        await expect(factory.killPTokenStaleRequest(pTokenAddr, requestId)).to.emit(
            pToken,
            "StaleRequestKilled"
        )
    })

    it("renounceOwnership on pToken always reverts", async function () {
        const { pToken } = await deployFactoryFixture()
        await expect(pToken.renounceOwnership()).to.be.revertedWithCustomError(
            pToken,
            "OwnershipCannotBeRenounced"
        )
    })

    it("forwarders revert after transferPTokenOwnership handoff", async function () {
        const { factory, stranger, pTokenAddr, portalAddr } = await deployFactoryFixture()
        await expect(factory.transferPTokenOwnership(pTokenAddr, stranger.address))
            .to.be.revertedWithCustomError(factory, "OldPortalNotPaused")
            .withArgs(portalAddr)
        const portal = await hre.ethers.getContractAt("PrivacyPortal", portalAddr)
        await portal.pause()
        await factory.transferPTokenOwnership(pTokenAddr, stranger.address)
        expect(await factory.portalForPToken(pTokenAddr)).to.equal(ZeroAddress)
        expect(await portal.factory()).to.equal(ZeroAddress)
        await expect(portal.unpause()).to.be.revertedWithCustomError(portal, "FactoryNotConfigured")
        await expect(factory.setPTokenRequestKillMinAge(pTokenAddr, 0))
            .to.be.revertedWithCustomError(factory, "UnknownPToken")
            .withArgs(pTokenAddr)
    })

    it("configureRouting requires inbox code; mother may be a remote-chain address", async function () {
        const { factory, stranger, inbox } = await deployFactoryFixture()
        await expect(factory.configureRouting(stranger.address, 7082400, stranger.address))
            .to.be.revertedWithCustomError(factory, "ImplementationHasNoCode")
            .withArgs(stranger.address)
        await expect(factory.configureRouting(await inbox.getAddress(), 7082400, stranger.address)).to.not.be
            .reverted
        expect(await factory.inbox()).to.equal(await inbox.getAddress())
        expect(await factory.cotiMotherContract()).to.equal(stranger.address)
    })

    it("admin can rescue native stranded on a factory-owned pToken", async function () {
        const { owner, factory, pTokenAddr } = await deployFactoryFixture()
        await owner.sendTransaction({ to: pTokenAddr, value: 500n })
        const before = await hre.ethers.provider.getBalance(owner.address)
        const tx = await factory.rescuePTokenNative(pTokenAddr, owner.address, 500n)
        const receipt = await tx.wait()
        const gas = receipt!.gasUsed * receipt!.gasPrice
        expect(await hre.ethers.provider.getBalance(pTokenAddr)).to.equal(0n)
        expect(await hre.ethers.provider.getBalance(owner.address)).to.equal(before - gas + 500n)
    })
})
