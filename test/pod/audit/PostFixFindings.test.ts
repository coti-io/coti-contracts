/**
 * Red PoCs for POST_FIX_INBOX_AUDIT_2026-08-13.md (coti-contracts / PoD surface).
 * Each test states the safe behavior and currently FAILS on HEAD.
 */
import fs from "node:fs"
import path from "node:path"
import hre from "hardhat"
import { expect } from "chai"
import { ZeroAddress, ZeroHash, id } from "ethers"

/** Hardhat config `gas: 60e6` exceeds the 16M tx gas cap on this node. */
const txGas = { gasLimit: 15_000_000 }

describe("Audit findings (pod) — expected to FAIL until fixed", function () {
    it("M1: onDefaultMpcError must match inbox errorSelector(bytes) encoding", async function () {
        const factory = await hre.ethers.getContractFactory("PodAdder128")
        const shipped = factory.interface.getFunction("onDefaultMpcError")
        expect(shipped, "onDefaultMpcError must exist").to.not.equal(null)
        const inboxSelector = id("onDefaultMpcError(bytes)").slice(0, 10)
        expect(shipped!.selector.toLowerCase()).to.equal(
            inboxSelector.toLowerCase(),
            "inbox delivers errorSelector(bytes); shipped handler is a different selector"
        )
        expect(shipped!.inputs[0].type).to.equal("bytes")
    })

    it("M3: transferWithAllowance(gtUint128,gtUint8,gtUint8,gtUint32) must tag allowance as SUINT32_T", function () {
        const srcPath = path.join(__dirname, "../../../contracts/utils/mpc/MpcCore.sol")
        const src = fs.readFileSync(srcPath, "utf8")
        const sig =
            "function transferWithAllowance(gtUint128 a, gtUint8 b, gtUint8 amount, gtUint32 allowance)"
        const start = src.indexOf(sig)
        expect(start).to.be.greaterThan(-1, "overload missing from MpcCore.sol")
        const chunk = src.slice(start, start + 800)
        const enums = chunk.match(/combineEnumsToBytes5\(([^)]+)\)/)
        expect(enums, "precompile enum pack missing").to.not.equal(null)
        const parts = enums![1].split(",").map((s) => s.trim())
        // 4th MPC_TYPE is the allowance operand; Solidity argument is gtUint32.
        expect(parts[3]).to.match(/SUINT32_T/)
        expect(parts[3]).to.not.match(/SUINT8_T/)
    })

    async function deployMintableWithMockInbox() {
        const [owner, attacker] = await hre.ethers.getSigners()
        const MockInbox = await hre.ethers.getContractFactory("MockInbox")
        const inbox = await MockInbox.deploy(txGas)
        await inbox.waitForDeployment()
        const PToken = await hre.ethers.getContractFactory("PodErc20Mintable")
        const pToken = await PToken.deploy(
            owner.address,
            7082400,
            await inbox.getAddress(),
            owner.address,
            "Private USD",
            "pUSD",
            txGas
        )
        await pToken.waitForDeployment()
        await owner.sendTransaction({
            to: await pToken.getAddress(),
            value: hre.ethers.parseEther("0.01"),
            ...txGas,
        })
        return { owner, attacker, inbox, pToken }
    }

    it("L2: public mint to address(0) must revert before paying inbox fees", async function () {
        const { pToken, inbox } = await deployMintableWithMockInbox()
        const sentBefore = await inbox.sentCount()
        await expect(
            pToken["mint(address,uint256,uint256)"](ZeroAddress, 1n, 1n, { value: 1000n, ...txGas })
        ).to.be.reverted
        expect(await inbox.sentCount()).to.equal(sentBefore)
    })

    it("L5: mintable implementation must not expose setMinter to its deployer", async function () {
        const [deployer, attacker] = await hre.ethers.getSigners()
        const Impl = await hre.ethers.getContractFactory("PodErc20MintableInitializable")
        const impl = await Impl.deploy(txGas)
        await impl.waitForDeployment()
        await expect(impl.connect(deployer).setMinter(attacker.address, txGas)).to.be.reverted
    })
})

describe("Audit finding M2 — remount with in-flight withdrawal", function () {
    async function deployFixture() {
        const [owner, user] = await hre.ethers.getSigners()

        const MockInbox = await hre.ethers.getContractFactory("MockInbox")
        const inbox = await MockInbox.deploy(txGas)
        await inbox.waitForDeployment()

        const PortalImpl = await hre.ethers.getContractFactory("PrivacyPortal")
        const portalImpl = await PortalImpl.deploy(txGas)
        await portalImpl.waitForDeployment()

        const PTokenImpl = await hre.ethers.getContractFactory("MockPodErc20MintableForPortal")
        const pTokenImpl = await PTokenImpl.deploy(txGas)
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
            2n ** 128n - 1n,
            txGas
        )
        await factory.waitForDeployment()

        const MockERC20 = await hre.ethers.getContractFactory("MockERC20")
        const underlying = await MockERC20.deploy("Mock USD", "mUSD", 6, txGas)
        await underlying.waitForDeployment()
        const amount = 100n * 10n ** 6n
        await underlying.mint(user.address, amount * 10n, txGas)

        await factory.createPortal(await underlying.getAddress(), "pMockUSD", "pmUSD", 6, false, txGas)
        const portalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        const pTokenAddr = await factory.pTokenForUnderlying(await underlying.getAddress())
        const portal = await hre.ethers.getContractAt("PrivacyPortal", portalAddr)
        const pToken = await hre.ethers.getContractAt("MockPodErc20MintableForPortal", pTokenAddr)
        return { owner, user, factory, underlying, amount, portal, pToken, portalAddr, pTokenAddr }
    }

    it("M2: remount must revert while a withdrawal is TransferPending", async function () {
        const { factory, underlying, user, amount, portal, portalAddr, pTokenAddr } =
            await deployFixture()

        await underlying.connect(user).approve(portalAddr, amount, txGas)
        await portal.connect(user).deposit(user.address, amount, 0, 100, { value: 1000, ...txGas })

        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600)
        await portal.connect(user).requestWithdrawWithPermit(
            user.address,
            amount,
            0,
            1000,
            100,
            deadline,
            27,
            ZeroHash,
            ZeroHash,
            { value: 1000, ...txGas }
        )

        await portal.pause(txGas)
        await expect(
            factory.createPortalWithExistingPToken(
                await underlying.getAddress(),
                pTokenAddr,
                false,
                txGas
            )
        ).to.be.reverted
    })

    it("M2: after remount+rescue, late Success on the old portal must still pay the user", async function () {
        const { owner, factory, underlying, user, amount, portal, pToken, portalAddr, pTokenAddr } =
            await deployFixture()

        await underlying.connect(user).approve(portalAddr, amount, txGas)
        await portal.connect(user).deposit(user.address, amount, 0, 100, { value: 1000, ...txGas })

        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600)
        const withdrawTx = await portal.connect(user).requestWithdrawWithPermit(
            user.address,
            amount,
            0,
            1000,
            100,
            deadline,
            27,
            ZeroHash,
            ZeroHash,
            { value: 1000, ...txGas }
        )
        const withdrawReceipt = await withdrawTx.wait()
        const withdrawLog = withdrawReceipt!.logs
            .map((log) => {
                try {
                    return portal.interface.parseLog(log)
                } catch {
                    return null
                }
            })
            .find((parsed) => parsed?.name === "WithdrawalRequested")
        const withdrawalId = withdrawLog!.args.withdrawalId as string

        await portal.pause(txGas)
        await factory.createPortalWithExistingPToken(
            await underlying.getAddress(),
            pTokenAddr,
            false,
            txGas
        )
        const newPortalAddr = await factory.portalForUnderlying(await underlying.getAddress())
        const oldBal = await underlying.balanceOf(portalAddr)
        await portal.connect(owner).rescueERC20(await underlying.getAddress(), oldBal, txGas)
        await underlying.connect(owner).transfer(newPortalAddr, oldBal, txGas)

        await pToken.markLastTransferSuccessful(txGas)
        const before = await underlying.balanceOf(user.address)
        await expect(portal.triggerWithdrawalRelease(withdrawalId, txGas)).to.emit(
            portal,
            "WithdrawalReleased"
        )
        expect(await underlying.balanceOf(user.address)).to.equal(before + amount)
    })
})
