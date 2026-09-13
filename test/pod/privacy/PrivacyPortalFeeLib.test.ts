import { expect } from "chai"
import hre from "hardhat"

describe("PrivacyPortalFeeLib resolvePortalFee", function () {
    async function deployHarness() {
        const Harness = await hre.ethers.getContractFactory("PrivacyPortalFeeLibHarness")
        const harness = await Harness.deploy()
        await harness.waitForDeployment()
        return harness
    }

    it("reverts ZeroUsdRate when percentageBps is set and a USD rate is zero", async function () {
        const harness = await deployHarness()
        const packed = await harness.packFeeConfig(1n, 100n, 1000n)
        await expect(harness.resolvePortalFee(packed, 1_000_000n, 6, 0n, 10n ** 18n)).to.be.revertedWithCustomError(
            harness,
            "ZeroUsdRate"
        )
        await expect(harness.resolvePortalFee(packed, 1_000_000n, 6, 10n ** 18n, 0n)).to.be.revertedWithCustomError(
            harness,
            "ZeroUsdRate"
        )
    })

    it("returns fixedFee when percentageBps is zero even if rates are zero", async function () {
        const harness = await deployHarness()
        const packed = await harness.packFeeConfig(42n, 0n, 1000n)
        const [fee, usedDynamic] = await harness.resolvePortalFee(packed, 1_000_000n, 6, 0n, 0n)
        expect(fee).to.equal(42n)
        expect(usedDynamic).to.equal(false)
    })

    it("uses dynamic pricing when percentageBps and both rates are non-zero", async function () {
        const harness = await deployHarness()
        const packed = await harness.packFeeConfig(1n, 100_000n, 10n ** 18n) // 10%
        const amount = 10n ** 6n // 1 token @ 6 decimals
        const rate = 10n ** 18n // $1
        const [fee, usedDynamic] = await harness.resolvePortalFee(packed, amount, 6, rate, rate)
        expect(usedDynamic).to.equal(true)
        expect(fee).to.be.gt(1n)
    })
})
