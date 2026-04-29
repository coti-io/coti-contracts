import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000
const MAX_INT256 = (1n << 255n) - 1n
const MIN_INT256 = -(1n << 255n)

async function deploy() {
  const [owner] = await setupAccounts()
  const factory = await hre.ethers.getContractFactory("ArithmeticSigned256TestsContract", owner as any)
  const contract = await factory.deploy({ gasLimit })
  await contract.waitForDeployment()

  return { contract, owner }
}

async function expectRevert(txPromise: Promise<any>, owner: any) {
  const tx = await txPromise
  try {
    await tx.wait()
    expect.fail("expected transaction to revert")
  } catch (e) {
    const receipt = await owner.provider?.getTransactionReceipt(tx.hash)
    expect(receipt?.status).to.equal(0)
  }
}

describe("Checked Signed Arithmetic 256-bit", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  for (const func of [
    "basicSigned8Test",
    "basicSigned16Test",
    "basicSigned32Test",
    "basicSigned64Test",
    "basicSigned128Test",
    "basicSigned256ArithmeticTest",
    "basicSigned256ComparisonTest",
    "basicSigned256MuxAndHelpersTest",
    "minDivMinusOne8Test",
    "minDivMinusOne128Test",
    "minDivMinusOne256Test",
    "plainMul128WrapTest",
    "plainMul256WrapTest",
  ]) {
    it(`${func} should preserve signed integer semantics`, async function () {
      const { contract } = deployment

      const tx = await contract.getFunction(func)({ gasLimit })
      const receipt = await tx.wait()

      expect(receipt?.status).to.equal(1)
    })
  }

  it("checkedAdd should return an in-range signed result", async function () {
    const { contract } = deployment

    const tx = await contract.getFunction("checkedAddTest")(100n, -40n, { gasLimit })
    await tx.wait()

    expect(await contract.getFunction("getAddResult")()).to.equal(60n)
  })

  it("checkedAdd should revert on signed overflow", async function () {
    const { contract, owner } = deployment

    await expectRevert(contract.getFunction("checkedAddTest")(MAX_INT256, 1n, { gasLimit }), owner)
  })

  it("checkedSub should return an in-range signed result", async function () {
    const { contract } = deployment

    const tx = await contract.getFunction("checkedSubTest")(-100n, -40n, { gasLimit })
    await tx.wait()

    expect(await contract.getFunction("getSubResult")()).to.equal(-60n)
  })

  it("checkedSub should revert on signed underflow", async function () {
    const { contract, owner } = deployment

    await expectRevert(contract.getFunction("checkedSubTest")(MIN_INT256, 1n, { gasLimit }), owner)
  })

  it("checkedMul should return an in-range signed result", async function () {
    const { contract } = deployment

    const tx = await contract.getFunction("checkedMulTest")(-12n, 9n, { gasLimit })
    await tx.wait()

    expect(await contract.getFunction("getMulResult")()).to.equal(-108n)
  })

  it("checkedMul should revert on positive signed overflow", async function () {
    const { contract, owner } = deployment

    await expectRevert(contract.getFunction("checkedMulTest")(1n << 128n, 1n << 128n, { gasLimit }), owner)
  })

  it("checkedMul should revert on min-int negation overflow", async function () {
    const { contract, owner } = deployment

    await expectRevert(contract.getFunction("checkedMulTest")(MIN_INT256, -1n, { gasLimit }), owner)
  })

  for (const func of [
    "checkedAdd8OverflowTest",
    "checkedSub8UnderflowTest",
    "checkedMul8OverflowTest",
    "checkedAdd128OverflowTest",
    "checkedSub128UnderflowTest",
    "checkedMul128OverflowTest",
  ]) {
    it(`${func} should revert`, async function () {
      const { contract, owner } = deployment

      await expectRevert(contract.getFunction(func)({ gasLimit }), owner)
    })
  }
})
