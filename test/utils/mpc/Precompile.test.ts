import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000
let last_random_value = 0

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  params: (bigint | number | boolean)[],
  ...expectedResults: (number | boolean | bigint)[]
) {
  it(`${contractName}.${func}(${params}) should return ${expectedResults}`, async function () {
    const [owner] = await setupAccounts()

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    await (await contract.getFunction(func)(...params, { gasLimit })).wait()
    const result = await contract.getFunction(resFunc)()
    if (resFunc === "getRandom" || resFunc === "getRandomBounded") {
      expect(result).to.not.equal(expectedResults[0])
      last_random_value = result
    } else if (expectedResults.length === 1) {
      expect(result).to.equal(expectedResults[0])
    } else {
      expect(result).to.deep.equal(expectedResults)
    }
  })
}

function buildTestWithUser(contractName: string, func: string, resFunc: string, param: bigint | number | boolean) {
  it(`${contractName}.${func}(${params}, <address>) should return the correct user decrypted value`, async function () {
    const [owner] = await setupAccounts()

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    await (await contract.getFunction(func)(param, owner.address, { gasLimit: 12000000 })).wait()
    const results = await contract.getFunction(resFunc)()
    for (let i = 0; i < results.length; i++) {
      if (i === 0) {
        expect(Boolean(await owner.decryptValue(results[i]))).to.equal(true)
      } else {
        expect(await owner.decryptValue(results[i])).to.equal(param)
      }
    }
  })
}

const params = [10, 5]
const shift = 2
const bit = false
const numBits = 7
const bool_a = true
const bool_b = false
const [a, b] = params
describe("Precompile", function () {
  buildTest("ArithmeticTestsContract", "addTest", "getAddResult", params, a + b)
  buildTest("ArithmeticTestsContract", "checkedAddTest", "getAddResult", params, a + b)
  buildTest("ArithmeticTestsContract", "subTest", "getSubResult", params, a - b)
  buildTest("ArithmeticTestsContract", "checkedSubTest", "getSubResult", params, a - b)
  buildTest("ArithmeticTestsContract", "mulTest", "getMulResult", params, a * b)
  buildTest("ArithmeticTestsContract", "checkedMulTest", "getMulResult", params, a * b)

  buildTest("MiscellaneousTestsContract", "divTest", "getDivResult", params, a / b)
  buildTest("MiscellaneousTestsContract", "remTest", "getRemResult", params, a % b)

  buildTest("BitwiseTestsContract", "andTest", "getAndResult", params, a & b)
  buildTest("BitwiseTestsContract", "orTest", "getOrResult", params, a | b)
  buildTest("BitwiseTestsContract", "xorTest", "getXorResult", params, a ^ b)

  buildTest("MinMaxTestsContract", "minTest", "getMinResult", params, Math.min(a, b))
  buildTest("MinMaxTestsContract", "maxTest", "getMaxResult", params, Math.max(a, b))
  buildTest("Comparison2TestsContract", "eqTest", "getEqResult", params, a == b)
  buildTest("Comparison2TestsContract", "neTest", "getNeResult", params, a != b)
  buildTest("Comparison2TestsContract", "geTest", "getGeResult", params, a >= b)
  buildTest("Comparison1TestsContract", "gtTest", "getGtResult", params, a > b)
  buildTest("Comparison1TestsContract", "leTest", "getLeResult", params, a <= b)
  buildTest("Comparison1TestsContract", "ltTest", "getLtResult", params, a < b)
  buildTest("MiscellaneousTestsContract", "muxTest", "getMuxResult", [bit, a, b], bit === false ? a : b)

  buildTest("TransferTestsContract", "transferTest", "getResults", [a, b, b], a - b, b + b, true)
  buildTest("TransferScalarTestsContract", "transferScalarTest", "getResults", [a, b, b], a - b, b + b, true)
  buildTest("TransferWithAllowanceTestsContract", "transferWithAllowanceTest", "getResults", [a, b, b, b], a - b, b + b, true, 0)
  buildTest("TransferWithAllowance64_8TestsContract", "transferWithAllowance64Test", "getResults", [a, b, b, b], a - b, b + b, true, 0)
  buildTest("TransferWithAllowance64_16TestsContract", "transferWithAllowance64Test", "getResults", [a, b, b, b], a - b, b + b, true, 0)
  buildTest("TransferWithAllowance64_32TestsContract", "transferWithAllowance64Test", "getResults", [a, b, b, b], a - b, b + b, true, 0)
  buildTest("TransferWithAllowance64_64TestsContract", "transferWithAllowance64Test", "getResults", [a, b, b, b], a - b, b + b, true, 0)
  buildTest("TransferWithAllowanceScalarTestsContract", "transferWithAllowanceScalarTest", "getResults", [a, b, b, b], a - b, b + b, true, 0)
  buildTest("OffboardToUserKeyTestContract", "offboardOnboardTest", "getOnboardOffboardResult", [a, a, a, a], a)
  buildTest("MiscellaneousTestsContract", "notTest", "getBoolResult", [!!a], !a)

  buildTestWithUser("OffboardToUserKeyTestContract", "offboardToUserTest", "getCTs", a)
  buildTestWithUser("OffboardToUserKeyTestContract", "offboardCombinedTest", "getCTs", a)
  buildTest("Miscellaneous1TestsContract", "randomTest", "getRandom", [], last_random_value)
  buildTest("Miscellaneous1TestsContract", "randomBoundedTest", "getRandomBounded", [numBits], last_random_value)
  buildTest(
    "Miscellaneous1TestsContract",
    "booleanTest",
    "getBooleanResults",
    [bool_a, bool_b, bit],
    bool_a && bool_b,
    bool_a || bool_b,
    bool_a != (bool_b as boolean),
    !bool_a,
    bool_a === (bool_b as boolean),
    bool_a != (bool_b as boolean),
    bit ? bool_b : bool_a,
    bool_a
  )
  buildTest(
    "ShiftTestsContract",
    "shlTest",
    "getAllShiftResults",
    [a, shift],
    ...[2, 4, 8, 16].map((x) => BigInt(a << shift) & BigInt(`0x${"f".repeat(x)}`))
  )
  buildTest("ShiftTestsContract", "shrTest", "getResult", params, a >> b)
})