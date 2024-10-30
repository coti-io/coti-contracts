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

    const factory = await hre.ethers.getContractFactory(contractName, owner)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    await (await contract.getFunction(func)(...params, { gasLimit })).wait()
    const result = await contract.getFunction(resFunc)()
    if (resFunc === "getRandom") {
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

    const factory = await hre.ethers.getContractFactory(contractName, owner)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    await (await contract.getFunction(func)(param, owner.address, { gasLimit: 12000000 })).wait()
    const results = await contract.getFunction(resFunc)()
    for (const result of results) {
      expect(await owner.decryptValue(result)).to.equal(param)
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
  buildTest("ArithmeticTestsContract", "addTest", "getResult", params, a + b)
  buildTest("ArithmeticTestsContract", "subTest", "getResult", params, a - b)
  buildTest("ArithmeticTestsContract", "mulTest", "getResult16", params, a * b)

  buildTest("Miscellaneous2TestsContract", "divTest", "getResult", params, a / b)
  buildTest("Miscellaneous2TestsContract", "remTest", "getResult", params, a % b)

  buildTest("BitwiseTestsContract", "andTest", "getResult", params, a & b)
  buildTest("BitwiseTestsContract", "orTest", "getResult", params, a | b)
  buildTest("BitwiseTestsContract", "xorTest", "getResult", params, a ^ b)

  buildTest(
    "ShiftTestsContract",
    "shlTest",
    "getAllShiftResults",
    [a, shift],
    ...[2, 4, 8, 16].map((x) => BigInt(a << shift) & BigInt(`0x${"f".repeat(x)}`))
  )
  buildTest("ShiftTestsContract", "shrTest", "getResult", params, a >> b)

  buildTest("MinMaxTestsContract", "minTest", "getResult", params, Math.min(a, b))
  buildTest("MinMaxTestsContract", "maxTest", "getResult", params, Math.max(a, b))
  buildTest("Comparison2TestsContract", "eqTest", "getResult", params, a == b)
  buildTest("Comparison2TestsContract", "neTest", "getResult", params, a != b)
  buildTest("Comparison2TestsContract", "geTest", "getResult", params, a >= b)
  buildTest("Comparison1TestsContract", "gtTest", "getResult", params, a > b)
  buildTest("Comparison1TestsContract", "leTest", "getResult", params, a <= b)
  buildTest("Comparison1TestsContract", "ltTest", "getResult", params, a < b)
  buildTest("Miscellaneous2TestsContract", "muxTest", "getResult", [bit, a, b], bit === false ? a : b)

  buildTest("TransferTestsContract", "transferTest", "getResults", [a, b, b], a - b, b + b, true)
  buildTest("TransferScalarTestsContract", "transferScalarTest", "getResults", [a, b, b], a - b, b + b, true)

  buildTest("Miscellaneous2TestsContract", "offboardOnboardTest", "getResult", [a, a, a, a], a)
  buildTest("Miscellaneous2TestsContract", "notTest", "getBoolResult", [!!a], !a)

  buildTestWithUser("OffboardToUserKeyTestContract", "offboardToUserTest", "getCTs", a)

  buildTest("Miscellaneous1TestsContract", "randomTest", "getRandom", [], last_random_value)
  buildTest("Miscellaneous1TestsContract", "randomBoundedTest", "getRandom", [numBits], last_random_value)
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
})