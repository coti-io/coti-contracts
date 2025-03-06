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

const params = [10, 5]
const [a, b] = params
describe("Precompile", function () {
  buildTest("CheckedArithmeticWithOverflowBitTestsContract", "checkedAddWithOverflowBitTest", "getAddResult", params, a + b)
  buildTest("CheckedArithmeticWithOverflowBitTestsContract", "checkedSubWithOverflowBitTest", "getSubResult", params, a - b)
  buildTest("CheckedArithmeticWithOverflowBitTestsContract", "checkedMulWithOverflowBitTest", "getMulResult", params, a * b)
})