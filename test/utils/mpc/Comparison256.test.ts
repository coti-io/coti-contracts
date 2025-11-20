import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  params: bigint[],
  expectedResult: boolean
) {
  it(`${contractName}.${func}(${params}) should return ${expectedResult}`, async function () {
    const [owner] = await setupAccounts()
    const provider = owner.provider!

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    const tx = await contract.getFunction(func)(...params, { gasLimit })
    const receipt = await tx.wait()
    
    const result = await contract.getFunction(resFunc)()
    expect(result).to.equal(expectedResult)
    
    const txFromChain = await provider.getTransactionReceipt(receipt.hash)
    expect(txFromChain).to.not.be.null
    expect(txFromChain?.status).to.equal(1)
  })
}

const params = [
  BigInt("1000000000000000000"),  // 1e18
  BigInt("500000000000000000")    // 0.5e18
]
const [a, b] = params

describe("Comparison 256-bit", function () {
  buildTest("Comparison256TestsContract", "eqTest", "getEqResult", params, a == b)
  buildTest("Comparison256TestsContract", "neTest", "getNeResult", params, a != b)
  buildTest("Comparison256TestsContract", "geTest", "getGeResult", params, a >= b)
  buildTest("Comparison256TestsContract", "gtTest", "getGtResult", params, a > b)
  buildTest("Comparison256TestsContract", "leTest", "getLeResult", params, a <= b)
  buildTest("Comparison256TestsContract", "ltTest", "getLtResult", params, a < b)
})

