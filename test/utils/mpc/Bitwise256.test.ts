import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  params: bigint[],
  expectedResult: bigint
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

describe("Bitwise 256-bit", function () {
  buildTest("Bitwise256TestsContract", "andTest", "getAndResult", params, a & b)
  buildTest("Bitwise256TestsContract", "orTest", "getOrResult", params, a | b)
  buildTest("Bitwise256TestsContract", "xorTest", "getXorResult", params, a ^ b)
})

