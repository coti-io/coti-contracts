import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

function buildTest(
  contractName: string,
  func: string,
  resFunc: string,
  params: bigint[],
  expectedResults: [bigint, bigint, boolean]
) {
  it(`${contractName}.${func}(${params}) should return correct transfer results`, async function () {
    const [owner] = await setupAccounts()
    const provider = owner.provider!

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()

    const tx = await contract.getFunction(func)(...params, { gasLimit })
    const receipt = await tx.wait()
    
    const results = await contract.getFunction(resFunc)()
    expect(results[0]).to.equal(expectedResults[0]) // newA
    expect(results[1]).to.equal(expectedResults[1]) // newB
    expect(results[2]).to.equal(expectedResults[2]) // result (success)
    
    const txFromChain = await provider.getTransactionReceipt(receipt.hash)
    expect(txFromChain).to.not.be.null
    expect(txFromChain?.status).to.equal(1)
  })
}

const params = [
  BigInt("1000000000000000000"),  // a = 1e18
  BigInt("500000000000000000"),   // b = 0.5e18
  BigInt("200000000000000000")    // amount = 0.2e18
]
const [a, b, amount] = params

describe("Transfer 256-bit", function () {
  buildTest("Transfer256TestsContract", "transferTest", "getResults", params, [a - amount, b + amount, true])
})

