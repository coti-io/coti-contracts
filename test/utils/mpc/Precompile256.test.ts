import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"

const gasLimit = 12000000

// Track if we've logged the deployment transaction
let deploymentLogged = false

function logTransaction(
  txHash: string,
  blockNumber: number,
  contractAddress: string,
  functionName: string,
  networkName: string,
  chainId: bigint,
  gasUsed?: bigint
) {
  console.log("\n" + "=".repeat(80))
  console.log(`📝 ON-CHAIN TRANSACTION - ${functionName}`)
  console.log("=".repeat(80))
  console.log(`Transaction Hash: ${txHash}`)
  console.log(`Block Number: ${blockNumber}`)
  console.log(`Contract Address: ${contractAddress}`)
  console.log(`Network: ${networkName}`)
  console.log(`Chain ID: ${chainId.toString()}`)
  if (gasUsed) {
    console.log(`Gas Used: ${gasUsed.toString()}`)
  }
  console.log("=".repeat(80) + "\n")
}

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
    const network = await provider.getNetwork()
    const networkName = hre.network.name

    const factory = await hre.ethers.getContractFactory(contractName, owner as any)
    const contract = await factory.deploy({ gasLimit })
    await contract.waitForDeployment()
    
    const contractAddress = await contract.getAddress()

    // Log deployment transaction (first transaction only)
    if (!deploymentLogged) {
      const deployTx = contract.deploymentTransaction()
      if (deployTx) {
        const deployReceipt = await deployTx.wait()
        if (deployReceipt) {
          logTransaction(
            deployReceipt.hash,
            deployReceipt.blockNumber,
            contractAddress,
            "Contract Deployment",
            networkName,
            network.chainId,
            deployReceipt.gasUsed
          )
          deploymentLogged = true
        }
      }
    }

    // Execute the function and log the transaction
    const tx = await contract.getFunction(func)(...params, { gasLimit })
    const receipt = await tx.wait()
    
    if (receipt) {
      logTransaction(
        receipt.hash,
        receipt.blockNumber,
        contractAddress,
        `${contractName}.${func}`,
        networkName,
        network.chainId,
        receipt.gasUsed
      )
    }

    // Verify the result
    const result = await contract.getFunction(resFunc)()
    expect(result).to.equal(expectedResult)
    
    // Additional verification: Check transaction exists on-chain
    const txFromChain = await provider.getTransactionReceipt(receipt.hash)
    expect(txFromChain).to.not.be.null
    expect(txFromChain?.blockNumber).to.equal(receipt.blockNumber)
    expect(txFromChain?.status).to.equal(1) // 1 = success
  })
}

const params = [
  BigInt("1000000000000000000"),  // 1e18
  BigInt("500000000000000000")    // 0.5e18
]
const [a, b] = params

describe("Precompile 256-bit", function () {
  buildTest("Arithmetic256TestsContract", "addTest", "getAddResult", params, a + b)
  buildTest("Arithmetic256TestsContract", "checkedAddTest", "getAddResult", params, a + b)
  buildTest("Arithmetic256TestsContract", "subTest", "getSubResult", params, a - b)
  buildTest("Arithmetic256TestsContract", "checkedSubTest", "getSubResult", params, a - b)
  buildTest("Arithmetic256TestsContract", "mulTest", "getMulResult", params, a * b)
  buildTest("Arithmetic256TestsContract", "checkedMulTest", "getMulResult", params, a * b)
  buildTest("Arithmetic256TestsContract", "divTest", "getDivResult", params, a / b)
  buildTest("Arithmetic256TestsContract", "remTest", "getRemResult", params, a % b)
})