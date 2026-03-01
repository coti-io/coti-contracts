import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { gasOptions, generateRandomNumber } from "./helpers"

function randomUnsigned256() {
  return generateRandomNumber(32);
}

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()
  const factory = await hre.ethers.getContractFactory("UnsignedInt256TestsContract")
  const contract = await factory.connect(owner).deploy(gasOptions)
  await contract.waitForDeployment()
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - unsigned 256-bit integers", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>
  before(async function () {
    deployment = await deploy()
  })

  const MAX = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

  describe("Validating encrypted unsigned 256-bit integers", function () {
    it("Should validate positive unsigned integers", async function () {
      const { contract, contractAddress, owner } = deployment
      const itValue = await owner.encryptUint256(
        42n,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue, gasOptions)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(42n)
    })

    it("Should validate maximum unsigned integers", async function () {
      const { contract, contractAddress, owner } = deployment
      const itValue = await owner.encryptUint256(
        MAX,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue, gasOptions)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(MAX)
    })

    it("Should validate zero", async function () {
      const { contract, contractAddress, owner } = deployment
      const itValue = await owner.encryptUint256(
        0n,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue, gasOptions)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(0n)
    })
  })

  describe("Offboard unsigned 256-bit integers", function () {
    it("Should offboard small unsigned integers", async function () {
      const { contract } = deployment
      await (await contract.offBoardTest(2n, 3n, 4n, gasOptions)).wait()
      await (await contract.onBoardTest()).wait()
      const decryptedInt1 = await contract.onBoardResults(0)
      const decryptedInt2 = await contract.onBoardResults(1)
      expect(decryptedInt1).to.equal(2n)
      expect(decryptedInt2).to.equal(4n)
    })
    it("Should decrypt the small unsigned integers", async function () {
      const { contract, owner } = deployment
      const encryptedInt = await contract.offBoardToUserResults(0)
      const decryptedInt = await owner.decryptUint256(encryptedInt)
      expect(decryptedInt).to.equal(3n)
    })
    it("Should offboard large unsigned integers", async function () {
      const { contract } = deployment
      await (await contract.resetState(gasOptions)).wait()

      const largeValue1 = randomUnsigned256()
      const largeValue2 = randomUnsigned256()
      const largeValue3 = randomUnsigned256()
      await (await contract.offBoardTest(largeValue1, largeValue2, largeValue3, gasOptions)).wait()
      await (await contract.onBoardTest(gasOptions)).wait()
      const decryptedInt1 = await contract.onBoardResults(0)
      const decryptedInt2 = await contract.onBoardResults(1)
      expect(decryptedInt1).to.equal(largeValue1)
      expect(decryptedInt2).to.equal(largeValue3)
    })
    it("Should decrypt the large unsigned integers", async function () {
      const { contract, owner } = deployment
      await (await contract.resetState(gasOptions)).wait()

      const largeValue = randomUnsigned256()
      await (await contract.offBoardTest(0n, largeValue, 0n, gasOptions)).wait()
      const encryptedInt = await contract.offBoardToUserResults(0)
      const decryptedInt = await owner.decryptUint256(encryptedInt)
      expect(decryptedInt).to.equal(largeValue)
    })
  })

  describe("Adding unsigned 256-bit integers", function () {
    it("Should add two positive numbers", async function () {
      const { contract } = deployment
      await (await contract.addTest(50n, 75n)).wait()
      const result = await contract.addResult()
      expect(result).to.equal(125n)
    })

    it("Should handle addition overflow", async function () {
      const { contract } = deployment
      const a = MAX - 100n
      const b = 200n
      await (await contract.addTest(a, b)).wait()
      const result = await contract.addResult()
      expect(result).to.equal(99n) // (MAX - 100 + 200) % (MAX + 1) = 99
    })
  })

  describe("Subtracting unsigned 256-bit integers", function () {
    it("Should subtract two numbers", async function () {
      const { contract } = deployment
      await (await contract.subTest(100n, 30n)).wait()
      const result = await contract.subResult()
      expect(result).to.equal(70n)
    })

    it("Should handle subtraction underflow", async function () {
      const { contract } = deployment
      await (await contract.subTest(30n, 100n)).wait()
      const result = await contract.subResult()
      expect(result).to.equal(MAX - 69n) // (30 - 100) + (MAX + 1) = MAX - 69
    })
  })

  describe("Multiplying unsigned 256-bit integers", function () {
    it("Should multiply two numbers", async function () {
      const { contract } = deployment
      await (await contract.mulTest(12n, 10n)).wait()
      const result = await contract.mulResult()
      expect(result).to.equal(120n)
    })

    it("Should handle multiplication overflow", async function () {
      const { contract } = deployment
      const a = 2n ** 128n
      const b = 2n ** 128n
      await (await contract.mulTest(a, b)).wait()
      const result = await contract.mulResult()
      expect(result).to.equal(0n) // 2^128 * 2^128 = 2^256 = 0 (wraps around)
    })
  })

  describe("Dividing unsigned 256-bit integers", function () {
    it("Should divide two numbers", async function () {
      const { contract } = deployment
      await (await contract.divTest(100n, 5n)).wait()
      const result = await contract.divResult()
      expect(result).to.equal(20n)
    })

    it("Should handle division by large numbers", async function () {
      const { contract } = deployment
      const a = randomUnsigned256()
      const b = randomUnsigned256()
      if (b > 0n) {
        await (await contract.divTest(a, b)).wait()
        const result = await contract.divResult()
        expect(result).to.equal(a / b)
      }
    })
  })

  describe("Bitwise operations on unsigned 256-bit integers", function () {
    it("Should perform AND operation", async function () {
      const { contract } = deployment
      await (await contract.andTest(0xFFn, 0xF0n)).wait()
      const result = await contract.andResult()
      expect(result).to.equal(0xF0n)
    })

    it("Should perform OR operation", async function () {
      const { contract } = deployment
      await (await contract.orTest(0x0Fn, 0xF0n)).wait()
      const result = await contract.orResult()
      expect(result).to.equal(0xFFn)
    })

    it("Should perform XOR operation", async function () {
      const { contract } = deployment
      await (await contract.xorTest(0xFFn, 0xF0n)).wait()
      const result = await contract.xorResult()
      expect(result).to.equal(0x0Fn)
    })
  })

  describe("Comparing unsigned 256-bit integers", function () {
    it("Should compare greater than", async function () {
      const { contract } = deployment
      await (await contract.gtTest(100n, 50n)).wait()
      const result = await contract.gtResult()
      expect(result).to.equal(true)

      await (await contract.gtTest(50n, 100n)).wait()
      const result2 = await contract.gtResult()
      expect(result2).to.equal(false)
    })

    it("Should compare less than", async function () {
      const { contract } = deployment
      await (await contract.ltTest(50n, 100n)).wait()
      const result = await contract.ltResult()
      expect(result).to.equal(true)

      await (await contract.ltTest(100n, 50n)).wait()
      const result2 = await contract.ltResult()
      expect(result2).to.equal(false)
    })

    it("Should compare equality", async function () {
      const { contract } = deployment
      await (await contract.eqTest(42n, 42n)).wait()
      const result = await contract.eqResult()
      expect(result).to.equal(true)

      await (await contract.eqTest(42n, 43n)).wait()
      const result2 = await contract.eqResult()
      expect(result2).to.equal(false)
    })

    it("Should compare not equal", async function () {
      const { contract } = deployment
      await (await contract.neTest(42n, 43n)).wait()
      const result = await contract.neResult()
      expect(result).to.equal(true)

      await (await contract.neTest(42n, 42n)).wait()
      const result2 = await contract.neResult()
      expect(result2).to.equal(false)
    })

    it("Should compare greater than or equal", async function () {
      const { contract } = deployment
      await (await contract.geTest(100n, 50n)).wait()
      const result = await contract.geResult()
      expect(result).to.equal(true)

      await (await contract.geTest(50n, 50n)).wait()
      const result2 = await contract.geResult()
      expect(result2).to.equal(true)

      await (await contract.geTest(50n, 100n)).wait()
      const result3 = await contract.geResult()
      expect(result3).to.equal(false)
    })

    it("Should compare less than or equal", async function () {
      const { contract } = deployment
      await (await contract.leTest(50n, 100n)).wait()
      const result = await contract.leResult()
      expect(result).to.equal(true)

      await (await contract.leTest(50n, 50n)).wait()
      const result2 = await contract.leResult()
      expect(result2).to.equal(true)

      await (await contract.leTest(100n, 50n)).wait()
      const result3 = await contract.leResult()
      expect(result3).to.equal(false)
    })
  })
})
