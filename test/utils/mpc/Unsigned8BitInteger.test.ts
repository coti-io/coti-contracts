import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { gasOptions, generateRandomNumber } from "./helpers";

function randomUnsigned8() {
  return generateRandomNumber(1);
}

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()
  const factory = await hre.ethers.getContractFactory("UnsignedInt8TestsContract")
  const contract = await factory.connect(owner).deploy(gasOptions)
  await contract.waitForDeployment()
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - unsigned 8-bit integers", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>
  before(async function () {
    deployment = await deploy()
  })

  const MAX = 255n;
  const MIN = 0n;

  describe("Validating encrypted unsigned 8-bit integers", function () {
    it("Should validate positive unsigned integers", async function () {
      const { contract, contractAddress, owner } = deployment
      const itValue = await owner.encryptUint8(
        42,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(42n)
    })

    it("Should validate maximum unsigned integers", async function () {
      const { contract, contractAddress, owner } = deployment
      const itValue = await owner.encryptUint8(
        255,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(255n)
    })

    it("Should validate zero", async function () {
      const { contract, contractAddress, owner } = deployment
      const itValue = await owner.encryptUint8(
        0,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )
      await (await contract.validateCiphertextTest(itValue)).wait()
      const decryptedInt = await contract.validateResult()
      expect(decryptedInt).to.equal(0n)
    })
  })

  describe("Offboard unsigned 8-bit integers", function () {
    it("Should offboard small unsigned integers", async function () {
      const { contract } = deployment
      await (await contract.offBoardTest(2, 3, 4)).wait()
      await (await contract.onBoardTest()).wait()
      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()
      expect(decryptedInt1).to.equal(2)
      expect(decryptedInt2).to.equal(4)
    })
    it("Should decrypt the small unsigned integers", async function () {
      const { contract, owner } = deployment
      const encryptedInt = await contract.offBoardToUserResult()
      const decryptedInt = await owner.decryptUint8(encryptedInt)
      expect(decryptedInt).to.equal(3)
    })
    it("Should offboard large unsigned integers", async function () {
      const { contract } = deployment
      await (await contract.offBoardTest(200, 201, 202)).wait()
      await (await contract.onBoardTest()).wait()
      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()
      expect(decryptedInt1).to.equal(200)
      expect(decryptedInt2).to.equal(202)
    })
    it("Should decrypt the large unsigned integers", async function () {
      const { contract, owner } = deployment

      const encryptedInt = await contract.offBoardToUserResult()

      const decryptedInt = await owner.decryptUint8(encryptedInt)
      
      expect(decryptedInt).to.equal(201n)
    })
  })

  describe("Adding unsigned 8-bit integers", function () {
    it("Should add two positive numbers", async function () {
      const { contract } = deployment
      await (await contract.addTest(50, 75)).wait()
      const result = await contract.addResult()
      expect(result).to.equal(125)
    })

    it("Should handle addition overflow", async function () {
      const { contract } = deployment
      await (await contract.addTest(200, 100)).wait()
      const result = await contract.addResult()
      expect(result).to.equal(44) // 300 % 256 = 44 (wraps around)
    })
  })

  describe("Subtracting unsigned 8-bit integers", function () {
    it("Should subtract two numbers", async function () {
      const { contract } = deployment
      await (await contract.subTest(100, 30)).wait()
      const result = await contract.subResult()
      expect(result).to.equal(70)
    })

    it("Should handle subtraction underflow", async function () {
      const { contract } = deployment
      await (await contract.subTest(30, 100)).wait()
      const result = await contract.subResult()
      expect(result).to.equal(186) // (30 - 100) + 256 = 186 (wraps around)
    })
  })

  describe("Multiplying unsigned 8-bit integers", function () {
    it("Should multiply two numbers", async function () {
      const { contract } = deployment
      await (await contract.mulTest(12, 10)).wait()
      const result = await contract.mulResult()
      expect(result).to.equal(120)
    })

    it("Should handle multiplication overflow", async function () {
      const { contract } = deployment
      await (await contract.mulTest(20, 20)).wait()
      const result = await contract.mulResult()
      expect(result).to.equal(144) // 400 % 256 = 144 (wraps around)
    })
  })

  describe("Comparing unsigned 8-bit integers", function () {
    it("Should compare greater than", async function () {
      const { contract } = deployment
      await (await contract.gtTest(100, 50)).wait()
      const result = await contract.gtResult()
      expect(result).to.equal(true)

      await (await contract.gtTest(50, 100)).wait()
      const result2 = await contract.gtResult()
      expect(result2).to.equal(false)
    })

    it("Should compare less than", async function () {
      const { contract } = deployment
      await (await contract.ltTest(50, 100)).wait()
      const result = await contract.ltResult()
      expect(result).to.equal(true)

      await (await contract.ltTest(100, 50)).wait()
      const result2 = await contract.ltResult()
      expect(result2).to.equal(false)
    })

    it("Should compare equality", async function () {
      const { contract } = deployment
      await (await contract.eqTest(42, 42)).wait()
      const result = await contract.eqResult()
      expect(result).to.equal(true)

      await (await contract.eqTest(42, 43)).wait()
      const result2 = await contract.eqResult()
      expect(result2).to.equal(false)
    })
  })
})
