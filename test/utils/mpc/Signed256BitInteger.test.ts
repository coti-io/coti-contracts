import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { gasOptions, generateRandomNumber } from "./helpers";

function randomSigned256() {
  let unsigned = generateRandomNumber(32);
  // If the most significant bit is set (i.e. sign bit), convert to signed using two's complement
  const signBit = 1n << 255n
  if (unsigned & signBit) {
      // Two's complement conversion for negative numbers
      unsigned = unsigned - (1n << 256n)
  }

  return unsigned
}

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const signedInt256TestsContractFactory = await hre.ethers.getContractFactory("SignedInt256TestsContract")
  const signedInt256TestsContract = await signedInt256TestsContractFactory.connect(owner).deploy(gasOptions)
  await signedInt256TestsContract.waitForDeployment()

  const arithmeticSigned256BitTestsContractFactory = await hre.ethers.getContractFactory("ArithmeticSigned256BitTestsContract")
  const arithmeticSigned256BitTestsContract = await arithmeticSigned256BitTestsContractFactory.connect(owner).deploy(gasOptions)
  await arithmeticSigned256BitTestsContract.waitForDeployment()

  return { signedInt256TestsContract, arithmeticSigned256BitTestsContract, contractAddress: await signedInt256TestsContract.getAddress(), owner, otherAccount }
}

describe("MPC Core - signed 256-bit integers", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Validating encrypted signed 256-bit integers", function () {
    it("Should validate positive signed 256-bit integers", async function () {
      const { signedInt256TestsContract, contractAddress, owner } = deployment

      const testValue = 1234567890123456789012345678901234567890n
      const itValue = await owner.encryptInt256(
        testValue,
        contractAddress,
        signedInt256TestsContract.validateCiphertextTest.fragment.selector
      )

      await (await signedInt256TestsContract.validateCiphertextTest(itValue, gasOptions)).wait()

      const decryptedInt = await signedInt256TestsContract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })

    it("Should validate negative signed 256-bit integers", async function () {
      const { signedInt256TestsContract, contractAddress, owner } = deployment

      const testValue = -987654321098765432109876543210987654321n
      const itValue = await owner.encryptInt256(
        testValue,
        contractAddress,
        signedInt256TestsContract.validateCiphertextTest.fragment.selector
      )

      await (await signedInt256TestsContract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await signedInt256TestsContract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })
  })

  describe("Adding signed 256-bit integers", function () {
    it("Should encrypt, add and decrypt two positive signed 256-bit integers", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.addTest([10000000000000000000000000000000000n], [20000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(30000000000000000000000000000000000n)
    })

    it("Should encrypt, add and decrypt two negative signed 256-bit integers", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.addTest([-10000000000000000000000000000000000n], [-20000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-30000000000000000000000000000000000n)
    })

    it("Should encrypt, add and decrypt a positive and negative signed 256-bit integer", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.addTest([50000000000000000000000000000000000n], [-30000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(20000000000000000000000000000000000n)
    })

    it("Should encrypt, add and decrypt a negative and positive signed 256-bit integer", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.addTest([-80000000000000000000000000000000000n], [30000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-50000000000000000000000000000000000n)
    })
  })

  describe("Subtracting signed 256-bit integers", function () {
    it("Should encrypt, subtract and decrypt two positive signed 256-bit integers", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.subTest([50000000000000000000000000000000000n], [20000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(30000000000000000000000000000000000n)
    })

    it("Should encrypt, subtract and decrypt two negative signed 256-bit integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { arithmeticSigned256BitTestsContract } = freshDeployment

      await (await arithmeticSigned256BitTestsContract.subTest([-50000000000000000000000000000000000n], [-20000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-30000000000000000000000000000000000n)
    })

    it("Should encrypt, subtract and decrypt a positive and negative signed 256-bit integer", async function () {
      // Deploy fresh arithmeticSigned256BitTestsContract to avoid state pollution
      const freshDeployment = await deploy()
      const { arithmeticSigned256BitTestsContract } = freshDeployment

      await (await arithmeticSigned256BitTestsContract.subTest([50000000000000000000000000000000000n], [-30000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(80000000000000000000000000000000000n)
    })

    it("Should encrypt, subtract and decrypt a negative and positive signed 256-bit integer", async function () {
      // Deploy fresh arithmeticSigned256BitTestsContract to avoid state pollution
      const freshDeployment = await deploy()
      const { arithmeticSigned256BitTestsContract } = freshDeployment

      await (await arithmeticSigned256BitTestsContract.subTest([-80000000000000000000000000000000000n], [30000000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-110000000000000000000000000000000000n)
    })
  })

  describe("Multiplying signed 256-bit integers", function () {
    it("Should encrypt, multiply and decrypt two positive signed 256-bit integers", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.mulTest([10000000000000000n], [20000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(200000000000000000000n)
    })

    it("Should encrypt, multiply and decrypt two negative signed 256-bit integers", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.mulTest([-10000000000000000n], [-30000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(300000000000000000000n)
    })

    it("Should encrypt, multiply and decrypt a positive and negative signed 256-bit integer", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.mulTest([20000000000000000n], [-15000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-300000000000000000000n)
    })

    it("Should encrypt, multiply and decrypt a negative and positive signed 256-bit integer", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.mulTest([-20000000000000000n], [15000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-300000000000000000000n)
    })
  })

  describe("Dividing signed 256-bit integers", function () {
    it("Should encrypt, divide and decrypt two positive signed 256-bit integers", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.divTest([60000000000000000000000000000000n], [20000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(3n)
    })

    it("Should encrypt, divide and decrypt two negative signed 256-bit integers", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.divTest([-90000000000000000000000000000000n], [-30000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(3n)
    })

    it("Should encrypt, divide and decrypt a positive and negative signed 256-bit integer", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.divTest([80000000000000000000000000000000n], [-20000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-4n)
    })

    it("Should encrypt, divide and decrypt a negative and positive signed 256-bit integer", async function () {
      const { arithmeticSigned256BitTestsContract } = deployment

      await (await arithmeticSigned256BitTestsContract.divTest([-120000000000000000000000000000000n], [30000000000000000000000000000000n])).wait()

      const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)

      expect(decryptedInt).to.equal(-4n)
    })
  })

  describe("AND signed 256-bit integers", function () {
    it("Should encrypt, AND and decrypt two positive signed 256-bit integers", async function () {
      const { signedInt256TestsContract } = deployment

      const a = 0xFFFFFFFn
      const b = 0x123456789n
      await (await signedInt256TestsContract.andTest(a, b)).wait()

      const decryptedInt = await signedInt256TestsContract.andResult()
      expect(decryptedInt).to.equal(BigInt.asIntN(256, a & b))
    })

    it("Should encrypt, AND and decrypt two negative signed 256-bit integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { signedInt256TestsContract } = freshDeployment

      await (await signedInt256TestsContract.andTest(-1n, -1n)).wait()

      const decryptedInt = await signedInt256TestsContract.andResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, AND and decrypt a positive and negative signed 256-bit integer", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.andTest(0xFFFFFFFFn, -1n)).wait()

      const decryptedInt = await signedInt256TestsContract.andResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, AND and decrypt a negative and positive signed 256-bit integer", async function () {
      // Deploy fresh signedInt256TestsContract to avoid state pollution
      const freshDeployment = await deploy()
      const { signedInt256TestsContract } = freshDeployment

      await (await signedInt256TestsContract.andTest(-2n, 1n)).wait()

      const decryptedInt = await signedInt256TestsContract.andResult()

      expect(decryptedInt).to.equal(0n)
    })
  })

  describe("OR signed 256-bit integers", function () {
    it("Should encrypt, OR and decrypt two positive signed 256-bit integers", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.orTest(0xF0F0F0F0n, 0x0F0F0F0Fn)).wait()

      const decryptedInt = await signedInt256TestsContract.orResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, OR and decrypt two negative signed 256-bit integers", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.orTest(-1n, -1n)).wait()

      const decryptedInt = await signedInt256TestsContract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, OR and decrypt a positive and negative signed 256-bit integer", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.orTest(1n, -1n)).wait()

      const decryptedInt = await signedInt256TestsContract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, OR and decrypt a negative and positive signed 256-bit integer", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.orTest(-2n, 1n)).wait()

      const decryptedInt = await signedInt256TestsContract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })
  })

  describe("XOR signed 256-bit integers", function () {
    it("Should encrypt, XOR and decrypt two positive signed 256-bit integers", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.xorTest(0xAAAAAAAAn, 0x55555555n)).wait()

      const decryptedInt = await signedInt256TestsContract.xorResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, XOR and decrypt two negative signed 256-bit integers", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.xorTest(-1n, -1n)).wait()

      const decryptedInt = await signedInt256TestsContract.xorResult()

      expect(decryptedInt).to.equal(0n)
    })

    it("Should encrypt, XOR and decrypt a positive and negative signed 256-bit integer", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.xorTest(1n, -1n)).wait()

      const decryptedInt = await signedInt256TestsContract.xorResult()

      expect(decryptedInt).to.equal(-2n)
    })

    it("Should encrypt, XOR and decrypt a negative and positive signed 256-bit integer", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.xorTest(-2n, 1n)).wait()

      const decryptedInt = await signedInt256TestsContract.xorResult()

      expect(decryptedInt).to.equal(-1n)
    })
  })

  describe("EQ signed 256-bit integers", function () {
    // 1. Both numbers < 2^128
    it("should return true for equal small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.eqTest(123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(true)
    })
    it("should return false for different small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.eqTest(123456789012345678901234567890n, 987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
    it("should return true for equal small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.eqTest(-123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(true)
    })
    it("should return false for different small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.eqTest(-123456789012345678901234567890n, -987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })

    // 2. One < 2^128, one between 2^128 and 2^256
    it("should return false for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(small, large)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(large, small)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(small, large)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(large, small)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(small, large)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(large, small)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(small, large)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(large, small)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })

    // 3. Both above 2^128
    it("should return true for equal large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(a, a)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(true)
    })
    it("should return false for different large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = (2n ** 200n) + 987654321098765432109876543210n
      await (await signedInt256TestsContract.eqTest(a, b)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
    it("should return true for equal large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(a, a)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(true)
    })
    it("should return false for different large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      const b = -(2n ** 200n) - 987654321098765432109876543210n
      await (await signedInt256TestsContract.eqTest(a, b)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(a, b)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(b, a)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })

    // 4. Positive vs positive, left small/right small
    it("should return false for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(small, large)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(large, small)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })

    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return false for small positive vs small negative", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.eqTest(123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(-123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(a, b)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(b, a)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })

    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.eqTest(small, large)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
      await (await signedInt256TestsContract.eqTest(large, small)).wait()
      expect(await signedInt256TestsContract.eqResult()).to.equal(false)
    })
  })

  describe("NE signed 256-bit integers", function () {
    // 1. Both numbers < 2^128
    it("should return false for equal small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.neTest(123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(false)
    })
    it("should return true for different small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.neTest(123456789012345678901234567890n, 987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
    it("should return false for equal small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.neTest(-123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(false)
    })
    it("should return true for different small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.neTest(-123456789012345678901234567890n, -987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })

    // 2. One < 2^128, one between 2^128 and 2^256
    it("should return true for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(small, large)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(large, small)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
    it("should return true for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(small, large)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(large, small)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
    it("should return true for small positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(small, large)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(large, small)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
    it("should return true for small negative vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(small, large)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(large, small)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })

    // 3. Both above 2^128
    it("should return false for equal large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(a, a)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(false)
    })
    it("should return true for different large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = (2n ** 200n) + 987654321098765432109876543210n
      await (await signedInt256TestsContract.neTest(a, b)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
    it("should return false for equal large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(a, a)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(false)
    })
    it("should return true for different large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      const b = -(2n ** 200n) - 987654321098765432109876543210n
      await (await signedInt256TestsContract.neTest(a, b)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(a, b)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(b, a)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })

    // 4. Positive vs positive, left small/right small
    it("should return true for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(small, large)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(large, small)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })

    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return true for small positive vs small negative", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.neTest(123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(-123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(a, b)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(b, a)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })

    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.neTest(small, large)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
      await (await signedInt256TestsContract.neTest(large, small)).wait()
      expect(await signedInt256TestsContract.neResult()).to.equal(true)
    })
  })

  describe("GT signed 256-bit integers", function () {
    // 1. Both numbers < 2^128
    it("should return false for equal small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.gtTest(123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return false for small positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.gtTest(123456789012345678901234567890n, 987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return true for small positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.gtTest(987654321098765432109876543210n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
    })
    it("should return false for equal small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.gtTest(-123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return false for small negative less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.gtTest(-987654321098765432109876543210n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return true for small negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.gtTest(-123456789012345678901234567890n, -987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
    })

    // 2. One < 2^128, one between 2^128 and 2^256
    it("should return false for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(small, large)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)

      await (await signedInt256TestsContract.gtTest(large, small)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
    })
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(small, large)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)

      await (await signedInt256TestsContract.gtTest(large, small)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return true for small positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(small, large)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
      await (await signedInt256TestsContract.gtTest(large, small)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(small, large)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)

      await (await signedInt256TestsContract.gtTest(large, small)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
    })

    // 3. Both above 2^128
    it("should return false for equal large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(a, a)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return false for large positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = (2n ** 200n) + 987654321098765432109876543210n
      await (await signedInt256TestsContract.gtTest(a, b)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return true for large positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 987654321098765432109876543210n
      const b = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(a, b)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
    })
    it("should return false for equal large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(a, a)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return false for large negative less than another (more negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 987654321098765432109876543210n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(a, b)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return true for large negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      const b = -(2n ** 200n) - 987654321098765432109876543210n
      await (await signedInt256TestsContract.gtTest(a, b)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(a, b)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)

      await (await signedInt256TestsContract.gtTest(b, a)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })

    // 4. Positive vs positive, left small/right small
    it("should return false for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(small, large)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
      await (await signedInt256TestsContract.gtTest(large, small)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)
    })

    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return true for small positive vs small negative", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.gtTest(123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)

      await (await signedInt256TestsContract.gtTest(-123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(a, b)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)

      await (await signedInt256TestsContract.gtTest(b, a)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })

    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.gtTest(small, large)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(true)

      await (await signedInt256TestsContract.gtTest(large, small)).wait()
      expect(await signedInt256TestsContract.gtResult()).to.equal(false)
    })
  })

  describe("LT signed 256-bit integers", function () {
    it("should return false for equal small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.ltTest(123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return true for small positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.ltTest(123456789012345678901234567890n, 987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    it("should return false for small positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.ltTest(987654321098765432109876543210n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return false for equal small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.ltTest(-123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return true for small negative less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.ltTest(-987654321098765432109876543210n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    it("should return false for small negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.ltTest(-123456789012345678901234567890n, -987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    // 2. One < 2^128, one between 2^128 and 2^256
    it("should return true for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(small, large)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
      await (await signedInt256TestsContract.ltTest(large, small)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(small, large)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      await (await signedInt256TestsContract.ltTest(large, small)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    it("should return false for small positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(small, large)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      await (await signedInt256TestsContract.ltTest(large, small)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    it("should return true for small negative vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(small, large)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
      await (await signedInt256TestsContract.ltTest(large, small)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    // 3. Both above 2^128
    it("should return false for equal large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(a, a)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return true for large positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = (2n ** 200n) + 987654321098765432109876543210n
      await (await signedInt256TestsContract.ltTest(a, b)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    it("should return false for large positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 987654321098765432109876543210n
      const b = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(a, b)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return false for equal large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(a, a)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return true for large negative less than another (more negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 987654321098765432109876543210n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(a, b)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    it("should return false for large negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      const b = -(2n ** 200n) - 987654321098765432109876543210n
      await (await signedInt256TestsContract.ltTest(a, b)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(a, b)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      await (await signedInt256TestsContract.ltTest(b, a)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    // 4. Positive vs positive, left small/right small
    it("should return true for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(small, large)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
      await (await signedInt256TestsContract.ltTest(large, small)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
    })
    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return false for small positive vs small negative", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.ltTest(123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      await (await signedInt256TestsContract.ltTest(-123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    it("should return false for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(a, b)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      await (await signedInt256TestsContract.ltTest(b, a)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.ltTest(small, large)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      await (await signedInt256TestsContract.ltTest(large, small)).wait()
      expect(await signedInt256TestsContract.ltResult()).to.equal(true)
    })
  })

  describe("GE signed 256-bit integers", function () {
    it("should return true for equal small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.geTest(123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return false for small positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.geTest(123456789012345678901234567890n, 987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    it("should return true for small positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.geTest(987654321098765432109876543210n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return true for equal small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.geTest(-123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return false for small negative less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.geTest(-987654321098765432109876543210n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    it("should return true for small negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.geTest(-123456789012345678901234567890n, -987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    // 2. One < 2^128, one between 2^128 and 2^256
    it("should return false for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(small, large)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
      await (await signedInt256TestsContract.geTest(large, small)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return true for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(small, large)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
      await (await signedInt256TestsContract.geTest(large, small)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    it("should return true for small positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(small, large)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
      await (await signedInt256TestsContract.geTest(large, small)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(small, large)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
      await (await signedInt256TestsContract.geTest(large, small)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    // 3. Both above 2^128
    it("should return true for equal large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(a, a)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return false for large positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = (2n ** 200n) + 987654321098765432109876543210n
      await (await signedInt256TestsContract.geTest(a, b)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    it("should return true for large positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 987654321098765432109876543210n
      const b = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(a, b)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return true for equal large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(a, a)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return false for large negative less than another (more negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 987654321098765432109876543210n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(a, b)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    it("should return true for large negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      const b = -(2n ** 200n) - 987654321098765432109876543210n
      await (await signedInt256TestsContract.geTest(a, b)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(a, b)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
      await (await signedInt256TestsContract.geTest(b, a)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    // 4. Positive vs positive, left small/right small
    it("should return false for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(small, large)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
      await (await signedInt256TestsContract.geTest(large, small)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
    })
    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return true for small positive vs small negative", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.geTest(123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
      await (await signedInt256TestsContract.geTest(-123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(a, b)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
      await (await signedInt256TestsContract.geTest(b, a)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.geTest(small, large)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(true)
      await (await signedInt256TestsContract.geTest(large, small)).wait()
      expect(await signedInt256TestsContract.geResult()).to.equal(false)
    })
  })

  describe("LE signed 256-bit integers", function () {
    it("should return true for equal small positives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.leTest(123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return true for small positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.leTest(123456789012345678901234567890n, 987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return false for small positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.leTest(987654321098765432109876543210n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
    })
    it("should return true for equal small negatives", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.leTest(-123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return true for small negative less than another", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.leTest(-987654321098765432109876543210n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return false for small negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.leTest(-123456789012345678901234567890n, -987654321098765432109876543210n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
    })
    // 2. One < 2^128, one between 2^128 and 2^256
    it("should return true for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(small, large)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
      await (await signedInt256TestsContract.leTest(large, small)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(small, large)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
      await (await signedInt256TestsContract.leTest(large, small)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return false for small positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(small, large)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
      await (await signedInt256TestsContract.leTest(large, small)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return true for small negative vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(small, large)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
      await (await signedInt256TestsContract.leTest(large, small)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
    })
    // 3. Both above 2^128
    it("should return true for equal large positives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(a, a)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return true for large positive less than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = (2n ** 200n) + 987654321098765432109876543210n
      await (await signedInt256TestsContract.leTest(a, b)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return false for large positive greater than another", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 987654321098765432109876543210n
      const b = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(a, b)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
    })
    it("should return true for equal large negatives", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(a, a)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return true for large negative less than another (more negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 987654321098765432109876543210n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(a, b)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return false for large negative greater than another (less negative)", async function () {
      const { signedInt256TestsContract } = deployment
      const a = -(2n ** 200n) - 123456789012345678901234567890n
      const b = -(2n ** 200n) - 987654321098765432109876543210n
      await (await signedInt256TestsContract.leTest(a, b)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(a, b)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
      await (await signedInt256TestsContract.leTest(b, a)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    // 4. Positive vs positive, left small/right small
    it("should return true for small positive vs large positive", async function () {
      const { signedInt256TestsContract } = deployment
      const small = 123456789012345678901234567890n
      const large = (2n ** 200n) + 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(small, large)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
      await (await signedInt256TestsContract.leTest(large, small)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
    })
    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return false for small positive vs small negative", async function () {
      const { signedInt256TestsContract } = deployment
      await (await signedInt256TestsContract.leTest(123456789012345678901234567890n, -123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
      await (await signedInt256TestsContract.leTest(-123456789012345678901234567890n, 123456789012345678901234567890n)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    it("should return false for large positive vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const a = (2n ** 200n) + 123456789012345678901234567890n
      const b = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(a, b)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
      await (await signedInt256TestsContract.leTest(b, a)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { signedInt256TestsContract } = deployment
      const small = -123456789012345678901234567890n
      const large = -(2n ** 200n) - 123456789012345678901234567890n
      await (await signedInt256TestsContract.leTest(small, large)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(false)
      await (await signedInt256TestsContract.leTest(large, small)).wait()
      expect(await signedInt256TestsContract.leResult()).to.equal(true)
    })
  })

  describe("Offboard signed 256-bit integers", function () {
    it("Should offboard positive signed 256-bit integers", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.offBoardTest(10000000000000000000000000000000000n, 20000000000000000000000000000000000n, 30000000000000000000000000000000000n, gasOptions)).wait()

      await (await signedInt256TestsContract.onBoardTest(gasOptions)).wait()

      const decryptedInt1 = await signedInt256TestsContract.onBoardResult1()
      const decryptedInt2 = await signedInt256TestsContract.onBoardResult2()

      expect(decryptedInt1).to.equal(10000000000000000000000000000000000n)
      expect(decryptedInt2).to.equal(30000000000000000000000000000000000n)
    })

    it("Should decrypt the positive signed 256-bit integers", async function () {
      const { signedInt256TestsContract, owner } = deployment

      const encryptedInt = await signedInt256TestsContract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt256(encryptedInt)

      expect(decryptedInt).to.equal(20000000000000000000000000000000000n)
    })

    it("Should offboard negative signed 256-bit integers", async function () {
      const { signedInt256TestsContract } = deployment

      await (await signedInt256TestsContract.offBoardTest(-10000000000000000000000000000000000n, -20000000000000000000000000000000000n, -30000000000000000000000000000000000n, gasOptions)).wait()

      await (await signedInt256TestsContract.onBoardTest(gasOptions)).wait()

      const decryptedInt1 = await signedInt256TestsContract.onBoardResult1()
      const decryptedInt2 = await signedInt256TestsContract.onBoardResult2()

      expect(decryptedInt1).to.equal(-10000000000000000000000000000000000n)
      expect(decryptedInt2).to.equal(-30000000000000000000000000000000000n)
    })

    it("Should decrypt the negative signed 256-bit integers", async function () {
      const { signedInt256TestsContract, owner } = deployment

      const encryptedInt = await signedInt256TestsContract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt256(encryptedInt)

      expect(decryptedInt).to.equal(-20000000000000000000000000000000000n)
    })
  })

  describe("Mux for signed 256-bit integers", function () {
    const MAX = (1n << 255n) - 1n;
    const MIN = -(1n << 255n);
    const testCases = [
      { bit: true, a: 0n, b: 1n, expected: 1n },
      { bit: false, a: 0n, b: 1n, expected: 0n },
      { bit: true, a: -1n, b: 1n, expected: 1n },
      { bit: false, a: -1n, b: 1n, expected: -1n },
      { bit: true, a: 1n, b: -1n, expected: -1n },
      { bit: false, a: 1n, b: -1n, expected: 1n },
      { bit: true, a: MAX, b: MIN, expected: MIN },
      { bit: false, a: MAX, b: MIN, expected: MAX },
      { bit: true, a: MIN, b: MAX, expected: MAX },
      { bit: false, a: MIN, b: MAX, expected: MIN },
      { bit: true, a: 0n, b: 0n, expected: 0n },
      { bit: false, a: 0n, b: 0n, expected: 0n },
      { bit: true, a: 1234567890123456789n, b: -9876543210987654321n, expected: -9876543210987654321n },
      { bit: false, a: 1234567890123456789n, b: -9876543210987654321n, expected: 1234567890123456789n },
    ];
    for (const { bit, a, b, expected } of testCases) {
      it(`Should mux ${bit} and (${a}, ${b}) => ${expected}`, async function () {
        const { signedInt256TestsContract } = deployment;
        await (await signedInt256TestsContract.muxTest(bit, a, b)).wait();
        expect(await signedInt256TestsContract.muxResult()).to.equal(expected);
      });
    }
  });

  describe("setPublic for signed 256-bit integers", function () {
    const testCases = [
      0n,
      1n,
      -1n,
      1234567890123456789012345678901234567890n,
      -987654321098765432109876543210987654321n,
      (1n << 255n) - 1n, // max int256
      -(1n << 255n),     // min int256
    ];

    for (const value of testCases) {
      it(`Should setPublic and decrypt ${value}`, async function () {
        const { signedInt256TestsContract } = deployment;
        await (await signedInt256TestsContract.setPublicTest(value)).wait();
        const result = await signedInt256TestsContract.setPublicResult();
        expect(result).to.equal(value);
      });
    }
  });

  describe("Edge cases for signed 256-bit arithmetic", function () {
    const MAX = (1n << 255n) - 1n
    const MIN = -(1n << 255n)
    const testCases = [
      { a: 0n, b: 0n },
      { a: 1n, b: 0n },
      { a: 0n, b: 1n },
      { a: -1n, b: 0n },
      { a: 0n, b: -1n },
      { a: 1n, b: -1n },
      { a: -1n, b: 1n },
      { a: MAX, b: 1n },
      { a: MIN, b: -1n },
      { a: MAX, b: -1n },
      { a: MIN, b: 1n },
      { a: MAX, b: MAX },
      { a: MIN, b: MIN },
      { a: MAX, b: MIN },
      { a: MIN, b: MAX },
      { a: 123456789012345678901234567890n, b: -987654321098765432109876543210n },
      { a: -987654321098765432109876543210n, b: 123456789012345678901234567890n },
    ]
  
    for (const { a, b } of testCases) {
      it(`edge case 256-bit addTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        await (await arithmeticSigned256BitTestsContract.addTest([a], [b])).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a + b))
      })
      it(`edge case 256-bit subTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        await (await arithmeticSigned256BitTestsContract.subTest([a], [b], gasOptions)).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a - b))
      })
      it(`edge case 256-bit mulTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        await (await arithmeticSigned256BitTestsContract.mulTest([a], [b])).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a * b))
      })
      it(`edge case 256-bit divTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        if(b === 0n) {
          let revert = false
          try {
            await (await arithmeticSigned256BitTestsContract.divTest([a], [b], gasOptions)).wait()
          } catch (error) {
            revert = true
          }
          expect(revert).to.equal(true)
          return
        }
        await (await arithmeticSigned256BitTestsContract.divTest([a], [b], gasOptions)).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a / b))
      })
      it(`edge case 256-bit eqTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.eqTest(a, b)).wait()
        expect(await signedInt256TestsContract.eqResult()).to.equal(a === b)
        await (await signedInt256TestsContract.eqTest(a, a)).wait()
        expect(await signedInt256TestsContract.eqResult()).to.equal(true)
      })
      it(`edge case 256-bit neTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.neTest(a, b)).wait()
        expect(await signedInt256TestsContract.neResult()).to.equal(a !== b)
        await (await signedInt256TestsContract.neTest(a, a)).wait()
        expect(await signedInt256TestsContract.neResult()).to.equal(false)
      })
      it(`edge case 256-bit ltTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
          await (await signedInt256TestsContract.ltTest(a, b)).wait()
          expect(await signedInt256TestsContract.ltResult()).to.equal(a < b)
          await (await signedInt256TestsContract.ltTest(b, a)).wait()
          expect(await signedInt256TestsContract.ltResult()).to.equal(b < a)
          await (await signedInt256TestsContract.ltTest(a, a)).wait()
          expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      })
      it(`edge case 256-bit leTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.leTest(a, b)).wait()
        expect(await signedInt256TestsContract.leResult()).to.equal(a <= b)
        await (await signedInt256TestsContract.leTest(b, a)).wait()
        expect(await signedInt256TestsContract.leResult()).to.equal(b <= a)
        await (await signedInt256TestsContract.leTest(a, a)).wait()
        expect(await signedInt256TestsContract.leResult()).to.equal(true)
      })
      it(`edge case 256-bit gtTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.gtTest(a, b)).wait()
        expect(await signedInt256TestsContract.gtResult()).to.equal(a > b)
        await (await signedInt256TestsContract.gtTest(b, a)).wait()
        expect(await signedInt256TestsContract.gtResult()).to.equal(b > a)
        await (await signedInt256TestsContract.gtTest(a, a)).wait()
        expect(await signedInt256TestsContract.gtResult()).to.equal(false)
      })
      it(`edge case 256-bit geTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.geTest(a, b)).wait()
        expect(await signedInt256TestsContract.geResult()).to.equal(a >= b)
        await (await signedInt256TestsContract.geTest(b, a)).wait()
        expect(await signedInt256TestsContract.geResult()).to.equal(b >= a)
        await (await signedInt256TestsContract.geTest(a, a)).wait()
        expect(await signedInt256TestsContract.geResult()).to.equal(true)
      })
    }
  })
  
  describe("Fuzz testing signed 256-bit arithmetic", function () {
    for (let i = 0; i < 10; i++) {
      const a = randomSigned256()
      const b = randomSigned256()
      it(`fuzz 256-bit addTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        await (await arithmeticSigned256BitTestsContract.addTest([a], [b])).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a + b))
      })
      it(`fuzz 256-bit subTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        await (await arithmeticSigned256BitTestsContract.subTest([a], [b])).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a - b))
      })
      it(`fuzz 256-bit mulTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        await (await arithmeticSigned256BitTestsContract.mulTest([a], [b])).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a * b))
      })
      it(`fuzz 256-bit divTest(${a}, ${b})`, async function () {
        const { arithmeticSigned256BitTestsContract } = deployment
        if(b === 0n) {
          let revert = false
          try {
            await (await arithmeticSigned256BitTestsContract.divTest([a], [b], gasOptions)).wait()
          } catch (error) {
            revert = true
          }
          expect(revert).to.equal(true)
          return
        }
        await (await arithmeticSigned256BitTestsContract.divTest([a], [b], gasOptions)).wait()
        const decryptedInt = await arithmeticSigned256BitTestsContract.numbers(0)
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a / b))
      })
      it(`fuzz 256-bit andTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.andTest(a, b)).wait()
        const decryptedInt = await signedInt256TestsContract.andResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(256, a & b))
      })
      it(`fuzz 256-bit orTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.orTest(a, b)).wait()
        const decryptedInt = await signedInt256TestsContract.orResult()
        expect(decryptedInt).to.equal(a | b)
      })
      it(`fuzz 256-bit xorTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.xorTest(a, b)).wait()
        const decryptedInt = await signedInt256TestsContract.xorResult()
        expect(decryptedInt).to.equal(a ^ b)
      })
      it(`fuzz 256-bit eqTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.eqTest(a, b)).wait()
        expect(await signedInt256TestsContract.eqResult()).to.equal(a === b)
        await (await signedInt256TestsContract.eqTest(a, a)).wait()
        expect(await signedInt256TestsContract.eqResult()).to.equal(true)
      })
      it(`fuzz 256-bit neTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.neTest(a, b)).wait()
        expect(await signedInt256TestsContract.neResult()).to.equal(a !== b)
        await (await signedInt256TestsContract.neTest(a, a)).wait()
        expect(await signedInt256TestsContract.neResult()).to.equal(false)
      })
      it(`fuzz 256-bit ltTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
          await (await signedInt256TestsContract.ltTest(a, b)).wait()
          expect(await signedInt256TestsContract.ltResult()).to.equal(a < b)
          await (await signedInt256TestsContract.ltTest(b, a)).wait()
          expect(await signedInt256TestsContract.ltResult()).to.equal(b < a)
          await (await signedInt256TestsContract.ltTest(a, a)).wait()
          expect(await signedInt256TestsContract.ltResult()).to.equal(false)
      })
      it(`fuzz 256-bit leTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.leTest(a, b)).wait()
        expect(await signedInt256TestsContract.leResult()).to.equal(a <= b)
        await (await signedInt256TestsContract.leTest(b, a)).wait()
        expect(await signedInt256TestsContract.leResult()).to.equal(b <= a)
        await (await signedInt256TestsContract.leTest(a, a)).wait()
        expect(await signedInt256TestsContract.leResult()).to.equal(true)
      })
      it(`fuzz 256-bit gtTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.gtTest(a, b)).wait()
        expect(await signedInt256TestsContract.gtResult()).to.equal(a > b)
        await (await signedInt256TestsContract.gtTest(b, a)).wait()
        expect(await signedInt256TestsContract.gtResult()).to.equal(b > a)
        await (await signedInt256TestsContract.gtTest(a, a)).wait()
        expect(await signedInt256TestsContract.gtResult()).to.equal(false)
      })
      it(`fuzz 256-bit geTest(${a}, ${b})`, async function () {
        const { signedInt256TestsContract } = deployment
        await (await signedInt256TestsContract.geTest(a, b)).wait()
        expect(await signedInt256TestsContract.geResult()).to.equal(a >= b)
        await (await signedInt256TestsContract.geTest(b, a)).wait()
        expect(await signedInt256TestsContract.geResult()).to.equal(b >= a)
        await (await signedInt256TestsContract.geTest(a, a)).wait()
        expect(await signedInt256TestsContract.geResult()).to.equal(true)
      })
    }
  });
})