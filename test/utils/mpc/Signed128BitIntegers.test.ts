import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { gasOptions, generateRandomNumber } from "./helpers";

function randomSigned128() {
  let unsigned = generateRandomNumber(16);
  // If the most significant bit is set (i.e. sign bit), convert to signed using two's complement
  const signBit = 1n << 127n
  if (unsigned & signBit) {
      // Two's complement conversion for negative numbers
      unsigned = unsigned - (1n << 128n)
  }

  return unsigned
}

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("SignedInt128TestsContract")
  const contract = await factory.connect(owner).deploy(gasOptions)
  await contract.waitForDeployment()

  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - signed 128-bit integers", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Validating encrypted signed 128-bit integers", function () {
    it("Should validate positive signed 128-bit integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const testValue = 123456789012345n
      const itValue = await owner.encryptInt128(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })

    it("Should validate negative signed 128-bit integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const testValue = -987654321098765n
      const itValue = await owner.encryptInt128(
        testValue,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(testValue)
    })
  })

  describe("Adding signed 128-bit integers", function () {
    it("Should encrypt, add and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.addTest(1000000000n, 2000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(3000000000n)
    })

    it("Should encrypt, add and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.addTest(-1000000000n, -2000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })

    it("Should encrypt, add and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.addTest(5000000000n, -3000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(2000000000n)
    })

    it("Should encrypt, add and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.addTest(-8000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-5000000000n)
    })
  })

  describe("Subtracting signed 128-bit integers", function () {
    it("Should encrypt, subtract and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.subTest(5000000000n, 2000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(3000000000n)
    })

    it("Should encrypt, subtract and decrypt two negative signed 128-bit integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(-5000000000n, -2000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })

    it("Should encrypt, subtract and decrypt a positive and negative signed 128-bit integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(5000000000n, -3000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(8000000000n)
    })

    it("Should encrypt, subtract and decrypt a negative and positive signed 128-bit integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(-8000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(-11000000000n)
    })
  })

  describe("Multiplying signed 128-bit integers", function () {
    it("Should encrypt, multiply and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.mulTest(1000000n, 2000n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(2000000000n)
    })

    it("Should encrypt, multiply and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.mulTest(-1000000n, -3000n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(3000000000n)
    })

    it("Should encrypt, multiply and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.mulTest(2000000n, -1500n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })

    it("Should encrypt, multiply and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.mulTest(-2000000n, 1500n)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(-3000000000n)
    })
  })

  describe("Dividing signed 128-bit integers", function () {
    it("Should encrypt, divide and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.divTest(6000000000n, 2000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(3n)
    })

    it("Should encrypt, divide and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.divTest(-9000000000n, -3000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(3n)
    })

    it("Should encrypt, divide and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.divTest(8000000000n, -2000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(-4n)
    })

    it("Should encrypt, divide and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.divTest(-12000000000n, 3000000000n)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(-4n)
    })
  })

  describe("AND signed 128-bit integers", function () {
    it("Should encrypt, AND and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      const a = 0xFFFFFFFn
      const b = 0x123456789n
      await (await contract.andTest(a, b)).wait()

      const decryptedInt = await contract.andResult()
      expect(decryptedInt).to.equal(BigInt.asIntN(128, a & b))
    })

    it("Should encrypt, AND and decrypt two negative signed 128-bit integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.andTest(-1n, -1n)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, AND and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.andTest(0xFFFFFFFFn, -1n)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, AND and decrypt a negative and positive signed 128-bit integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.andTest(-2n, 1n)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(0n)
    })
  })

  describe("OR signed 128-bit integers", function () {
    it("Should encrypt, OR and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.orTest(0xF0F0F0F0n, 0x0F0F0F0Fn)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, OR and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.orTest(-1n, -1n)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, OR and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.orTest(1n, -1n)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })

    it("Should encrypt, OR and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.orTest(-2n, 1n)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1n)
    })
  })

  describe("XOR signed 128-bit integers", function () {
    it("Should encrypt, XOR and decrypt two positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.xorTest(0xAAAAAAAAn, 0x55555555n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(0xFFFFFFFFn)
    })

    it("Should encrypt, XOR and decrypt two negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.xorTest(-1n, -1n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(0n)
    })

    it("Should encrypt, XOR and decrypt a positive and negative signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.xorTest(1n, -1n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(-2n)
    })

    it("Should encrypt, XOR and decrypt a negative and positive signed 128-bit integer", async function () {
      const { contract } = deployment

      await (await contract.xorTest(-2n, 1n)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(-1n)
    })
  })

  describe("EQ signed 128-bit integers", function () {
    // 1. Both numbers < 2^64
    it("should return true for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small positives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, 987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.eqTest(-123456789n, -987654321n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })

    // 2. One < 2^64, one between 2^64 and 2^128
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })

    // 3. Both above 2^64
    it("should return true for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = (2n ** 80n) + 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return true for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      await (await contract.eqTest(a, a)).wait()
      expect(await contract.eqResult()).to.equal(true)
    })
    it("should return false for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      const b = -(2n ** 80n) - 987654321n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })

    // 4. Positive vs positive, left small/right small
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })

    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.eqTest(123456789n, -123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(-123456789n, 123456789n)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.eqTest(a, b)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(b, a)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })

    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.eqTest(small, large)).wait()
      expect(await contract.eqResult()).to.equal(false)
      await (await contract.eqTest(large, small)).wait()
      expect(await contract.eqResult()).to.equal(false)
    })
  })

  describe("NE signed 128-bit integers", function () {
    // 1. Both numbers < 2^64
    it("should return false for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.neTest(123456789n, 123456789n)).wait()
      expect(await contract.neResult()).to.equal(false)
    })
    it("should return true for different small positives", async function () {
      const { contract } = deployment
      await (await contract.neTest(123456789n, 987654321n)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
    it("should return false for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.neTest(-123456789n, -123456789n)).wait()
      expect(await contract.neResult()).to.equal(false)
    })
    it("should return true for different small negatives", async function () {
      const { contract } = deployment
      await (await contract.neTest(-123456789n, -987654321n)).wait()
      expect(await contract.neResult()).to.equal(true)
    })

    // 2. One < 2^64, one between 2^64 and 2^128
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.neTest(small, large)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(large, small)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
    it("should return true for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.neTest(small, large)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(large, small)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
    it("should return true for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.neTest(small, large)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(large, small)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
    it("should return true for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.neTest(small, large)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(large, small)).wait()
      expect(await contract.neResult()).to.equal(true)
    })

    // 3. Both above 2^64
    it("should return false for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      await (await contract.neTest(a, a)).wait()
      expect(await contract.neResult()).to.equal(false)
    })
    it("should return true for different large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = (2n ** 80n) + 987654321n
      await (await contract.neTest(a, b)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
    it("should return false for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      await (await contract.neTest(a, a)).wait()
      expect(await contract.neResult()).to.equal(false)
    })
    it("should return true for different large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      const b = -(2n ** 80n) - 987654321n
      await (await contract.neTest(a, b)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.neTest(a, b)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(b, a)).wait()
      expect(await contract.neResult()).to.equal(true)
    })

    // 4. Positive vs positive, left small/right small
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.neTest(small, large)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(large, small)).wait()
      expect(await contract.neResult()).to.equal(true)
    })

    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return true for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.neTest(123456789n, -123456789n)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(-123456789n, 123456789n)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.neTest(a, b)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(b, a)).wait()
      expect(await contract.neResult()).to.equal(true)
    })

    // 6. Negative vs negative, left small/right small
    it("should return true for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.neTest(small, large)).wait()
      expect(await contract.neResult()).to.equal(true)
      await (await contract.neTest(large, small)).wait()
      expect(await contract.neResult()).to.equal(true)
    })
  })

  describe("GT signed 128-bit integers", function () {
    // 1. Both numbers < 2^64
    it("should return false for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.gtTest(123456789n, 123456789n)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return false for small positive less than another", async function () {
      const { contract } = deployment
      await (await contract.gtTest(123456789n, 987654321n)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return true for small positive greater than another", async function () {
      const { contract } = deployment
      await (await contract.gtTest(987654321n, 123456789n)).wait()
      expect(await contract.gtResult()).to.equal(true)
    })
    it("should return false for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.gtTest(-123456789n, -123456789n)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return false for small negative less than another", async function () {
      const { contract } = deployment
      await (await contract.gtTest(-987654321n, -123456789n)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return true for small negative greater than another (less negative)", async function () {
      const { contract } = deployment
      await (await contract.gtTest(-123456789n, -987654321n)).wait()
      expect(await contract.gtResult()).to.equal(true)
    })

    // 2. One < 2^64, one between 2^64 and 2^128
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.gtTest(small, large)).wait()
      expect(await contract.gtResult()).to.equal(false)

      await (await contract.gtTest(large, small)).wait()
      expect(await contract.gtResult()).to.equal(true)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.gtTest(small, large)).wait()
      expect(await contract.gtResult()).to.equal(true)

      await (await contract.gtTest(large, small)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return true for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.gtTest(small, large)).wait()
      expect(await contract.gtResult()).to.equal(true)
      await (await contract.gtTest(large, small)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.gtTest(small, large)).wait()
      expect(await contract.gtResult()).to.equal(false)

      await (await contract.gtTest(large, small)).wait()
      expect(await contract.gtResult()).to.equal(true)
    })

    // 3. Both above 2^64
    it("should return false for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      await (await contract.gtTest(a, a)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return false for large positive less than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = (2n ** 80n) + 987654321n
      await (await contract.gtTest(a, b)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return true for large positive greater than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 987654321n
      const b = (2n ** 80n) + 123456789n
      await (await contract.gtTest(a, b)).wait()
      expect(await contract.gtResult()).to.equal(true)
    })
    it("should return false for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      await (await contract.gtTest(a, a)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return false for large negative less than another (more negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 987654321n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.gtTest(a, b)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return true for large negative greater than another (less negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      const b = -(2n ** 80n) - 987654321n
      await (await contract.gtTest(a, b)).wait()
      expect(await contract.gtResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.gtTest(a, b)).wait()
      expect(await contract.gtResult()).to.equal(true)

      await (await contract.gtTest(b, a)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })

    // 4. Positive vs positive, left small/right small
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.gtTest(small, large)).wait()
      expect(await contract.gtResult()).to.equal(false)
      await (await contract.gtTest(large, small)).wait()
      expect(await contract.gtResult()).to.equal(true)
    })

    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return true for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.gtTest(123456789n, -123456789n)).wait()
      expect(await contract.gtResult()).to.equal(true)

      await (await contract.gtTest(-123456789n, 123456789n)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.gtTest(a, b)).wait()
      expect(await contract.gtResult()).to.equal(true)

      await (await contract.gtTest(b, a)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })

    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.gtTest(small, large)).wait()
      expect(await contract.gtResult()).to.equal(true)

      await (await contract.gtTest(large, small)).wait()
      expect(await contract.gtResult()).to.equal(false)
    })
  })

  describe("LE signed 128-bit integers", function () {
    it("should return true for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.leTest(123456789n, 123456789n)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return true for small positive less than another", async function () {
      const { contract } = deployment
      await (await contract.leTest(123456789n, 987654321n)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return false for small positive greater than another", async function () {
      const { contract } = deployment
      await (await contract.leTest(987654321n, 123456789n)).wait()
      expect(await contract.leResult()).to.equal(false)
    })
    it("should return true for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.leTest(-123456789n, -123456789n)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return true for small negative less than another", async function () {
      const { contract } = deployment
      await (await contract.leTest(-987654321n, -123456789n)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return false for small negative greater than another (less negative)", async function () {
      const { contract } = deployment
      await (await contract.leTest(-123456789n, -987654321n)).wait()
      expect(await contract.leResult()).to.equal(false)
    })
    // 2. One < 2^64, one between 2^64 and 2^128
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.leTest(small, large)).wait()
      expect(await contract.leResult()).to.equal(true)
      await (await contract.leTest(large, small)).wait()
      expect(await contract.leResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.leTest(small, large)).wait()
      expect(await contract.leResult()).to.equal(false)
      await (await contract.leTest(large, small)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.leTest(small, large)).wait()
      expect(await contract.leResult()).to.equal(false)
      await (await contract.leTest(large, small)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return true for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.leTest(small, large)).wait()
      expect(await contract.leResult()).to.equal(true)
      await (await contract.leTest(large, small)).wait()
      expect(await contract.leResult()).to.equal(false)
    })
    // 3. Both above 2^64
    it("should return true for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      await (await contract.leTest(a, a)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return true for large positive less than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = (2n ** 80n) + 987654321n
      await (await contract.leTest(a, b)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return false for large positive greater than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 987654321n
      const b = (2n ** 80n) + 123456789n
      await (await contract.leTest(a, b)).wait()
      expect(await contract.leResult()).to.equal(false)
    })
    it("should return true for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      await (await contract.leTest(a, a)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return true for large negative less than another (more negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 987654321n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.leTest(a, b)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return false for large negative greater than another (less negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      const b = -(2n ** 80n) - 987654321n
      await (await contract.leTest(a, b)).wait()
      expect(await contract.leResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.leTest(a, b)).wait()
      expect(await contract.leResult()).to.equal(false)
      await (await contract.leTest(b, a)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    // 4. Positive vs positive, left small/right small
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.leTest(small, large)).wait()
      expect(await contract.leResult()).to.equal(true)
      await (await contract.leTest(large, small)).wait()
      expect(await contract.leResult()).to.equal(false)
    })
    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.leTest(123456789n, -123456789n)).wait()
      expect(await contract.leResult()).to.equal(false)
      await (await contract.leTest(-123456789n, 123456789n)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.leTest(a, b)).wait()
      expect(await contract.leResult()).to.equal(false)
      await (await contract.leTest(b, a)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.leTest(small, large)).wait()
      expect(await contract.leResult()).to.equal(false)
      await (await contract.leTest(large, small)).wait()
      expect(await contract.leResult()).to.equal(true)
    })
  })

  describe("GE signed 128-bit integers", function () {
    it("should return true for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.geTest(123456789n, 123456789n)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return false for small positive less than another", async function () {
      const { contract } = deployment
      await (await contract.geTest(123456789n, 987654321n)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    it("should return true for small positive greater than another", async function () {
      const { contract } = deployment
      await (await contract.geTest(987654321n, 123456789n)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return true for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.geTest(-123456789n, -123456789n)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return false for small negative less than another", async function () {
      const { contract } = deployment
      await (await contract.geTest(-987654321n, -123456789n)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    it("should return true for small negative greater than another (less negative)", async function () {
      const { contract } = deployment
      await (await contract.geTest(-123456789n, -987654321n)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    // 2. One < 2^64, one between 2^64 and 2^128
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.geTest(small, large)).wait()
      expect(await contract.geResult()).to.equal(false)
      await (await contract.geTest(large, small)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return true for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.geTest(small, large)).wait()
      expect(await contract.geResult()).to.equal(true)
      await (await contract.geTest(large, small)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    it("should return true for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.geTest(small, large)).wait()
      expect(await contract.geResult()).to.equal(true)
      await (await contract.geTest(large, small)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    it("should return false for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.geTest(small, large)).wait()
      expect(await contract.geResult()).to.equal(false)
      await (await contract.geTest(large, small)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    // 3. Both above 2^64
    it("should return true for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      await (await contract.geTest(a, a)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return false for large positive less than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = (2n ** 80n) + 987654321n
      await (await contract.geTest(a, b)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    it("should return true for large positive greater than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 987654321n
      const b = (2n ** 80n) + 123456789n
      await (await contract.geTest(a, b)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return true for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      await (await contract.geTest(a, a)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return false for large negative less than another (more negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 987654321n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.geTest(a, b)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    it("should return true for large negative greater than another (less negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      const b = -(2n ** 80n) - 987654321n
      await (await contract.geTest(a, b)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.geTest(a, b)).wait()
      expect(await contract.geResult()).to.equal(true)
      await (await contract.geTest(b, a)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    // 4. Positive vs positive, left small/right small
    it("should return false for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.geTest(small, large)).wait()
      expect(await contract.geResult()).to.equal(false)
      await (await contract.geTest(large, small)).wait()
      expect(await contract.geResult()).to.equal(true)
    })
    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return true for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.geTest(123456789n, -123456789n)).wait()
      expect(await contract.geResult()).to.equal(true)
      await (await contract.geTest(-123456789n, 123456789n)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    it("should return true for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.geTest(a, b)).wait()
      expect(await contract.geResult()).to.equal(true)
      await (await contract.geTest(b, a)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.geTest(small, large)).wait()
      expect(await contract.geResult()).to.equal(true)
      await (await contract.geTest(large, small)).wait()
      expect(await contract.geResult()).to.equal(false)
    })
  })

  describe("LT signed 128-bit integers", function () {
    it("should return false for equal small positives", async function () {
      const { contract } = deployment
      await (await contract.ltTest(123456789n, 123456789n)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return true for small positive less than another", async function () {
      const { contract } = deployment
      await (await contract.ltTest(123456789n, 987654321n)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    it("should return false for small positive greater than another", async function () {
      const { contract } = deployment
      await (await contract.ltTest(987654321n, 123456789n)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return false for equal small negatives", async function () {
      const { contract } = deployment
      await (await contract.ltTest(-123456789n, -123456789n)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return true for small negative less than another", async function () {
      const { contract } = deployment
      await (await contract.ltTest(-987654321n, -123456789n)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    it("should return false for small negative greater than another (less negative)", async function () {
      const { contract } = deployment
      await (await contract.ltTest(-123456789n, -987654321n)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    // 2. One < 2^64, one between 2^64 and 2^128
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.ltTest(small, large)).wait()
      expect(await contract.ltResult()).to.equal(true)
      await (await contract.ltTest(large, small)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.ltTest(small, large)).wait()
      expect(await contract.ltResult()).to.equal(false)
      await (await contract.ltTest(large, small)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    it("should return false for small positive vs large negative", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.ltTest(small, large)).wait()
      expect(await contract.ltResult()).to.equal(false)
      await (await contract.ltTest(large, small)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    it("should return true for small negative vs large positive", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.ltTest(small, large)).wait()
      expect(await contract.ltResult()).to.equal(true)
      await (await contract.ltTest(large, small)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    // 3. Both above 2^64
    it("should return false for equal large positives", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      await (await contract.ltTest(a, a)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return true for large positive less than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = (2n ** 80n) + 987654321n
      await (await contract.ltTest(a, b)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    it("should return false for large positive greater than another", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 987654321n
      const b = (2n ** 80n) + 123456789n
      await (await contract.ltTest(a, b)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return false for equal large negatives", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      await (await contract.ltTest(a, a)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return true for large negative less than another (more negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 987654321n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.ltTest(a, b)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    it("should return false for large negative greater than another (less negative)", async function () {
      const { contract } = deployment
      const a = -(2n ** 80n) - 123456789n
      const b = -(2n ** 80n) - 987654321n
      await (await contract.ltTest(a, b)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.ltTest(a, b)).wait()
      expect(await contract.ltResult()).to.equal(false)
      await (await contract.ltTest(b, a)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    // 4. Positive vs positive, left small/right small
    it("should return true for small positive vs large positive", async function () {
      const { contract } = deployment
      const small = 123456789n
      const large = (2n ** 80n) + 123456789n
      await (await contract.ltTest(small, large)).wait()
      expect(await contract.ltResult()).to.equal(true)
      await (await contract.ltTest(large, small)).wait()
      expect(await contract.ltResult()).to.equal(false)
    })
    // 5. Positive vs negative, left small/right small, left negative/positive
    it("should return false for small positive vs small negative", async function () {
      const { contract } = deployment
      await (await contract.ltTest(123456789n, -123456789n)).wait()
      expect(await contract.ltResult()).to.equal(false)
      await (await contract.ltTest(-123456789n, 123456789n)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    it("should return false for large positive vs large negative", async function () {
      const { contract } = deployment
      const a = (2n ** 80n) + 123456789n
      const b = -(2n ** 80n) - 123456789n
      await (await contract.ltTest(a, b)).wait()
      expect(await contract.ltResult()).to.equal(false)
      await (await contract.ltTest(b, a)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
    // 6. Negative vs negative, left small/right small
    it("should return false for small negative vs large negative", async function () {
      const { contract } = deployment
      const small = -123456789n
      const large = -(2n ** 80n) - 123456789n
      await (await contract.ltTest(small, large)).wait()
      expect(await contract.ltResult()).to.equal(false)
      await (await contract.ltTest(large, small)).wait()
      expect(await contract.ltResult()).to.equal(true)
    })
  })

  describe("Offboard signed 128-bit integers", function () {
    it("Should offboard positive signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.offBoardTest(1000000000n, 2000000000n, 3000000000n)).wait()

      await (await contract.onBoardTest()).wait()

      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()

      expect(decryptedInt1).to.equal(1000000000n)
      expect(decryptedInt2).to.equal(3000000000n)
    })

    it("Should decrypt the positive signed 128-bit integers", async function () {
      const { contract, owner } = deployment

      const encryptedInt = await contract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt128(encryptedInt)

      expect(decryptedInt).to.equal(2000000000n)
    })

    it("Should offboard negative signed 128-bit integers", async function () {
      const { contract } = deployment

      await (await contract.offBoardTest(-1000000000n, -2000000000n, -3000000000n)).wait()

      await (await contract.onBoardTest()).wait()

      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()

      expect(decryptedInt1).to.equal(-1000000000n)
      expect(decryptedInt2).to.equal(-3000000000n)
    })

    it("Should decrypt the negative signed 128-bit integers", async function () {
      const { contract, owner } = deployment

      const encryptedInt = await contract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt128(encryptedInt)

      expect(decryptedInt).to.equal(-2000000000n)
    })
  })

  describe("Mux for signed 128-bit integers", function () {
    const MAX = (1n << 127n) - 1n;
    const MIN = -(1n << 127n);
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
        const { contract } = deployment;
        await (await contract.muxTest(bit, a, b)).wait();
        expect(await contract.muxResult()).to.equal(expected);
      });
    }
  });

  describe("setPublic for signed 128-bit integers", function () {
    const testCases = [
      0n,
      1n,
      -1n,
      123456789012345n,
      -98765432109876n,
      (1n << 127n) - 1n, // max int128
      -(1n << 127n),     // min int128
    ];

    for (const value of testCases) {
      it(`Should setPublic and decrypt ${value}`, async function () {
        const { contract } = deployment;
        await (await contract.setPublicTest(value)).wait();
        const result = await contract.setPublicResult();
        expect(result).to.equal(value);
      });
    }
  });

  describe("Edge cases for signed 128-bit arithmetic", function () {
    let deployment: Awaited<ReturnType<typeof deploy>>
    before(async function () { deployment = await deploy() })
  
    const MAX = (1n << 127n) - 1n
    const MIN = -(1n << 127n)
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
      { a: 123456789n, b: -987654321n },
      { a: -987654321n, b: 123456789n },
    ]
  
    for (const { a, b } of testCases) {
      it(`edge case 128-bit addTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.addTest(a, b)).wait()
        const decryptedInt = await contract.addResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a + b))
      })
      it(`edge case 128-bit subTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.subTest(a, b)).wait()
        const decryptedInt = await contract.subResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a - b))
      })
      it(`edge case 128-bit mulTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.mulTest(a, b)).wait()
        const decryptedInt = await contract.mulResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a * b))
      })
      it(`edge case 128-bit divTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        if(b === 0n) {
          let revert = false
          try {
            await (await contract.divTest(a, b, gasOptions)).wait()
          } catch (error) {
            revert = true
          }
          expect(revert).to.equal(true)
          return
        }
        await (await contract.divTest(a, b, gasOptions)).wait()
        const decryptedInt = await contract.divResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a / b))
      })
      it(`edge case 128-bit eqTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(a === b)
        await (await contract.eqTest(a, a)).wait()
        expect(await contract.eqResult()).to.equal(true)
      })
      it(`edge case 128-bit neTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.neTest(a, b)).wait()
        expect(await contract.neResult()).to.equal(a !== b)
        await (await contract.neTest(a, a)).wait()
        expect(await contract.neResult()).to.equal(false)
      })
      it(`edge case 128-bit ltTest(${a}, ${b})`, async function () {
        const { contract } = deployment
          await (await contract.ltTest(a, b)).wait()
          expect(await contract.ltResult()).to.equal(a < b)
          await (await contract.ltTest(b, a)).wait()
          expect(await contract.ltResult()).to.equal(b < a)
          await (await contract.ltTest(a, a)).wait()
          expect(await contract.ltResult()).to.equal(false)
      })
      it(`edge case 128-bit leTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.leTest(a, b)).wait()
        expect(await contract.leResult()).to.equal(a <= b)
        await (await contract.leTest(b, a)).wait()
        expect(await contract.leResult()).to.equal(b <= a)
        await (await contract.leTest(a, a)).wait()
        expect(await contract.leResult()).to.equal(true)
      })
      it(`edge case 128-bit gtTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.gtTest(a, b)).wait()
        expect(await contract.gtResult()).to.equal(a > b)
        await (await contract.gtTest(b, a)).wait()
        expect(await contract.gtResult()).to.equal(b > a)
        await (await contract.gtTest(a, a)).wait()
        expect(await contract.gtResult()).to.equal(false)
      })
      it(`edge case 128-bit geTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.geTest(a, b)).wait()
        expect(await contract.geResult()).to.equal(a >= b)
        await (await contract.geTest(b, a)).wait()
        expect(await contract.geResult()).to.equal(b >= a)
        await (await contract.geTest(a, a)).wait()
        expect(await contract.geResult()).to.equal(true)
      })
    }
  })
  
  describe("Fuzz testing signed 128-bit arithmetic", function () {
    let deployment: Awaited<ReturnType<typeof deploy>>
    before(async function () { deployment = await deploy() })
  
    for (let i = 0; i < 10; i++) {
      const a = randomSigned128()
      const b = randomSigned128()
      it(`fuzz 128-bit addTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.addTest(a, b)).wait()
        const decryptedInt = await contract.addResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a + b))
      })
      it(`fuzz 128-bit subTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.subTest(a, b)).wait()
        const decryptedInt = await contract.subResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a - b))
      })
      it(`fuzz 128-bit mulTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.mulTest(a, b)).wait()
        const decryptedInt = await contract.mulResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a * b))
      })
      it(`fuzz 128-bit divTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        if(b === 0n) {
          let revert = false
          try {
            await (await contract.divTest(a, b, gasOptions)).wait()
          } catch (error) {
            revert = true
          }
          expect(revert).to.equal(true)
          return
        }
        await (await contract.divTest(a, b, gasOptions)).wait()
        const decryptedInt = await contract.divResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a / b))
      })
      it(`fuzz 128-bit andTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.andTest(a, b)).wait()
        const decryptedInt = await contract.andResult()
        expect(decryptedInt).to.equal(BigInt.asIntN(128, a & b))
      })
      it(`fuzz 128-bit orTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.orTest(a, b)).wait()
        const decryptedInt = await contract.orResult()
        expect(decryptedInt).to.equal(a | b)
      })
      it(`fuzz 128-bit xorTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.xorTest(a, b)).wait()
        const decryptedInt = await contract.xorResult()
        expect(decryptedInt).to.equal(a ^ b)
      })
      it(`fuzz 128-bit eqTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.eqTest(a, b)).wait()
        expect(await contract.eqResult()).to.equal(a === b)
        await (await contract.eqTest(a, a)).wait()
        expect(await contract.eqResult()).to.equal(true)
      })
      it(`fuzz 128-bit neTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.neTest(a, b)).wait()
        expect(await contract.neResult()).to.equal(a !== b)
        await (await contract.neTest(a, a)).wait()
        expect(await contract.neResult()).to.equal(false)
      })
      it(`fuzz 128-bit ltTest(${a}, ${b})`, async function () {
        const { contract } = deployment
          await (await contract.ltTest(a, b)).wait()
          expect(await contract.ltResult()).to.equal(a < b)
          await (await contract.ltTest(b, a)).wait()
          expect(await contract.ltResult()).to.equal(b < a)
          await (await contract.ltTest(a, a)).wait()
          expect(await contract.ltResult()).to.equal(false)
      })
      it(`fuzz 128-bit leTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.leTest(a, b)).wait()
        expect(await contract.leResult()).to.equal(a <= b)
        await (await contract.leTest(b, a)).wait()
        expect(await contract.leResult()).to.equal(b <= a)
        await (await contract.leTest(a, a)).wait()
        expect(await contract.leResult()).to.equal(true)
      })
      it(`fuzz 128-bit gtTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.gtTest(a, b)).wait()
        expect(await contract.gtResult()).to.equal(a > b)
        await (await contract.gtTest(b, a)).wait()
        expect(await contract.gtResult()).to.equal(b > a)
        await (await contract.gtTest(a, a)).wait()
        expect(await contract.gtResult()).to.equal(false)
      })
      it(`fuzz 128-bit geTest(${a}, ${b})`, async function () {
        const { contract } = deployment
        await (await contract.geTest(a, b)).wait()
        expect(await contract.geResult()).to.equal(a >= b)
        await (await contract.geTest(b, a)).wait()
        expect(await contract.geResult()).to.equal(b >= a)
        await (await contract.geTest(a, a)).wait()
        expect(await contract.geResult()).to.equal(true)
      })
    }
  }) 
})
