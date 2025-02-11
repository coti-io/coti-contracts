import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { itUint } from "@coti-io/coti-ethers"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("SignedIntegerTestsContract")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()

  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

function toSignedInt(value: bigint): number {
    const binaryStr = value.toString(2).padStart(8, '0')

    if (binaryStr[0] !== "1") {
        return parseInt(binaryStr, 2)
    }

    const twosComplement = parseInt(binaryStr.split('').map(bit => bit === "0" ? "1" : "0").join(""), 2) + 1
    return -twosComplement
}

describe("MPC Core", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Validating encrypted signed integers", function () {
    it("Should validate positive signed integers", async function () {
        const { contract, contractAddress, owner } = deployment

        const itValue = await owner.encryptValue(
            123,
            contractAddress,
            contract.validateCiphertextTest.fragment.selector
        ) as itUint

        await (
            await contract.validateCiphertextTest(itValue)
        ).wait()

        const decryptedInt = await contract.validateResult()

        expect(decryptedInt).to.equal(123)
    })

    it("Should validate negative signed integers", async function () {
        const { contract, contractAddress, owner } = deployment

        const itValue = await owner.encryptValue(
            -20,
            contractAddress,
            contract.validateCiphertextTest.fragment.selector
        ) as itUint

        await (
            await contract.validateCiphertextTest(itValue)
        ).wait()

        const decryptedInt = await contract.validateResult()

        expect(decryptedInt).to.equal(-20)
    })
  })

  describe("Adding signed integers", function () {
    it("Should encrypt, add and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.addTest(1, 1)
        ).wait()

        const decryptedInt = await contract.addResult()

        expect(decryptedInt).to.equal(2)
    })

    it("Should encrypt, add and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.addTest(-1, -1)
        ).wait()

        const decryptedInt = await contract.addResult()

        expect(decryptedInt).to.equal(-2)
    })

    it("Should encrypt, add and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.addTest(1, -1)
        ).wait()

        const decryptedInt = await contract.addResult()

        expect(decryptedInt).to.equal(0)
    })

    it("Should encrypt, add and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.addTest(-2, 1)
        ).wait()

        const decryptedInt = await contract.addResult()

        expect(decryptedInt).to.equal(-1)
    })
  })

  describe("Subtracting signed integers", function () {
    it("Should encrypt, subtract and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.subTest(2, 1)
        ).wait()

        const decryptedInt = await contract.subResult()

        expect(decryptedInt).to.equal(1)
    })

    it("Should encrypt, subtract and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.subTest(-40, -20)
        ).wait()

        const decryptedInt = await contract.subResult()

        expect(decryptedInt).to.equal(-20)
    })

    it("Should encrypt, subtract and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.subTest(52, -8)
        ).wait()

        const decryptedInt = await contract.subResult()

        expect(decryptedInt).to.equal(60)
    })

    it("Should encrypt, subtract and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.subTest(-14, 3)
        ).wait()

        const decryptedInt = await contract.subResult()

        expect(decryptedInt).to.equal(-17)
    })
  })

  describe("Multiplying signed integers", function () {
    it("Should encrypt, multiply and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.mulTest(3, 2)
        ).wait()

        const decryptedInt = await contract.mulResult()

        expect(decryptedInt).to.equal(6)
    })

    it("Should encrypt, multiply and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.mulTest(-3, -2)
        ).wait()

        const decryptedInt = await contract.mulResult()

        expect(decryptedInt).to.equal(6)
    })

    it("Should encrypt, multiply and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.mulTest(10, -1)
        ).wait()

        const decryptedInt = await contract.mulResult()

        expect(decryptedInt).to.equal(-10)
    })

    it("Should encrypt, multiply and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.mulTest(-4, 2)
        ).wait()

        const decryptedInt = await contract.mulResult()

        expect(decryptedInt).to.equal(-8)
    })
  })

  describe("Dividing signed integers", function () {
    it("Should encrypt, divide and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.divTest(4, 2)
        ).wait()

        const decryptedInt = await contract.divResult()

        expect(decryptedInt).to.equal(6)
    })

    it("Should encrypt, divide and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.divTest(-6, -2)
        ).wait()

        const decryptedInt = await contract.divResult()

        expect(decryptedInt).to.equal(6)
    })

    it("Should encrypt, divide and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.divTest(9, -3)
        ).wait()

        const decryptedInt = await contract.divResult()

        expect(decryptedInt).to.equal(-10)
    })

    it("Should encrypt, divide and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.divTest(12, -4)
        ).wait()

        const decryptedInt = await contract.divResult()

        expect(decryptedInt).to.equal(-8)
    })
  })

  describe("AND signed integers", function () {
    it("Should encrypt, AND and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.andTest(-15, 5)
        ).wait()

        const decryptedInt = await contract.andResult()

        expect(decryptedInt).to.equal(0)
    })

    it("Should encrypt, AND and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.andTest(-1, -1)
        ).wait()

        const decryptedInt = await contract.andResult()

        expect(decryptedInt).to.equal(-1)
    })

    it("Should encrypt, AND and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.andTest(1, -1)
        ).wait()

        const decryptedInt = await contract.andResult()

        expect(decryptedInt).to.equal(1)
    })

    it("Should encrypt, AND and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.andTest(-2, 1)
        ).wait()

        const decryptedInt = await contract.andResult()

        expect(decryptedInt).to.equal(0)
    })
  })

  describe("OR signed integers", function () {
    it("Should encrypt, OR and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.orTest(2, 1)
        ).wait()

        const decryptedInt = await contract.orResult()

        expect(decryptedInt).to.equal(3)
    })

    it("Should encrypt, OR and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.orTest(-1, -1)
        ).wait()

        const decryptedInt = await contract.orResult()

        expect(decryptedInt).to.equal(-1)
    })

    it("Should encrypt, OR and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.orTest(1, -1)
        ).wait()

        const decryptedInt = await contract.orResult()

        expect(decryptedInt).to.equal(-1)
    })

    it("Should encrypt, OR and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.orTest(-2, 1)
        ).wait()

        const decryptedInt = await contract.orResult()

        expect(decryptedInt).to.equal(-1)
    })
  })

  describe("XOR signed integers", function () {
    it("Should encrypt, XOR and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.xorTest(2, 1)
        ).wait()

        const decryptedInt = await contract.xorResult()

        expect(decryptedInt).to.equal(3)
    })

    it("Should encrypt, XOR and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.xorTest(-1, -1)
        ).wait()

        const decryptedInt = await contract.xorResult()

        expect(decryptedInt).to.equal(0)
    })

    it("Should encrypt, XOR and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.xorTest(1, -1)
        ).wait()

        const decryptedInt = await contract.xorResult()

        expect(decryptedInt).to.equal(-2)
    })

    it("Should encrypt, XOR and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.xorTest(-2, 1)
        ).wait()

        const decryptedInt = await contract.xorResult()

        expect(decryptedInt).to.equal(-1)
    })
  })

  describe("EQ signed integers", function () {
    it("Should encrypt, EQ and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.eqTest(2, 2)
        ).wait()

        const decryptedInt = await contract.eqResult()

        expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, EQ and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.eqTest(-1, -1)
        ).wait()

        const decryptedInt = await contract.eqResult()

        expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, EQ and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.eqTest(1, -1)
        ).wait()

        const decryptedInt = await contract.eqResult()

        expect(decryptedInt).to.equal(false)
    })

    it("Should encrypt, EQ and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.eqTest(-2, 1)
        ).wait()

        const decryptedInt = await contract.eqResult()

        expect(decryptedInt).to.equal(false)
    })
  })

  describe("NE signed integers", function () {
    it("Should encrypt, NE and decrypt two positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.neTest(2, 2)
        ).wait()

        const decryptedInt = await contract.neResult()

        expect(decryptedInt).to.equal(false)
    })

    it("Should encrypt, NE and decrypt two negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.neTest(-1, -1)
        ).wait()

        const decryptedInt = await contract.neResult()

        expect(decryptedInt).to.equal(false)
    })

    it("Should encrypt, NE and decrypt a positive and negative signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.neTest(1, -1)
        ).wait()

        const decryptedInt = await contract.neResult()

        expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, NE and decrypt a negative and positive signed integer", async function () {
        const { contract } = deployment

        await (
            await contract.neTest(-2, 1)
        ).wait()

        const decryptedInt = await contract.neResult()

        expect(decryptedInt).to.equal(true)
    })
  })

  describe("Offboard signed integers", function () {
    it("Should offboard positive signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.offBoardTest(2, 3, 4)
        ).wait()

        await (
            await contract.onBoardTest()
        ).wait()

        const decryptedInt1 = await contract.onBoardResult1()
        const decryptedInt2 = await contract.onBoardResult2()

        expect(decryptedInt1).to.equal(2)
        expect(decryptedInt2).to.equal(4)
    })

    it("Should decrypt the positive signed integers", async function () {
        const { contract, owner } = deployment

        const encryptedInt = await contract.offBoardToUserResult()

        const decryptedInt = await owner.decryptValue(encryptedInt)

        expect(decryptedInt).to.equal(3)
    })

    it("Should offboard negative signed integers", async function () {
        const { contract } = deployment

        await (
            await contract.offBoardTest(-10, -11, -12)
        ).wait()

        await (
            await contract.onBoardTest()
        ).wait()

        const decryptedInt1 = await contract.onBoardResult1()
        const decryptedInt2 = await contract.onBoardResult2()

        expect(decryptedInt1).to.equal(-10)
        expect(decryptedInt2).to.equal(-12)
    })

    it("Should decrypt the negative signed integers", async function () {
        const { contract, owner } = deployment

        const encryptedInt = await contract.offBoardToUserResult()

        const decryptedInt = await owner.decryptValue(encryptedInt) as bigint

        const signedInt = toSignedInt(decryptedInt)

        expect(signedInt).to.equal(-11)
    })
  })
})