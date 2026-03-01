import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { gasOptions, generateRandomNumber } from "./helpers";

function randomSigned32() {
  let unsigned = generateRandomNumber(4);
  // If the most significant bit is set (i.e. sign bit), convert to signed using two's complement
  const signBit = 1n << 31n;
  if (unsigned & signBit) {
      unsigned = unsigned - (1n << 32n);
  }
  return unsigned;
}


async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("SignedInt32TestsContract")
  const contract = await factory.connect(owner).deploy(gasOptions)
  await contract.waitForDeployment()

  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("MPC Core - signed 32-bit integers", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Validating encrypted signed integers", function () {
    it("Should validate positive signed integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const itValue = await owner.encryptInt32(
        123,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(123)
    })

    it("Should validate negative signed integers", async function () {
      const { contract, contractAddress, owner } = deployment

      const itValue = await owner.encryptInt32(
        -20,
        contractAddress,
        contract.validateCiphertextTest.fragment.selector
      )

      await (await contract.validateCiphertextTest(itValue)).wait()

      const decryptedInt = await contract.validateResult()

      expect(decryptedInt).to.equal(-20)
    })
  })

  describe("Adding signed integers", function () {
    it("Should encrypt, add and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.addTest(1, 1)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(2)
    })

    it("Should encrypt, add and decrypt two negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.addTest(-1, -1)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-2)
    })

    it("Should encrypt, add and decrypt a positive and negative signed integer", async function () {
      const { contract } = deployment

      await (await contract.addTest(1, -1)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(0)
    })

    it("Should encrypt, add and decrypt a negative and positive signed integer", async function () {
      const { contract } = deployment

      await (await contract.addTest(-2, 1)).wait()

      const decryptedInt = await contract.addResult()

      expect(decryptedInt).to.equal(-1)
    })
  })

  describe("Subtracting signed integers", function () {
    it("Should encrypt, subtract and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.subTest(2, 1)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(1)
    })

    it("Should encrypt, subtract and decrypt two negative signed integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(-40, -20)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(-20)
    })

    it("Should encrypt, subtract and decrypt a positive and negative signed integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(52, -8)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(60)
    })

    it("Should encrypt, subtract and decrypt a negative and positive signed integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.subTest(-14, 3)).wait()

      const decryptedInt = await contract.subResult()

      expect(decryptedInt).to.equal(-17)
    })
  })

  describe("Multiplying signed integers", function () {
    it("Should encrypt, multiply and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.mulTest(3, 2)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(6)
    })

    it("Should encrypt, multiply and decrypt two negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.mulTest(-3, -2)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(6)
    })

    it("Should encrypt, multiply and decrypt a positive and negative signed integer", async function () {
      const { contract } = deployment

      await (await contract.mulTest(10, -1)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(-10)
    })

    it("Should encrypt, multiply and decrypt a negative and positive signed integer", async function () {
      const { contract } = deployment

      await (await contract.mulTest(-4, 2)).wait()

      const decryptedInt = await contract.mulResult()

      expect(decryptedInt).to.equal(-8)
    })
  })

  describe("Dividing signed integers", function () {
    it("Should encrypt, divide and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.divTest(4, 2)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(2)
    })

    it("Should encrypt, divide and decrypt two negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.divTest(-6, -2)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(3)
    })

    it("Should encrypt, divide and decrypt a positive and negative signed integer", async function () {
      const { contract } = deployment

      await (await contract.divTest(9, -3)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(-3)
    })

    it("Should encrypt, divide and decrypt a negative and positive signed integer", async function () {
      const { contract } = deployment

      await (await contract.divTest(12, -4)).wait()

      const decryptedInt = await contract.divResult()

      expect(decryptedInt).to.equal(-3)
    })
  })

  describe("AND signed integers", function () {
    it("Should encrypt, AND and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.andTest(-15, 5)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(1)
    })

    it("Should encrypt, AND and decrypt two negative signed integers", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.andTest(-1, -1)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(-1)
    })

    it("Should encrypt, AND and decrypt a positive and negative signed integer", async function () {
      const { contract } = deployment

      await (await contract.andTest(1, -1)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(1)
    })

    it("Should encrypt, AND and decrypt a negative and positive signed integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.andTest(-2, 1)).wait()

      const decryptedInt = await contract.andResult()

      expect(decryptedInt).to.equal(0)
    })
  })

  describe("OR signed integers", function () {
    it("Should encrypt, OR and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.orTest(2, 1)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(3)
    })

    it("Should encrypt, OR and decrypt two negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.orTest(-1, -1)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1)
    })

    it("Should encrypt, OR and decrypt a positive and negative signed integer", async function () {
      const { contract } = deployment

      await (await contract.orTest(1, -1)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1)
    })

    it("Should encrypt, OR and decrypt a negative and positive signed integer", async function () {
      const { contract } = deployment

      await (await contract.orTest(-2, 1)).wait()

      const decryptedInt = await contract.orResult()

      expect(decryptedInt).to.equal(-1)
    })
  })

  describe("XOR signed integers", function () {
    it("Should encrypt, XOR and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.xorTest(2, 1)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(3)
    })

    it("Should encrypt, XOR and decrypt two negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.xorTest(-1, -1)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(0)
    })

    it("Should encrypt, XOR and decrypt a positive and negative signed integer", async function () {
      const { contract } = deployment

      await (await contract.xorTest(1, -1)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(-2)
    })

    it("Should encrypt, XOR and decrypt a negative and positive signed integer", async function () {
      const { contract } = deployment

      await (await contract.xorTest(-2, 1)).wait()

      const decryptedInt = await contract.xorResult()

      expect(decryptedInt).to.equal(-1)
    })
  })

  describe("EQ signed integers", function () {
    it("Should encrypt, EQ and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.eqTest(2, 2)).wait()

      const decryptedInt = await contract.eqResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, EQ and decrypt two negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.eqTest(-1, -1)).wait()

      const decryptedInt = await contract.eqResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, EQ and decrypt a positive and negative signed integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.eqTest(1, -1)).wait()

      const decryptedInt = await contract.eqResult()

      expect(decryptedInt).to.equal(false)
    })

    it("Should encrypt, EQ and decrypt a negative and positive signed integer", async function () {
      // Deploy fresh contract to avoid state pollution
      const freshDeployment = await deploy()
      const { contract } = freshDeployment

      await (await contract.eqTest(-2, 1)).wait()

      const decryptedInt = await contract.eqResult()

      expect(decryptedInt).to.equal(false)
    })
  })

  describe("NE signed integers", function () {
    it("Should encrypt, NE and decrypt two positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.neTest(2, 2)).wait()

      const decryptedInt = await contract.neResult()

      expect(decryptedInt).to.equal(false)
    })

    it("Should encrypt, NE and decrypt two negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.neTest(-1, -1)).wait()

      const decryptedInt = await contract.neResult()

      expect(decryptedInt).to.equal(false)
    })

    it("Should encrypt, NE and decrypt a positive and negative signed integer", async function () {
      const { contract } = deployment

      await (await contract.neTest(1, -1)).wait()

      const decryptedInt = await contract.neResult()

      expect(decryptedInt).to.equal(true)
    })

    it("Should encrypt, NE and decrypt a negative and positive signed integer", async function () {
      const { contract } = deployment

      await (await contract.neTest(-2, 1)).wait()

      const decryptedInt = await contract.neResult()

      expect(decryptedInt).to.equal(true)
    })
  })

  describe("Offboard signed integers", function () {
    it("Should offboard positive signed integers", async function () {
      const { contract } = deployment

      await (await contract.offBoardTest(2, 3, 4)).wait()

      await (await contract.onBoardTest()).wait()

      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()

      expect(decryptedInt1).to.equal(2)
      expect(decryptedInt2).to.equal(4)
    })

    it("Should decrypt the positive signed integers", async function () {
      const { contract, owner } = deployment

      const encryptedInt = await contract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt32(encryptedInt)

      expect(decryptedInt).to.equal(3)
    })

    it("Should offboard negative signed integers", async function () {
      const { contract } = deployment

      await (await contract.offBoardTest(-10, -11, -12)).wait()

      await (await contract.onBoardTest()).wait()

      const decryptedInt1 = await contract.onBoardResult1()
      const decryptedInt2 = await contract.onBoardResult2()

      expect(decryptedInt1).to.equal(-10)
      expect(decryptedInt2).to.equal(-12)
    })

    it("Should decrypt the negative signed integers", async function () {
      const { contract, owner } = deployment

      const encryptedInt = await contract.offBoardToUserResult()

      const decryptedInt = await owner.decryptInt32(encryptedInt)

      expect(decryptedInt).to.equal(-11n)
    })
  })

  describe("GT signed 32-bit integers", function () {
    it("should return true for gtTest(12345, 6789) (pos, pos)", async function () {
      const { contract } = deployment;
      await (await contract.gtTest(12345n, 6789n)).wait();
      expect(await contract.gtResult()).to.equal(true);
    });
    it("should return true for gtTest(12345, -6789) (pos, neg)", async function () {
      const { contract } = deployment;
      await (await contract.gtTest(12345n, -6789n)).wait();
      expect(await contract.gtResult()).to.equal(true);
    });
    it("should return false for gtTest(-12345, 6789) (neg, pos)", async function () {
      const { contract } = deployment;
      await (await contract.gtTest(-12345n, 6789n)).wait();
      expect(await contract.gtResult()).to.equal(false);
    });
    it("should return false for gtTest(-12345, -6789) (neg, neg)", async function () {
      const { contract } = deployment;
      await (await contract.gtTest(-12345n, -6789n)).wait();
      expect(await contract.gtResult()).to.equal(false);
    });
    it("should return true for gtTest(12345, 12345) (equal pos)", async function () {
      const { contract } = deployment;
      await (await contract.gtTest(12345n, 12345n)).wait();
      expect(await contract.gtResult()).to.equal(false);
    });
    it("should return false for gtTest(-12345, -12345) (equal neg)", async function () {
      const { contract } = deployment;
      await (await contract.gtTest(-12345n, -12345n)).wait();
      expect(await contract.gtResult()).to.equal(false);
    });
  });

  describe("GE signed 32-bit integers", function () {
    it("should return true for geTest(12345, 6789) (pos, pos)", async function () {
      const { contract } = deployment;
      await (await contract.geTest(12345n, 6789n)).wait();
      expect(await contract.geResult()).to.equal(true);
    });
    it("should return true for geTest(12345, -6789) (pos, neg)", async function () {
      const { contract } = deployment;
      await (await contract.geTest(12345n, -6789n)).wait();
      expect(await contract.geResult()).to.equal(true);
    });
    it("should return false for geTest(-12345, 6789) (neg, pos)", async function () {
      const { contract } = deployment;
      await (await contract.geTest(-12345n, 6789n)).wait();
      expect(await contract.geResult()).to.equal(false);
    });
    it("should return false for geTest(-12345, -6789) (neg, neg)", async function () {
      const { contract } = deployment;
      await (await contract.geTest(-12345n, -6789n)).wait();
      expect(await contract.geResult()).to.equal(false);
    });
    it("should return true for geTest(12345, 12345) (equal pos)", async function () {
      const { contract } = deployment;
      await (await contract.geTest(12345n, 12345n)).wait();
      expect(await contract.geResult()).to.equal(true);
    });
    it("should return true for geTest(-12345, -12345) (equal neg)", async function () {
      const { contract } = deployment;
      await (await contract.geTest(-12345n, -12345n)).wait();
      expect(await contract.geResult()).to.equal(true);
    });
  });

  describe("LT signed 32-bit integers", function () {
    it("should return false for ltTest(12345, 6789) (pos, pos)", async function () {
      const { contract } = deployment;
      await (await contract.ltTest(12345n, 6789n)).wait();
      expect(await contract.ltResult()).to.equal(false);
    });
    it("should return false for ltTest(12345, -6789) (pos, neg)", async function () {
      const { contract } = deployment;
      await (await contract.ltTest(12345n, -6789n)).wait();
      expect(await contract.ltResult()).to.equal(false);
    });
    it("should return true for ltTest(-12345, 6789) (neg, pos)", async function () {
      const { contract } = deployment;
      await (await contract.ltTest(-12345n, 6789n)).wait();
      expect(await contract.ltResult()).to.equal(true);
    });
    it("should return true for ltTest(-12345, -6789) (neg, neg)", async function () {
      const { contract } = deployment;
      await (await contract.ltTest(-12345n, -6789n)).wait();
      expect(await contract.ltResult()).to.equal(true);
    });
    it("should return false for ltTest(12345, 12345) (equal pos)", async function () {
      const { contract } = deployment;
      await (await contract.ltTest(12345n, 12345n)).wait();
      expect(await contract.ltResult()).to.equal(false);
    });
    it("should return false for ltTest(-12345, -12345) (equal neg)", async function () {
      const { contract } = deployment;
      await (await contract.ltTest(-12345n, -12345n)).wait();
      expect(await contract.ltResult()).to.equal(false);
    });
  });

  describe("LE signed 32-bit integers", function () {
    it("should return false for leTest(12345, 6789) (pos, pos)", async function () {
      const { contract } = deployment;
      await (await contract.leTest(12345n, 6789n)).wait();
      expect(await contract.leResult()).to.equal(false);
    });
    it("should return false for leTest(12345, -6789) (pos, neg)", async function () {
      const { contract } = deployment;
      await (await contract.leTest(12345n, -6789n)).wait();
      expect(await contract.leResult()).to.equal(false);
    });
    it("should return true for leTest(-12345, 6789) (neg, pos)", async function () {
      const { contract } = deployment;
      await (await contract.leTest(-12345n, 6789n)).wait();
      expect(await contract.leResult()).to.equal(true);
    });
    it("should return true for leTest(-12345, -6789) (neg, neg)", async function () {
      const { contract } = deployment;
      await (await contract.leTest(-12345n, -6789n)).wait();
      expect(await contract.leResult()).to.equal(true);
    });
    it("should return true for leTest(12345, 12345) (equal pos)", async function () {
      const { contract } = deployment;
      await (await contract.leTest(12345n, 12345n)).wait();
      expect(await contract.leResult()).to.equal(true);
    });
    it("should return true for leTest(-12345, -12345) (equal neg)", async function () {
      const { contract } = deployment;
      await (await contract.leTest(-12345n, -12345n)).wait();
      expect(await contract.leResult()).to.equal(true);
    });
  });

  describe("EQ signed 32-bit integers", function () {
    it("should return true for eqTest(12345, 12345) (equal pos)", async function () {
      const { contract } = deployment;
      await (await contract.eqTest(12345n, 12345n)).wait();
      expect(await contract.eqResult()).to.equal(true);
    });
    it("should return true for eqTest(-12345, -12345) (equal neg)", async function () {
      const { contract } = deployment;
      await (await contract.eqTest(-12345n, -12345n)).wait();
      expect(await contract.eqResult()).to.equal(true);
    });
    it("should return false for eqTest(12345, -12345) (pos, neg)", async function () {
      const { contract } = deployment;
      await (await contract.eqTest(12345n, -12345n)).wait();
      expect(await contract.eqResult()).to.equal(false);
    });
    it("should return false for eqTest(-12345, 12345) (neg, pos)", async function () {
      const { contract } = deployment;
      await (await contract.eqTest(-12345n, 12345n)).wait();
      expect(await contract.eqResult()).to.equal(false);
    });
  });

  describe("NE signed 32-bit integers", function () {
    it("should return false for neTest(12345, 12345) (equal pos)", async function () {
      const { contract } = deployment;
      await (await contract.neTest(12345n, 12345n)).wait();
      expect(await contract.neResult()).to.equal(false);
    });
    it("should return false for neTest(-12345, -12345) (equal neg)", async function () {
      const { contract } = deployment;
      await (await contract.neTest(-12345n, -12345n)).wait();
      expect(await contract.neResult()).to.equal(false);
    });
    it("should return true for neTest(12345, -12345) (pos, neg)", async function () {
      const { contract } = deployment;
      await (await contract.neTest(12345n, -12345n)).wait();
      expect(await contract.neResult()).to.equal(true);
    });
    it("should return true for neTest(-12345, 12345) (neg, pos)", async function () {
      const { contract } = deployment;
      await (await contract.neTest(-12345n, 12345n)).wait();
      expect(await contract.neResult()).to.equal(true);
    });
  });

  describe("Edge cases for signed 32-bit", function () {
    const MAX = (1n << 31n) - 1n;
    const MIN = -(1n << 31n);
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
    ];
    for (const { a, b } of testCases) {
      it(`edge case 32-bit addTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.addTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.addResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a + b));
      });
      it(`edge case 32-bit subTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.subTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.subResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a - b));
      });
      it(`edge case 32-bit mulTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.mulTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.mulResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a * b));
      });
      it(`edge case 32-bit divTest(${a}, ${b})`, async function () {
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
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a / b))
      });
      it(`edge case 32-bit ltTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.ltTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.ltResult();
        expect(decryptedInt).to.equal(a < b);
      });
      it(`edge case 32-bit leTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.leTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.leResult();
        expect(decryptedInt).to.equal(a <= b);
      });
      it(`edge case 32-bit gtTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.gtTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.gtResult();
        expect(decryptedInt).to.equal(a > b);
      });
      it(`edge case 32-bit geTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.geTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.geResult();
        expect(decryptedInt).to.equal(a >= b);
      });
      it(`edge case 32-bit eqTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.eqTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.eqResult();
        expect(decryptedInt).to.equal(a === b);
      });
      it(`edge case 32-bit neTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.neTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.neResult();
        expect(decryptedInt).to.equal(a !== b);
      });
    }
  });

  describe("Fuzz testing signed 32-bit arithmetic", function () {
    let deployment: Awaited<ReturnType<typeof deploy>>;
    before(async function () { deployment = await deploy(); });
    for (let i = 0; i < 10; i++) {
      const a = randomSigned32();
      const b = randomSigned32();
      it(`fuzz 32-bit addTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.addTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.addResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a + b));
      });
      it(`fuzz 32-bit subTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.subTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.subResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a - b));
      });
      it(`fuzz 32-bit mulTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.mulTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.mulResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a * b));
      });
      it(`fuzz 32-bit divTest(${a}, ${b})`, async function () {
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
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a / b))
      });
      it(`fuzz 32-bit andTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.andTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.andResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a & b));
      });
      it(`fuzz 32-bit orTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.orTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.orResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a | b));
      });
      it(`fuzz 32-bit xorTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.xorTest(a, b, gasOptions)).wait();
        const decryptedInt = await contract.xorResult();
        expect(decryptedInt).to.equal(BigInt.asIntN(32, a ^ b));
      });
      it(`fuzz 32-bit eqTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.eqTest(a, b, gasOptions)).wait();
        expect(await contract.eqResult()).to.equal(a === b);
        await (await contract.eqTest(a, a)).wait();
        expect(await contract.eqResult()).to.equal(true);
      });
      it(`fuzz 32-bit neTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.neTest(a, b, gasOptions)).wait();
        expect(await contract.neResult()).to.equal(a !== b);
        await (await contract.neTest(a, a)).wait();
        expect(await contract.neResult()).to.equal(false);
      });
      it(`fuzz 32-bit ltTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.ltTest(a, b, gasOptions)).wait();
        expect(await contract.ltResult()).to.equal(a < b);
        await (await contract.ltTest(b, a)).wait();
        expect(await contract.ltResult()).to.equal(b < a);
        await (await contract.ltTest(a, a)).wait();
        expect(await contract.ltResult()).to.equal(false);
      });
      it(`fuzz 32-bit leTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.leTest(a, b, gasOptions)).wait();
        expect(await contract.leResult()).to.equal(a <= b);
        await (await contract.leTest(b, a)).wait();
        expect(await contract.leResult()).to.equal(b <= a);
        await (await contract.leTest(a, a)).wait();
        expect(await contract.leResult()).to.equal(true);
      });
      it(`fuzz 32-bit gtTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.gtTest(a, b, gasOptions)).wait();
        expect(await contract.gtResult()).to.equal(a > b);
        await (await contract.gtTest(b, a)).wait();
        expect(await contract.gtResult()).to.equal(b > a);
        await (await contract.gtTest(a, a)).wait();
        expect(await contract.gtResult()).to.equal(false);
      });
      it(`fuzz 32-bit geTest(${a}, ${b})`, async function () {
        const { contract } = deployment;
        await (await contract.geTest(a, b, gasOptions)).wait();
        expect(await contract.geResult()).to.equal(a >= b);
        await (await contract.geTest(b, a)).wait();
        expect(await contract.geResult()).to.equal(b >= a);
        await (await contract.geTest(a, a)).wait();
        expect(await contract.geResult()).to.equal(true);
      });
    }
  }); 
})
