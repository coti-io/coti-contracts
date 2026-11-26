import hre from "hardhat";
import { expect } from "chai";

const COTI_CHAIN_ID = 2632500n;
const OTHER_CHAIN_ID = 11155111n;
const SOURCE_REQUEST_ID = hre.ethers.id("source-request");

// Same derivation as InboxBase.SYSTEM_SENDER in coti-pod-inbox-contracts.
const SYSTEM_SENDER = hre.ethers.getAddress(
  hre.ethers.dataSlice(hre.ethers.id("POD_INBOX_SYSTEM_SENDER"), 12)
);

enum InboxErrorType {
  NotErrorContext,
  SystemError,
  Exception,
}

describe("PodLibBase onDefaultMpcError", function () {
  async function deploy() {
    const [owner, executor, stranger] = await hre.ethers.getSigners();

    const Inbox = await hre.ethers.getContractFactory("ErrorLegInbox");
    const inbox = await Inbox.deploy();
    await inbox.waitForDeployment();

    const Adder = await hre.ethers.getContractFactory("MpcAdder");
    const adder = await Adder.connect(owner).deploy(await inbox.getAddress());
    await adder.waitForDeployment();
    await adder.configure(hre.ethers.ZeroAddress, executor.address, COTI_CHAIN_ID);

    return { inbox, adder, executor, stranger };
  }

  // Builds calldata the same way the inbox does: abi.encodeWithSelector(errorSelector, payload).
  function errorCall(adder: Awaited<ReturnType<typeof deploy>>["adder"], payload: string) {
    return adder.interface.encodeFunctionData("onDefaultMpcError", [payload]);
  }

  function systemErrorPayload(code: bigint, message: string) {
    return hre.ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint64", "bytes"],
      [code, hre.ethers.toUtf8Bytes(message)]
    );
  }

  it("emits the decoded code and message for an inbox system error", async function () {
    const { inbox, adder } = await deploy();
    const payload = systemErrorPayload(1n, "execution failed");

    await expect(
      inbox.deliver(
        await adder.getAddress(),
        errorCall(adder, payload),
        COTI_CHAIN_ID,
        SYSTEM_SENDER,
        SOURCE_REQUEST_ID,
        InboxErrorType.SystemError
      )
    )
      .to.emit(adder, "ErrorRemoteCall")
      .withArgs(SOURCE_REQUEST_ID, 1n, hre.ethers.hexlify(hre.ethers.toUtf8Bytes("execution failed")));
  });

  it("emits the raw payload for a raise from the MPC executor", async function () {
    const { inbox, adder, executor } = await deploy();
    const payload = hre.ethers.hexlify(hre.ethers.toUtf8Bytes("app error"));

    await expect(
      inbox.deliver(
        await adder.getAddress(),
        errorCall(adder, payload),
        COTI_CHAIN_ID,
        executor.address,
        SOURCE_REQUEST_ID,
        InboxErrorType.Exception
      )
    )
      .to.emit(adder, "ErrorRemoteCall")
      .withArgs(SOURCE_REQUEST_ID, 0n, payload);
  });

  it("rejects a raise from a contract other than the MPC executor", async function () {
    const { inbox, adder, stranger } = await deploy();

    await expect(
      inbox.deliver(
        await adder.getAddress(),
        errorCall(adder, "0x1234"),
        COTI_CHAIN_ID,
        stranger.address,
        SOURCE_REQUEST_ID,
        InboxErrorType.Exception
      )
    )
      .to.be.revertedWithCustomError(adder, "OnlyMpcExecutor")
      .withArgs(COTI_CHAIN_ID, stranger.address);
  });

  it("rejects a system error that did not come from the COTI chain", async function () {
    const { inbox, adder } = await deploy();

    await expect(
      inbox.deliver(
        await adder.getAddress(),
        errorCall(adder, systemErrorPayload(1n, "x")),
        OTHER_CHAIN_ID,
        SYSTEM_SENDER,
        SOURCE_REQUEST_ID,
        InboxErrorType.SystemError
      )
    )
      .to.be.revertedWithCustomError(adder, "OnlyMpcExecutor")
      .withArgs(OTHER_CHAIN_ID, SYSTEM_SENDER);
  });

  it("rejects a delivery that is not linked to a source request", async function () {
    const { inbox, adder, executor } = await deploy();

    await expect(
      inbox.deliver(
        await adder.getAddress(),
        errorCall(adder, "0x"),
        COTI_CHAIN_ID,
        executor.address,
        hre.ethers.ZeroHash,
        InboxErrorType.Exception
      )
    ).to.be.revertedWithCustomError(adder, "NotLinkedReturnLeg");
  });

  it("rejects a linked delivery that is not an error context", async function () {
    const { inbox, adder, executor } = await deploy();

    await expect(
      inbox.deliver(
        await adder.getAddress(),
        errorCall(adder, "0x"),
        COTI_CHAIN_ID,
        executor.address,
        SOURCE_REQUEST_ID,
        InboxErrorType.NotErrorContext
      )
    ).to.be.revertedWithCustomError(adder, "UnexpectedErrorContext");
  });

  it("rejects calls that do not come from the inbox", async function () {
    const { adder, stranger } = await deploy();

    await expect(adder.connect(stranger).onDefaultMpcError("0x"))
      .to.be.revertedWithCustomError(adder, "OnlyInbox")
      .withArgs(stranger.address);
  });
});
