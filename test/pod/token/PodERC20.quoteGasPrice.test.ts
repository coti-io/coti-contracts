import hre from "hardhat";
import { expect } from "chai";

const ONE_GWEI = 1_000_000_000n;
const MIN_PRIORITY = 50n * ONE_GWEI;
const MIN_GAS = 1n;
const GAS_UNITS = 1000n;

const zeroIt = { ciphertext: { ciphertextHigh: 0n, ciphertextLow: 0n }, signature: "0x" };

describe("PodERC20 quote gas price", function () {
  async function deploy() {
    const [owner, cotiSide] = await hre.ethers.getSigners();
    const Inbox = await hre.ethers.getContractFactory("QuoteGasInbox");
    const inbox = await Inbox.deploy(MIN_PRIORITY, MIN_GAS, 0n);
    await inbox.waitForDeployment();

    const PToken = await hre.ethers.getContractFactory("PodERC20");
    const pToken = await PToken.deploy(7082400, await inbox.getAddress(), cotiSide.address, "Private USD", "pUSD");
    await pToken.waitForDeployment();
    return { owner, inbox, pToken };
  }

  it("auto-fee transfer pays the reference price when the tx tip is below minPriority", async function () {
    const { inbox, pToken } = await deploy();
    const [, , to] = await hre.ethers.getSigners();
    await hre.network.provider.send("hardhat_setNextBlockBaseFeePerGas", ["0x" + ONE_GWEI.toString(16)]);

    const tx = await pToken["transfer(address,((uint256,uint256),bytes))"](to.address, zeroIt, {
      value: hre.ethers.parseEther("1"),
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 100n * ONE_GWEI,
    });
    const receipt = await tx.wait();
    const block = await hre.ethers.provider.getBlock(receipt!.blockNumber);
    const baseFee = block!.baseFeePerGas!;
    const reference = baseFee + MIN_PRIORITY;

    expect(receipt!.gasPrice).to.be.lt(reference);
    expect(await inbox.lastReferenceGasPrice()).to.equal(reference);
    expect(await inbox.lastCallbackFee()).to.equal(GAS_UNITS * reference);
  });

  it("estimateFee inside a tx matches the reference price even with a low tip", async function () {
    const { inbox, pToken } = await deploy();
    await hre.network.provider.send("hardhat_setNextBlockBaseFeePerGas", ["0x" + ONE_GWEI.toString(16)]);

    const tx = await inbox.recordQuote(await pToken.getAddress(), {
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 100n * ONE_GWEI,
    });
    const receipt = await tx.wait();
    const block = await hre.ethers.provider.getBlock(receipt!.blockNumber);
    const reference = block!.baseFeePerGas! + MIN_PRIORITY;

    expect(receipt!.gasPrice).to.be.lt(reference);
    expect(await inbox.lastReferenceGasPrice()).to.equal(reference);
    expect(await inbox.lastCallbackFee()).to.equal(GAS_UNITS * reference);
  });

  it("plain eth_call sees basefee 0, so the caller must pass gasPrice", async function () {
    const { pToken } = await deploy();
    const bare = await pToken.estimateFee();
    expect(bare.callbackFeeWei).to.equal(GAS_UNITS * 2_000_000_000n);

    const reference = ONE_GWEI + MIN_PRIORITY;
    const priced = await pToken.estimateFee({ gasPrice: reference });
    expect(priced.callbackFeeWei).to.equal(GAS_UNITS * reference);
    expect(priced.targetFeeWei).to.equal(GAS_UNITS * reference);
  });
});
