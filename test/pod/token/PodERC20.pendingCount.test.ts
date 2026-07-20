import hre from "hardhat";
import { expect } from "chai";

describe("PodERC20 PP-08 pendingTransferCount", function () {
  it("exposes pendingTransferCount and no TransferAlreadyPending error", async function () {
    const [owner] = await hre.ethers.getSigners();
    const peer = owner.address;
    const PToken = await hre.ethers.getContractFactory("PodERC20");
    const pToken = await PToken.deploy(7082400, peer, peer, "Private USD", "pUSD");
    await pToken.waitForDeployment();

    expect(await pToken.pendingTransferCount(hre.ethers.ZeroAddress)).to.equal(0n);
    expect(pToken.interface.getError("TransferAlreadyPending")).to.equal(null);
    expect(pToken.interface.getError("ApprovalAlreadyPending")).to.not.equal(null);
  });
});
