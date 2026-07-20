import hre from "hardhat";
import { expect } from "chai";

describe("PodERC20 PP-12 self-transfer", function () {
  it("rejects public self-transfer", async function () {
    const [owner, other] = await hre.ethers.getSigners();
    const PToken = await hre.ethers.getContractFactory("PodERC20");
    const pToken = await PToken.deploy(7082400, other.address, other.address, "Private USD", "pUSD");
    await pToken.waitForDeployment();

    await expect(
      pToken["transfer(address,uint256,uint256)"](owner.address, 1n, 1n, { value: 1n })
    ).to.be.revertedWithCustomError(pToken, "SelfTransfer");
    await expect(
      pToken["transferFrom(address,address,uint256,uint256)"](owner.address, owner.address, 1n, 1n, { value: 1n })
    ).to.be.revertedWithCustomError(pToken, "SelfTransfer");
  });
});
