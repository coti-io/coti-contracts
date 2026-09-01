import hre from "hardhat";
import { expect } from "chai";

describe("PodERC20PausableMock", function () {
  async function deployPausableMock() {
    const [owner, other] = await hre.ethers.getSigners();
    const Mock = await hre.ethers.getContractFactory("PodERC20PausableMock");
    const pToken = await Mock.deploy(7082400, other.address, other.address, "Private USD", "pUSD");
    await pToken.waitForDeployment();
    await owner.sendTransaction({ to: await pToken.getAddress(), value: hre.ethers.parseEther("0.01") });
    return { pToken, owner, other };
  }

  it("blocks transfer and burn while paused; restores after unpause", async function () {
    const { pToken, owner, other } = await deployPausableMock();
    const to = other.address;

    await pToken.connect(owner).pause();

    await expect(
      pToken["transfer(address,uint256,uint256)"](to, 1n, 1n, { value: 1n })
    ).to.be.revertedWithCustomError(pToken, "EnforcedPause");
    await expect(pToken["burn(uint256,uint256)"](1n, 1n, { value: 1n })).to.be.revertedWithCustomError(
      pToken,
      "EnforcedPause"
    );

    await pToken.connect(owner).unpause();

    await expect(pToken["burn(uint256,uint256)"](0n, 1n, { value: 1n })).to.be.revertedWithCustomError(
      pToken,
      "ZeroAmount"
    );
  });
});
