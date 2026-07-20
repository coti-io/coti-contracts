import hre from "hardhat";
import { expect } from "chai";

describe("PodERC20 PP-05 zero public amounts", function () {
  async function deployPToken() {
    const [owner, other] = await hre.ethers.getSigners();
    // Dummy inbox/peer — ZeroAmount reverts before any inbox call.
    const inbox = other.address;
    const cotiSide = other.address;
    const PToken = await hre.ethers.getContractFactory("PodERC20");
    const pToken = await PToken.deploy(7082400, inbox, cotiSide, "Private USD", "pUSD");
    await pToken.waitForDeployment();
    // Fund for payable fee args (unused on revert path).
    await owner.sendTransaction({ to: await pToken.getAddress(), value: hre.ethers.parseEther("0.01") });
    return { pToken, owner, other };
  }

  it("rejects zero-amount public transfer / transferFrom / burn / transferFromAndCall", async function () {
    const { pToken, owner, other } = await deployPToken();
    const to = other.address;

    await expect(pToken.transfer(to, 0n, 1n, { value: 1n })).to.be.revertedWithCustomError(pToken, "ZeroAmount");
    await expect(pToken.transferFrom(owner.address, to, 0n, 1n, { value: 1n })).to.be.revertedWithCustomError(
      pToken,
      "ZeroAmount"
    );
    await expect(pToken.burn(0n, 1n, { value: 1n })).to.be.revertedWithCustomError(pToken, "ZeroAmount");
    await expect(pToken.transferFromAndCall(owner.address, to, 0n, "0x", 1n, { value: 1n })).to.be.revertedWithCustomError(
      pToken,
      "ZeroAmount"
    );
  });
});
