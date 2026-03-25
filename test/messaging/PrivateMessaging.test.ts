import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

describe("PrivateMessaging", () => {
  async function deployFixture() {
    const [owner, alice, bob, carol] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("PrivateMessagingHarness");
    const contract = (await factory.deploy(14 * 24 * 60 * 60)) as any;

    const ct = (values: bigint[]) => ({ value: values });

    return { contract, owner, alice, bob, carol, ct };
  }

  it("records sent and inbox pages with viewer-specific ciphertext", async () => {
    const { contract, alice, bob, carol, ct } = await loadFixture(deployFixture);

    await contract.recordSyntheticMessage(
      alice.address,
      bob.address,
      ct([11n, 12n]),
      ct([21n, 22n]),
      ct([31n, 32n])
    );

    expect(await contract.sentCount(alice.address)).to.equal(1n);
    expect(await contract.inboxCount(bob.address)).to.equal(1n);
    expect(await contract.getSentPage(alice.address, 0, 10)).to.deep.equal([0n]);
    expect(await contract.getInboxPage(bob.address, 0, 10)).to.deep.equal([0n]);

    const senderView = await contract.connect(alice).getMessage(0);
    expect(senderView.from).to.equal(alice.address);
    expect(senderView.to).to.equal(bob.address);
    expect(senderView.chunkCount).to.equal(1n);
    expect(senderView.ciphertext.value).to.deep.equal([21n, 22n]);

    const recipientView = await contract.connect(bob).getMessage(0);
    expect(recipientView.ciphertext.value).to.deep.equal([31n, 32n]);
    expect((await contract.getSenderCiphertext(0)).value).to.deep.equal([21n, 22n]);
    expect((await contract.getRecipientCiphertext(0)).value).to.deep.equal([31n, 32n]);
    expect((await contract.getNetworkCiphertext(0)).value).to.deep.equal([11n, 12n]);

    await expect(contract.connect(carol).getMessage(0)).to.be.revertedWithCustomError(
      contract,
      "UnauthorizedViewer"
    );
  });

  it("stores multipart messages and returns chunked ciphertexts", async () => {
    const { contract, alice, bob, carol, ct } = await loadFixture(deployFixture);

    await contract.recordSyntheticMultipartMessage(
      alice.address,
      bob.address,
      [ct([11n]), ct([12n])],
      [ct([21n]), ct([22n])],
      [ct([31n]), ct([32n])]
    );

    const initialView = await contract.connect(alice).getMessage(0);
    expect(initialView.chunkCount).to.equal(2n);
    expect(initialView.ciphertext.value).to.deep.equal([21n]);

    const secondChunk = await contract.connect(alice).getMessageChunk(0, 1);
    expect(secondChunk.value).to.deep.equal([22n]);

    const recipientSecondChunk = await contract.getRecipientChunkCiphertext(0, 1);
    expect(recipientSecondChunk.value).to.deep.equal([32n]);

    await expect(contract.connect(carol).getMessageChunk(0, 1)).to.be.revertedWithCustomError(
      contract,
      "UnauthorizedViewer"
    );

    await expect(contract.connect(alice).getMessageChunk(0, 2)).to.be.revertedWithCustomError(
      contract,
      "ChunkOutOfBounds"
    );
  });

  it("splits epoch rewards by encrypted cell usage and gives final dust to the last claimant", async () => {
    const { contract, alice, bob, ct } = await loadFixture(deployFixture);

    await contract.fundEpoch(0, { value: 11n });

    await contract.recordSyntheticMultipartMessage(
      alice.address,
      bob.address,
      [ct([1n]), ct([2n, 3n])],
      [ct([101n]), ct([102n, 103n])],
      [ct([201n]), ct([202n, 203n])]
    );
    await contract.recordSyntheticMessage(
      bob.address,
      alice.address,
      ct([4n]),
      ct([104n]),
      ct([204n])
    );

    await time.increase(14 * 24 * 60 * 60 + 1);

    expect(await contract.epochUsageUnits(0, alice.address)).to.equal(3n);
    expect(await contract.epochUsageUnits(0, bob.address)).to.equal(1n);
    expect(await contract.pendingRewards(0, alice.address)).to.equal(8n);
    expect(await contract.pendingRewards(0, bob.address)).to.equal(2n);

    await expect(() => contract.connect(alice).claimRewards(0)).to.changeEtherBalances(
      [alice, contract],
      [8n, -8n]
    );

    expect(await contract.pendingRewards(0, bob.address)).to.equal(3n);

    await expect(() => contract.connect(bob).claimRewards(0)).to.changeEtherBalances(
      [bob, contract],
      [3n, -3n]
    );

    const summary = await contract.getEpochSummary(0);
    expect(summary.claimedAmount).to.equal(11n);
    expect(summary.totalUsageUnits).to.equal(4n);
    expect(summary.claimedUsageUnits).to.equal(4n);
  });

  it("rejects active-epoch claims, double claims, and past-epoch funding", async () => {
    const { contract, alice, bob, ct } = await loadFixture(deployFixture);

    await contract.fundEpoch(0, { value: 9n });
    await contract.recordSyntheticMessage(
      alice.address,
      bob.address,
      ct([1n]),
      ct([2n]),
      ct([3n])
    );

    await expect(contract.connect(alice).claimRewards(0)).to.be.revertedWithCustomError(
      contract,
      "EpochStillActive"
    );

    await time.increase(14 * 24 * 60 * 60 + 1);

    await contract.connect(alice).claimRewards(0);

    await expect(contract.connect(alice).claimRewards(0)).to.be.revertedWithCustomError(
      contract,
      "AlreadyClaimed"
    );

    await expect(contract.fundEpoch(0, { value: 1n })).to.be.revertedWithCustomError(
      contract,
      "PastEpochFundingNotAllowed"
    );
  });
});
