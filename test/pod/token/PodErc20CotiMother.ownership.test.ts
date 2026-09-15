import hre from "hardhat"
import { expect } from "chai"

describe("PodErc20CotiMother ownership", function () {
    it("rejects renounceOwnership", async function () {
        const [owner] = await hre.ethers.getSigners()
        const MockInbox = await hre.ethers.getContractFactory("MockInbox")
        const inbox = await MockInbox.deploy()
        await inbox.waitForDeployment()

        const Mother = await hre.ethers.getContractFactory("PodErc20CotiMother")
        const mother = await Mother.deploy(await inbox.getAddress(), owner.address)
        await mother.waitForDeployment()

        await expect(mother.renounceOwnership()).to.be.revertedWithCustomError(
            mother,
            "OwnershipCannotBeRenounced"
        )
        expect(await mother.owner()).to.equal(owner.address)
    })
})
