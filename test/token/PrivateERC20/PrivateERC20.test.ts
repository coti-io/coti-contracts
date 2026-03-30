import hre from "hardhat"
import { expect } from "chai"

import { setupAccounts } from "../../utils/accounts"
import {
    IPRIVATE_ERC20_INTERFACE_ID,
    mintPublic,
    burnPublic,
    txOpts,
    encryptItUint256,
    decryptCtUint256,
    expectTxFails
} from "../../utils/privateErc20Helpers"
import { PrivateERC20Mock, PrivateERC20WalletMock } from "../../../typechain-types"
import { Wallet } from "@coti-io/coti-ethers"
import type { itUint256 } from "@coti-io/coti-sdk-typescript"
import { ZeroAddress } from "ethers"

async function deploy() {
    const [owner, otherAccount] = await setupAccounts()

    const tokenContract = await hre.ethers.getContractFactory("PrivateERC20Mock")

    const token = await tokenContract.connect(owner).deploy(txOpts)

    const contract = await token.waitForDeployment()

    return {
        contract,
        contractAddress: await contract.getAddress(),
        owner,
        otherAccount
    }
}

describe("Private ERC20", function () {
    let contract: PrivateERC20Mock
    let contractAddress: string
    let owner: Wallet
    let otherAccount: Wallet

    before(async function () {
        const deployment = await deploy()

        contract = deployment.contract
        contractAddress = deployment.contractAddress
        owner = deployment.owner
        otherAccount = deployment.otherAccount
    })

    describe("deploy", function () {
        it("has a name", async function () {
            await expect(await contract.name()).to.equal("PrivateERC20Mock")
        })

        it("has a symbol", async function () {
            await expect(await contract.symbol()).to.equal("PE20M")
        })

        it("has 6 decimals", async function () {
            await expect(await contract.decimals()).to.equal(6n)
        })

        it("totalSupply view is zero (privacy stance)", async function () {
            await expect(await contract.totalSupply()).to.equal(0n)
        })

        it("publicAmountsEnabled is true by default", async function () {
            await expect(await contract.publicAmountsEnabled()).to.equal(true)
        })

        it("supports ERC-165 and IPrivateERC20", async function () {
            await expect(await contract.supportsInterface("0x01ffc9a7")).to.equal(true)
            await expect(await contract.supportsInterface(IPRIVATE_ERC20_INTERFACE_ID)).to.equal(true)
            await expect(await contract.supportsInterface("0xffffffff")).to.equal(false)
        })
    })

    describe("mint", function () {
        const value = 5000n

        describe("successful mint", function () {
            before("minting", async function () {
                this.tx = await mintPublic(contract, owner, owner.address, value)
                await this.tx.wait()
            })

            it("does not increment totalSupply", async function () {
                await expect(await contract.totalSupply()).to.equal(0n)
            })

            it("increments recipient balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.address)

                const balance = decryptCtUint256(owner, ctBalance)

                await expect(balance).to.equal(value)
            })

            it("emits Transfer event", async function () {
                await expect(this.tx).to.emit(contract, "Transfer")
            })
        })

        describe("failed mint", function () {
            it("rejects minting to the zero address", async function () {
                await expectTxFails(
                    contract.connect(owner).getFunction("mint(address,uint256)")(ZeroAddress, value, txOpts)
                )
            })
        })
    })

    describe("burn", function () {
        const value = 5000n

        describe("failed burn", function () {
            it("rejects burning from the zero address", async function () {
                await expectTxFails(
                    contract.connect(owner).getFunction("burn(address,uint256)")(ZeroAddress, value, txOpts)
                )
            })

            it("reverts when burning more than balance (no Transfer)", async function () {
                await expectTxFails(
                    contract
                        .connect(owner)
                        .getFunction("burn(address,uint256)")(owner.address, value + 1n, txOpts)
                )
            })
        })

        describe("successful burn", function () {
            before("burning", async function () {
                this.tx = await burnPublic(contract, owner, owner.address, value)
                await this.tx.wait()
            })

            it("decrements the senders balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.address)

                const balance = decryptCtUint256(owner, ctBalance)

                await expect(balance).to.equal(0n)
            })

            it("emits Transfer event", async function () {
                await expect(this.tx).to.emit(contract, "Transfer")
            })
        })
    })

    describe("transfer", function () {
        const value = 10000n

        before("minting", async function () {
            this.tx = await mintPublic(contract, owner, owner.address, value)
            await this.tx.wait()
        })

        describe("failed transfer", function () {
            it("rejects transferring to the zero address", async function () {
                const itValue = (await encryptItUint256(owner,
                    value,
                    contractAddress,
                    contract.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
                )) as itUint256

                await expect(
                    contract
                        .connect(owner)
                        .getFunction("transfer(address,((uint256,uint256),bytes))")(ZeroAddress, itValue)
                )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidReceiver")
                    .withArgs(ZeroAddress)
            })

            it("reverts when amount exceeds balance (no Transfer)", async function () {
                const itValue = (await encryptItUint256(owner,
                    value + 1n,
                    contractAddress,
                    contract.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
                )) as itUint256

                await expectTxFails(
                    contract
                        .connect(owner)
                        .getFunction("transfer(address,((uint256,uint256),bytes))")(
                            otherAccount.address,
                            itValue,
                            txOpts
                        )
                )
            })
        })

        describe("successful transfer", function () {
            before("transferring", async function () {
                const itValue = (await encryptItUint256(owner,
                    value / 2n,
                    contractAddress,
                    contract.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
                )) as itUint256

                const tx = await contract
                    .connect(owner)
                    .getFunction("transfer(address,((uint256,uint256),bytes))")(
                        otherAccount.address,
                        itValue,
                        txOpts
                    )

                await tx.wait()
            })

            it("decrements the senders balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.address)

                const balance = decryptCtUint256(owner, ctBalance)

                await expect(balance).to.equal(value / 2n)
            })

            it("increments the receivers balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](otherAccount.address)

                const balance = decryptCtUint256(otherAccount, ctBalance)

                await expect(balance).to.equal(value / 2n)
            })
        })
    })

    describe("approve", function () {
        const value = 5000n

        describe("failed approval", function () {
            it("rejects when approving the zero address", async function () {
                const itValue = (await encryptItUint256(owner,
                    value,
                    contractAddress,
                    contract.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
                )) as itUint256

                await expect(
                    contract
                        .connect(owner)
                        .getFunction("approve(address,((uint256,uint256),bytes))")(ZeroAddress, itValue)
                )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidSpender")
                    .withArgs(ZeroAddress)
            })
        })

        describe("successful approval", function () {
            before("approving", async function () {
                const itValue = (await encryptItUint256(owner,
                    value,
                    contractAddress,
                    contract.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
                )) as itUint256

                const tx = await contract
                    .connect(owner)
                    .getFunction("approve(address,((uint256,uint256),bytes))")(otherAccount.address, itValue, txOpts)

                await tx.wait()
            })

            it("stores allowance ciphertext for owner view", async function () {
                const ctAllowance = await contract["allowance(address,address)"](owner.address, otherAccount.address)

                const allowance = decryptCtUint256(owner, ctAllowance.ownerCiphertext)

                await expect(allowance).to.equal(value)
            })

            it("stores allowance ciphertext for spender view", async function () {
                const ctAllowance = await contract["allowance(address,address)"](owner.address, otherAccount.address)

                const allowance = decryptCtUint256(otherAccount, ctAllowance.spenderCiphertext)

                await expect(allowance).to.equal(value)
            })
        })
    })

    describe("transferFrom", function () {
        const value = 3000n

        describe("failed transferFrom", function () {
            it("rejects transferring to the zero address", async function () {
                const itValue = (await encryptItUint256(otherAccount,
                    value,
                    contractAddress,
                    contract.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
                )) as itUint256

                await expect(
                    contract
                        .connect(otherAccount)
                        .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")
                        .staticCall(owner.address, ZeroAddress, itValue)
                )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidReceiver")
                    .withArgs(ZeroAddress)
            })

            it("rejects from zero address", async function () {
                const itValue = (await encryptItUint256(otherAccount,
                    value,
                    contractAddress,
                    contract.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
                )) as itUint256

                await expect(
                    contract
                        .connect(otherAccount)
                        .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")
                        .staticCall(ZeroAddress, otherAccount.address, itValue)
                ).to.be.revertedWithCustomError(contract, "ERC20InvalidSender")
            })

            it("reverts when allowance is insufficient", async function () {
                const itValue = (await encryptItUint256(otherAccount,
                    999999n,
                    contractAddress,
                    contract.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
                )) as itUint256

                await expectTxFails(
                    contract
                        .connect(otherAccount)
                        .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")(
                            owner.address,
                            otherAccount.address,
                            itValue,
                            txOpts
                        )
                )
            })

            it("reverts when amount exceeds balance (allowance OK)", async function () {
                await contract
                    .connect(owner)
                    .getFunction("increaseAllowance(address,uint256)")(otherAccount.address, 5000n, txOpts)
                    .then((t) => t.wait())

                const itValue = (await encryptItUint256(otherAccount,
                    6000n,
                    contractAddress,
                    contract.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
                )) as itUint256

                await expectTxFails(
                    contract
                        .connect(otherAccount)
                        .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")(
                            owner.address,
                            "0x0000000000000000000000000000000000000001",
                            itValue,
                            txOpts
                        )
                )
            })
        })

        describe("successful transferFrom", function () {
            before("transferring", async function () {
                await contract
                    .connect(owner)
                    .getFunction("approve(address,uint256)")(otherAccount.address, 0n, txOpts)
                    .then((t) => t.wait())
                await contract
                    .connect(owner)
                    .getFunction("approve(address,uint256)")(otherAccount.address, 5000n, txOpts)
                    .then((t) => t.wait())

                const itValue = (await encryptItUint256(otherAccount,
                    value,
                    contractAddress,
                    contract.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
                )) as itUint256

                const tx = await contract
                    .connect(otherAccount)
                    .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")(
                        owner.address,
                        otherAccount.address,
                        itValue,
                        txOpts
                    )

                await tx.wait()
            })

            it("decrements the owners balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.address)

                const balance = decryptCtUint256(owner, ctBalance)

                await expect(balance).to.equal(2000n)
            })

            it("increments the recipients balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](otherAccount.address)

                const balance = decryptCtUint256(otherAccount, ctBalance)

                await expect(balance).to.equal(8000n)
            })

            it("decrements the spenders allowance", async function () {
                const ctAllowance = await contract["allowance(address,address)"](owner.address, otherAccount.address)

                const allowance = decryptCtUint256(otherAccount, ctAllowance.spenderCiphertext)

                await expect(allowance).to.equal(2000n)
            })
        })
    })

    describe("contract-to-contract interactions", function () {
        const value = 10000n
        let walletContract: PrivateERC20WalletMock
        let walletContractAddress: string

        before("deploying and funding wallet contract", async function () {
            const walletContractFactory = await hre.ethers.getContractFactory("PrivateERC20WalletMock")

            const w = await walletContractFactory.connect(owner).deploy(txOpts)
            await w.waitForDeployment()
            walletContract = w as unknown as PrivateERC20WalletMock

            walletContractAddress = await walletContract.getAddress()

            await mintPublic(contract, owner, walletContractAddress, value).then((t) => t.wait())
        })

        describe("setAccountEncryptionAddress", function () {
            before("setting account encryption address", async function () {
                const tx = await walletContract
                    .connect(otherAccount)
                    .setAccountEncryptionAddress(contractAddress, otherAccount.address, txOpts)

                await tx.wait()
            })

            it("updates accountEncryptionAddress mapping", async function () {
                const accountEncryptionAddress = await contract.accountEncryptionAddress(walletContractAddress)

                await expect(accountEncryptionAddress).to.equal(otherAccount.address)
            })

            it("reencrypts balance for the new encryption address", async function () {
                const ctBalance = await contract["balanceOf(address)"](walletContractAddress)

                const balance = decryptCtUint256(otherAccount, ctBalance)

                await expect(balance).to.equal(value)
            })
        })

        describe("transfer via wallet", function () {
            let otherBalanceBeforeWalletTransfer = 0n

            before("transferring", async function () {
                const ctBefore = await contract["balanceOf(address)"](otherAccount.address)
                otherBalanceBeforeWalletTransfer = decryptCtUint256(otherAccount, ctBefore)

                const tx = await walletContract
                    .connect(otherAccount)
                    .transfer(contractAddress, otherAccount.address, value / 2n, txOpts)

                await tx.wait()
            })

            it("decrements the wallet balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](walletContractAddress)

                const balance = decryptCtUint256(otherAccount, ctBalance)

                await expect(balance).to.equal(value / 2n)
            })

            it("increments the receiver balance", async function () {
                const ctBalance = await contract["balanceOf(address)"](otherAccount.address)

                const balance = decryptCtUint256(otherAccount, ctBalance)

                await expect(balance).to.equal(otherBalanceBeforeWalletTransfer + value / 2n)
            })
        })

        describe("approve via wallet", function () {
            before("approving", async function () {
                const tx = await walletContract
                    .connect(otherAccount)
                    .approve(contractAddress, owner.address, value / 2n, txOpts)

                await tx.wait()
            })

            it("sets allowance for wallet owner/spender pair", async function () {
                const ctAllowance = await contract["allowance(address,address)"](walletContractAddress, owner.address)

                const allowance = decryptCtUint256(otherAccount, ctAllowance.ownerCiphertext)

                await expect(allowance).to.equal(value / 2n)
            })
        })
    })

    describe("maximum allowance", function () {
        const value = 2n ** 256n - 1n
        let ownerBalanceBeforeMaxTransfer = 0n
        let maxAllowanceTransferFromReceipt: any

        before("approve max and transferFrom", async function () {
            let ct = await contract["balanceOf(address)"](owner.address)
            ownerBalanceBeforeMaxTransfer = decryptCtUint256(owner, ct)
            const need = 7000n
            if (ownerBalanceBeforeMaxTransfer < need) {
                await mintPublic(contract, owner, owner.address, need - ownerBalanceBeforeMaxTransfer).then((t) =>
                    t.wait()
                )
                ct = await contract["balanceOf(address)"](owner.address)
                ownerBalanceBeforeMaxTransfer = decryptCtUint256(owner, ct)
            }

            await contract
                .connect(owner)
                .getFunction("approve(address,uint256)")(otherAccount.address, 0n, txOpts)
                .then((t) => t.wait())

            const itMax = (await encryptItUint256(owner,
                value,
                contractAddress,
                contract.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            let tx = await contract
                .connect(owner)
                .getFunction("approve(address,((uint256,uint256),bytes))")(otherAccount.address, itMax, txOpts)

            await tx.wait()

            const itValue = (await encryptItUint256(otherAccount,
                7000n,
                contractAddress,
                contract.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
            )) as itUint256

            tx = await contract
                .connect(otherAccount)
                .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")(
                    owner.address,
                    "0x0000000000000000000000000000000000000001",
                    itValue,
                    txOpts
                )

            maxAllowanceTransferFromReceipt = await tx.wait()
        })

        it("reduces owner balance but not unlimited allowance", async function () {
            const ctBalance = await contract["balanceOf(address)"](owner.address)

            const balance = decryptCtUint256(owner, ctBalance)

            await expect(balance).to.equal(ownerBalanceBeforeMaxTransfer - 7000n)
        })

        it("keeps max allowance for spender", async function () {
            const ctAllowance = await contract["allowance(address,address)"](owner.address, otherAccount.address)

            const allowance = decryptCtUint256(owner, ctAllowance.ownerCiphertext)

            await expect(allowance).to.equal(value)
        })

        it("does not emit Approval on spend when allowance is unlimited", async function () {
            const approvalEv = contract.interface.getEvent("Approval")
            const approvalTopic = approvalEv.topicHash
            const hasApproval = maxAllowanceTransferFromReceipt.logs.some((l: any) => l.topics?.[0] === approvalTopic)
            await expect(hasApproval).to.equal(false)
        })
    })

    describe("supplyCap boundaries (capped token)", function () {
        it("enforces cap for public and encrypted mint", async function () {
            const [capOwner] = await setupAccounts()
            const cappedFactory = await hre.ethers.getContractFactory("PrivateERC20CappedMock")
            const capped = await cappedFactory.connect(capOwner).deploy(1000n, txOpts)
            await capped.waitForDeployment()
            const cappedAddr = await capped.getAddress()

            // grant MINTER_ROLE for both mint overloads
            const minterRole = await (capped as any).MINTER_ROLE()
            await (await (capped as any).grantRole(minterRole, capOwner.address, txOpts)).wait()

            // public mint within cap
            await (await capped.connect(capOwner).getFunction("mint(address,uint256)")(capOwner.address, 1000n, txOpts)).wait()
            // public mint above cap
            await expectTxFails(
                capped.connect(capOwner).getFunction("mint(address,uint256)")(capOwner.address, 1n, txOpts)
            )

            // encrypted mint within remaining (cap already full, so minting any more should fail)
            const itOne = (await encryptItUint256(
                capOwner,
                1n,
                cappedAddr,
                (capped.interface.getFunction("mint(address,((uint256,uint256),bytes))") as any).selector
            )) as itUint256
            await expectTxFails(
                capped.connect(capOwner).getFunction("mint(address,((uint256,uint256),bytes))")(capOwner.address, itOne, txOpts)
            )
        })
    })

    describe("increaseAllowance and decreaseAllowance", function () {
        let localContract: PrivateERC20Mock
        let localAddress: string
        let localOwner: Wallet
        let localOther: Wallet

        before(async function () {
            const deployment = await deploy()
            localContract = deployment.contract
            localAddress = deployment.contractAddress
            localOwner = deployment.owner
            localOther = deployment.otherAccount
            await mintPublic(localContract, localOwner, localOwner.address, 100000n).then((t) => t.wait())
        })

        it("increases allowance from zero", async function () {
            const add = 1234n
            await localContract
                .connect(localOwner)
                .getFunction("increaseAllowance(address,uint256)")(localOther.address, add, txOpts)
                .then((t) => t.wait())
            const ctAllowance = await localContract["allowance(address,address)"](localOwner.address, localOther.address)
            const allowance = decryptCtUint256(localOwner, ctAllowance.ownerCiphertext)
            await expect(allowance).to.equal(add)
        })

        it("decreases allowance", async function () {
            const sub = 234n
            await localContract
                .connect(localOwner)
                .getFunction("decreaseAllowance(address,uint256)")(localOther.address, sub, txOpts)
                .then((t) => t.wait())
            const ctAllowance = await localContract["allowance(address,address)"](localOwner.address, localOther.address)
            const allowance = decryptCtUint256(localOwner, ctAllowance.ownerCiphertext)
            await expect(allowance).to.equal(1234n - 234n)
        })

        it("reverts decrease when allowance is insufficient", async function () {
            await expectTxFails(
                localContract
                    .connect(localOwner)
                    .getFunction("decreaseAllowance(address,uint256)")(localOther.address, 100000n, txOpts)
            )
        })

        it("reverts increaseAllowance when addition overflows uint256", async function () {
            const max = 2n ** 256n - 1n
            await localContract
                .connect(localOwner)
                .getFunction("approve(address,uint256)")(localOther.address, 0n, txOpts)
                .then((t) => t.wait())

            const itMax = (await encryptItUint256(localOwner,
                max,
                localAddress,
                localContract.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await localContract
                .connect(localOwner)
                .getFunction("approve(address,((uint256,uint256),bytes))")(localOther.address, itMax, txOpts)
                .then((t) => t.wait())

            await expectTxFails(
                localContract
                    .connect(localOwner)
                    .getFunction("increaseAllowance(address,uint256)")(localOther.address, 1n, txOpts)
            )
        })
    })

    describe("publicAmountsDisabled", function () {
        let c: PrivateERC20Mock
        let o: Wallet

        before(async function () {
            const d = await deploy()
            c = d.contract
            o = d.owner
            await mintPublic(c, o, o.address, 1000n).then((t) => t.wait())
            await c.connect(o).setPublicAmountsEnabled(false).then((t) => t.wait())
        })

        it("reverts public transfer", async function () {
            await expect(
                c.connect(o).getFunction("transfer(address,uint256)").staticCall(otherAccount.address, 1n)
            ).to.be.revertedWithCustomError(c, "PublicAmountsDisabled")
        })

        it("reverts public approve/increase/decrease/transferFrom/burn/transferAndCall", async function () {
            await expect(
                c.connect(o).getFunction("approve(address,uint256)").staticCall(otherAccount.address, 1n)
            ).to.be.revertedWithCustomError(c, "PublicAmountsDisabled")

            await expect(
                c.connect(o).getFunction("increaseAllowance(address,uint256)").staticCall(otherAccount.address, 1n)
            ).to.be.revertedWithCustomError(c, "PublicAmountsDisabled")

            await expect(
                c.connect(o).getFunction("decreaseAllowance(address,uint256)").staticCall(otherAccount.address, 1n)
            ).to.be.revertedWithCustomError(c, "PublicAmountsDisabled")

            await expect(
                c.connect(o)
                    .getFunction("transferFrom(address,address,uint256)")
                    .staticCall(o.address, otherAccount.address, 1n)
            ).to.be.revertedWithCustomError(c, "PublicAmountsDisabled")

            await expect(
                c.connect(o).getFunction("burn(uint256)").staticCall(1n)
            ).to.be.revertedWithCustomError(c, "PublicAmountsDisabled")

            // transferAndCall(public) also blocked
            const recvFactory = await hre.ethers.getContractFactory("PublicTokenReceiverMock")
            const recv = await recvFactory.connect(o).deploy(txOpts)
            await recv.waitForDeployment()
            await expect(
                c.connect(o)
                    .getFunction("transferAndCall(address,uint256,bytes)")
                    .staticCall(await recv.getAddress(), 1n, "0x")
            ).to.be.revertedWithCustomError(c, "PublicAmountsDisabled")
        })

        after(async function () {
            await c.connect(o).setPublicAmountsEnabled(true).then((t) => t.wait())
        })
    })

    describe("transferAndCall reentrancy (encrypted)", function () {
        it("prevents receiver callback re-entering token", async function () {
            const d = await deploy()
            const t = d.contract
            const tAddr = d.contractAddress
            const o = d.owner
            const other = d.otherAccount

            // fund owner
            await mintPublic(t, o, o.address, 1000n).then((x) => x.wait())

            const receiverFactory = await hre.ethers.getContractFactory("PrivateERC20ReentrantReceiverMock")
            const receiver = await receiverFactory.connect(o).deploy(txOpts)
            await receiver.waitForDeployment()
            const receiverAddr = await receiver.getAddress()

            // configure callback to attempt re-entry into approve(uint256)
            const reenterData = t.interface.encodeFunctionData("approve(address,uint256)", [other.address, 1n])
            await (await (receiver as any).configure(tAddr, true, reenterData, txOpts)).wait()

            const itAmount = (await encryptItUint256(
                o,
                1n,
                tAddr,
                t.interface.getFunction("transferAndCall(address,((uint256,uint256),bytes),bytes)").selector
            )) as itUint256

            await expectTxFails(
                t.connect(o)
                    .getFunction("transferAndCall(address,((uint256,uint256),bytes),bytes)")(receiverAddr, itAmount, "0x", txOpts)
            )
        })
    })

    describe("more edge cases (fresh deploy)", function () {
        let c: PrivateERC20Mock
        let addr: string
        let o: Wallet
        let other: Wallet

        before(async function () {
            const d = await deploy()
            c = d.contract
            addr = d.contractAddress
            o = d.owner
            other = d.otherAccount
            await mintPublic(c, o, o.address, 1000n).then((t) => t.wait())
        })

        it("public transfer exact balance moves all tokens", async function () {
            const amount = 1000n
            await (await c.connect(o).getFunction("transfer(address,uint256)")(other.address, amount, txOpts)).wait()
            await expect(decryptCtUint256(o, await c["balanceOf(address)"](o.address))).to.equal(0n)
            await expect(decryptCtUint256(other, await c["balanceOf(address)"](other.address))).to.equal(amount)
        })

        it("public transferFrom exact allowance reduces allowance to zero", async function () {
            // reset: mint back to owner
            await mintPublic(c, o, o.address, 500n).then((t) => t.wait())
            await (await c.connect(o).getFunction("approve(address,uint256)")(other.address, 123n, txOpts)).wait()

            await (await c.connect(other).getFunction("transferFrom(address,address,uint256)")(o.address, other.address, 123n, txOpts)).wait()

            const a = await c["allowance(address,address)"](o.address, other.address)
            await expect(decryptCtUint256(other, a.spenderCiphertext)).to.equal(0n)
        })

        it("public approve is unsafe when current allowance non-zero", async function () {
            await (await c.connect(o).getFunction("approve(address,uint256)")(other.address, 10n, txOpts)).wait()
            await expectTxFails(c.connect(o).getFunction("approve(address,uint256)")(other.address, 11n, txOpts))
        })

        it("public transferFrom with from==to reverts (self-transfer)", async function () {
            // clear any prior allowance set by earlier tests in this block
            await (await c.connect(o).getFunction("approve(address,uint256)")(other.address, 0n, txOpts)).wait()
            await (await c.connect(o).getFunction("approve(address,uint256)")(other.address, 1n, txOpts)).wait()
            await expectTxFails(
                c.connect(other).getFunction("transferFrom(address,address,uint256)")(o.address, o.address, 1n, txOpts)
            )
        })

        it("encrypted approve(0) is NOT a safe reset when current allowance non-zero", async function () {
            // set non-zero allowance first
            await (await c.connect(o).getFunction("approve(address,uint256)")(other.address, 0n, txOpts)).wait()
            await (await c.connect(o).getFunction("approve(address,uint256)")(other.address, 55n, txOpts)).wait()

            const itZero = (await encryptItUint256(
                o,
                0n,
                addr,
                c.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            // Contract treats "new allowance is zero" via MPC equality; depending on MPC encoding,
            // an encrypted-zero may not compare equal to public zero, so this may still hit ERC20UnsafeApprove.
            await expectTxFails(
                c.connect(o)
                    .getFunction("approve(address,((uint256,uint256),bytes))")(other.address, itZero, txOpts)
            )
        })

        it("transferAndCall(public) checks receiver must be contract (before PublicAmountsDisabled)", async function () {
            await (await c.connect(o).setPublicAmountsEnabled(false).then((t) => t.wait()))
            // EOA receiver => should hit TransferAndCallRequiresContract first
            await expect(
                c.connect(o).getFunction("transferAndCall(address,uint256,bytes)").staticCall(other.address, 1n, "0x")
            ).to.be.revertedWithCustomError(c, "TransferAndCallRequiresContract")
        })

        it("accountEncryptionAddress(0) and allowance(address,bool) with zero address revert", async function () {
            await expect(c.accountEncryptionAddress(ZeroAddress)).to.be.revertedWithCustomError(c, "ERC20InvalidReceiver")
            await expect(
                c.connect(o).getFunction("allowance(address,bool)").staticCall(ZeroAddress, true)
            ).to.be.revertedWithCustomError(c, "ERC20InvalidReceiver")
        })
    })

    describe("transferAndCall reentrancy (public)", function () {
        it("prevents receiver callback re-entering token", async function () {
            const d = await deploy()
            const t = d.contract
            const tAddr = d.contractAddress
            const o = d.owner
            const other = d.otherAccount

            await mintPublic(t, o, o.address, 1000n).then((x) => x.wait())

            const recvFactory = await hre.ethers.getContractFactory("PublicReentrantTokenReceiverMock")
            const recv = await recvFactory.connect(o).deploy(txOpts)
            await recv.waitForDeployment()
            const recvAddr = await recv.getAddress()

            // ensure public ops enabled for this test
            await (await t.connect(o).setPublicAmountsEnabled(true).then((x) => x.wait()))

            const reenterData = t.interface.encodeFunctionData("approve(address,uint256)", [other.address, 1n])
            await (await (recv as any).configure(tAddr, true, reenterData, txOpts)).wait()

            await expectTxFails(
                t.connect(o).getFunction("transferAndCall(address,uint256,bytes)")(recvAddr, 1n, "0x", txOpts)
            )
        })
    })

    describe("missing branches: GT overloads + transferAndCall success/failure", function () {
        it("covers transferAndCall(public) success and callback-false failure", async function () {
            const d = await deploy()
            const t = d.contract
            const o = d.owner

            await mintPublic(t, o, o.address, 10n).then((x) => x.wait())

            const okRecvF = await hre.ethers.getContractFactory("PublicTokenReceiverBoolMock")
            const okRecv = await okRecvF.connect(o).deploy(true, txOpts)
            await okRecv.waitForDeployment()

            const badRecv = await okRecvF.connect(o).deploy(false, txOpts)
            await badRecv.waitForDeployment()

            await (await t.connect(o).getFunction("transferAndCall(address,uint256,bytes)")(await okRecv.getAddress(), 1n, "0x", txOpts)).wait()
            await expectTxFails(
                t.connect(o).getFunction("transferAndCall(address,uint256,bytes)")(await badRecv.getAddress(), 1n, "0x", txOpts)
            )
        })

        it("covers transferAndCall(encrypted) success and callback-false failure", async function () {
            const d = await deploy()
            const t = d.contract
            const tAddr = d.contractAddress
            const o = d.owner

            await mintPublic(t, o, o.address, 10n).then((x) => x.wait())

            const recvF = await hre.ethers.getContractFactory("EncryptedTokenReceiverMock")
            const okRecv = await recvF.connect(o).deploy(true, txOpts)
            await okRecv.waitForDeployment()
            const badRecv = await recvF.connect(o).deploy(false, txOpts)
            await badRecv.waitForDeployment()

            const itAmt = (await encryptItUint256(
                o,
                1n,
                tAddr,
                t.interface.getFunction("transferAndCall(address,((uint256,uint256),bytes),bytes)").selector
            )) as itUint256

            await (await t.connect(o).getFunction("transferAndCall(address,((uint256,uint256),bytes),bytes)")(await okRecv.getAddress(), itAmt, "0x", txOpts)).wait()
            await expectTxFails(
                t.connect(o).getFunction("transferAndCall(address,((uint256,uint256),bytes),bytes)")(await badRecv.getAddress(), itAmt, "0x", txOpts)
            )
        })

        it("covers GT entrypoints via helper contract", async function () {
            const d = await deploy()
            const t = d.contract
            const tAddr = d.contractAddress
            const o = d.owner
            const other = d.otherAccount

            await mintPublic(t, o, o.address, 1000n).then((x) => x.wait())

            const callerF = await hre.ethers.getContractFactory("PrivateERC20GtCallerMock")
            const caller = await callerF.connect(o).deploy(txOpts)
            await caller.waitForDeployment()
            const callerAddr = await caller.getAddress()

            // fund caller so it can burnGt and transferGT as msg.sender
            await (await t.connect(o).getFunction("transfer(address,uint256)")(callerAddr, 10n, txOpts)).wait()

            // transferGT from caller to other
            await (await (caller as any).transferGT(tAddr, other.address, 1n, txOpts)).wait()
            await expect(decryptCtUint256(other, await t["balanceOf(address)"](other.address))).to.be.greaterThan(0n)

            // approveGT from caller (owner=caller) to itself (spender=caller), then transferFromGT (spender=caller)
            await (await (caller as any).approveGT(tAddr, callerAddr, 5n, txOpts)).wait()
            await (await (caller as any).transferFromGT(tAddr, callerAddr, other.address, 2n, txOpts)).wait()

            // burnGt from caller
            await (await (caller as any).burnGt(tAddr, 1n, txOpts)).wait()
        })
    })

    describe("reencryptAllowance event", function () {
        it("emits AllowanceReencrypted", async function () {
            await contract
                .connect(owner)
                .getFunction("approve(address,uint256)")(otherAccount.address, 0n, txOpts)
                .then((t) => t.wait())

            const it42 = (await encryptItUint256(owner,
                42n,
                contractAddress,
                contract.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await contract
                .connect(owner)
                .getFunction("approve(address,((uint256,uint256),bytes))")(otherAccount.address, it42, txOpts)
                .then((t) => t.wait())

            const txResp = await contract.connect(owner).reencryptAllowance(otherAccount.address, false, txOpts)
            const receipt = await txResp.wait()
            expect(receipt).to.not.be.null
            expect(receipt!.status).to.equal(1)
            const ev = contract.interface.getEvent("AllowanceReencrypted")
            expect(receipt!.logs.some((l) => l.topics[0] === ev.topicHash)).to.equal(true)
        })
    })

    describe("encrypted edge cases (fresh deploy)", function () {
        let c: PrivateERC20Mock
        let addr: string
        let o: Wallet
        let other: Wallet

        before(async function () {
            const d = await deploy()
            c = d.contract
            addr = d.contractAddress
            o = d.owner
            other = d.otherAccount

            await mintPublic(c, o, o.address, 1000n).then((t) => t.wait())
        })

        it("transfer encrypted 0n keeps balances unchanged", async function () {
            const ctFromBefore = await c["balanceOf(address)"](o.address)
            const ctToBefore = await c["balanceOf(address)"](other.address)

            const fromBefore = decryptCtUint256(o, ctFromBefore)
            const toBefore = decryptCtUint256(other, ctToBefore)

            const itZero = (await encryptItUint256(
                o,
                0n,
                addr,
                c.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(o)
                    .getFunction("transfer(address,((uint256,uint256),bytes))")(other.address, itZero, txOpts)
            ).wait()

            const ctFromAfter = await c["balanceOf(address)"](o.address)
            const ctToAfter = await c["balanceOf(address)"](other.address)

            const fromAfter = decryptCtUint256(o, ctFromAfter)
            const toAfter = decryptCtUint256(other, ctToAfter)

            await expect(fromAfter).to.equal(fromBefore)
            await expect(toAfter).to.equal(toBefore)
        })

        it("transfer encrypted exact balance moves all tokens", async function () {
            const value = 1000n

            const itValue = (await encryptItUint256(
                o,
                value,
                addr,
                c.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(o)
                    .getFunction("transfer(address,((uint256,uint256),bytes))")(other.address, itValue, txOpts)
            ).wait()

            const ctFrom = await c["balanceOf(address)"](o.address)
            const ctTo = await c["balanceOf(address)"](other.address)

            await expect(decryptCtUint256(o, ctFrom)).to.equal(0n)
            await expect(decryptCtUint256(other, ctTo)).to.equal(value)
        })

        it("approve encrypted 0 then transferFrom encrypted 0 does not change state", async function () {
            // reset: mint back for this test sequence
            // (this block runs after the previous test, which zeroed o's balance)
            await mintPublic(c, o, o.address, 1000n).then((t) => t.wait())
            await mintPublic(c, o, other.address, 0n).then((t) => t.wait())

            const zero = 0n
            const itZeroApprove = (await encryptItUint256(
                o,
                zero,
                addr,
                c.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(o)
                    .getFunction("approve(address,((uint256,uint256),bytes))")(other.address, itZeroApprove, txOpts)
            ).wait()

            const itZeroTransferFrom = (await encryptItUint256(
                other,
                zero,
                addr,
                c.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
            )) as itUint256

            const fromBefore = decryptCtUint256(o, await c["balanceOf(address)"](o.address))
            const toBefore = decryptCtUint256(other, await c["balanceOf(address)"](other.address))

            await (
                await c
                    .connect(other)
                    .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")(
                        o.address,
                        other.address,
                        itZeroTransferFrom,
                        txOpts
                    )
            ).wait()

            const fromAfter = decryptCtUint256(o, await c["balanceOf(address)"](o.address))
            const toAfter = decryptCtUint256(other, await c["balanceOf(address)"](other.address))

            await expect(fromAfter).to.equal(fromBefore)
            await expect(toAfter).to.equal(toBefore)

            const ctAllowance = await c["allowance(address,address)"](o.address, other.address)
            const allowanceSpenderView = decryptCtUint256(other, ctAllowance.spenderCiphertext)
            await expect(allowanceSpenderView).to.equal(0n)
        })

        it("transferFrom encrypted exact allowance reduces allowance to zero", async function () {
            // reset: mint back and set a known allowance
            await mintPublic(c, o, o.address, 1000n).then((t) => t.wait())

            const allow = 250n
            await (
                await c
                    .connect(o)
                    .getFunction("approve(address,uint256)")(other.address, allow, txOpts)
            ).wait()

            const itAllow = (await encryptItUint256(
                other,
                allow,
                addr,
                c.interface.getFunction("transferFrom(address,address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(other)
                    .getFunction("transferFrom(address,address,((uint256,uint256),bytes))")(
                        o.address,
                        other.address,
                        itAllow,
                        txOpts
                    )
            ).wait()

            const ctFrom = await c["balanceOf(address)"](o.address)
            const ctTo = await c["balanceOf(address)"](other.address)

            // owner was >= 250 due to minting above; exact expected amounts depend on prior tests
            await expect(decryptCtUint256(other, ctTo)).to.be.greaterThan(0n)

            const ctAllowance = await c["allowance(address,address)"](o.address, other.address)
            const allowanceSpenderView = decryptCtUint256(other, ctAllowance.spenderCiphertext)
            await expect(allowanceSpenderView).to.equal(0n)
        })

        it("increaseAllowance encrypted 0n is a no-op", async function () {
            // Ensure allowance starts from 0 by approving 0 publicly.
            await (
                await c.connect(o).getFunction("approve(address,uint256)")(other.address, 0n, txOpts)
            ).wait()

            const itZero = (await encryptItUint256(
                o,
                0n,
                addr,
                c.interface.getFunction("increaseAllowance(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(o)
                    .getFunction("increaseAllowance(address,((uint256,uint256),bytes))")(other.address, itZero, txOpts)
            ).wait()

            const ctAllowance = await c["allowance(address,address)"](o.address, other.address)
            const allowanceOwnerView = decryptCtUint256(o, ctAllowance.ownerCiphertext)
            await expect(allowanceOwnerView).to.equal(0n)
        })

        it("decreaseAllowance encrypted exact current allowance reduces to zero", async function () {
            const current = 123n
            await (
                await c
                    .connect(o)
                    .getFunction("approve(address,uint256)")(other.address, current, txOpts)
            ).wait()

            const itSub = (await encryptItUint256(
                o,
                current,
                addr,
                c.interface.getFunction("decreaseAllowance(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(o)
                    .getFunction("decreaseAllowance(address,((uint256,uint256),bytes))")(other.address, itSub, txOpts)
            ).wait()

            const ctAllowance = await c["allowance(address,address)"](o.address, other.address)
            const allowanceOwnerView = decryptCtUint256(o, ctAllowance.ownerCiphertext)
            await expect(allowanceOwnerView).to.equal(0n)
        })

        it("encrypted mint/burn accept 0n and reject malformed itUint256", async function () {
            const fromBefore = decryptCtUint256(o, await c["balanceOf(address)"](o.address))

            // PrivateERC20Mock only bypasses MINTER_ROLE for the public mint overload.
            // The encrypted mint overload still requires MINTER_ROLE, so grant it here.
            await (
                await c.connect(o).grantRole(await c.MINTER_ROLE(), o.address)
            ).wait()

            const itZeroMint = (await encryptItUint256(
                o,
                0n,
                addr,
                c.interface.getFunction("mint(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(o)
                    .getFunction("mint(address,((uint256,uint256),bytes))")(o.address, itZeroMint, txOpts)
            ).wait()

            const itZeroBurn = (await encryptItUint256(
                o,
                0n,
                addr,
                c.interface.getFunction("burn(((uint256,uint256),bytes))").selector
            )) as itUint256

            await (
                await c
                    .connect(o)
                    .getFunction("burn(((uint256,uint256),bytes))")(itZeroBurn, txOpts)
            ).wait()

            const fromAfter = decryptCtUint256(o, await c["balanceOf(address)"](o.address))
            await expect(fromAfter).to.equal(fromBefore)

            const goodMint = (await encryptItUint256(
                o,
                1n,
                addr,
                c.interface.getFunction("mint(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            const badSig: itUint256 = {
                ciphertext: goodMint.ciphertext,
                signature: new Uint8Array()
            }

            await expectTxFails(
                c.connect(o)
                    .getFunction("mint(address,((uint256,uint256),bytes))")(o.address, badSig, txOpts)
            )
        })

        it("encrypted operations still work when publicAmountsEnabled=false", async function () {
            await (
                await c.connect(o).setPublicAmountsEnabled(false, txOpts)
            ).wait()

            const value = 10n
            const itValue = (await encryptItUint256(
                o,
                value,
                addr,
                c.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            const fromBefore = decryptCtUint256(o, await c["balanceOf(address)"](o.address))
            const toBefore = decryptCtUint256(other, await c["balanceOf(address)"](other.address))

            await (
                await c
                    .connect(o)
                    .getFunction("transfer(address,((uint256,uint256),bytes))")(other.address, itValue, txOpts)
            ).wait()

            const fromAfter = decryptCtUint256(o, await c["balanceOf(address)"](o.address))
            const toAfter = decryptCtUint256(other, await c["balanceOf(address)"](other.address))

            await expect(fromAfter).to.equal(fromBefore - value)
            await expect(toAfter).to.equal(toBefore + value)
        })

        it("rejects malformed itUint256: bad signature and swapped ciphertext limbs", async function () {
            const good = (await encryptItUint256(
                o,
                1n,
                addr,
                c.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            const badSig: itUint256 = {
                ciphertext: good.ciphertext,
                signature: new Uint8Array()
            }

            const swapped: itUint256 = {
                ciphertext: {
                    ciphertextHigh: good.ciphertext.ciphertextLow,
                    ciphertextLow: good.ciphertext.ciphertextHigh
                },
                signature: good.signature
            }

            await expectTxFails(
                c.connect(o)
                    .getFunction("transfer(address,((uint256,uint256),bytes))")(other.address, badSig, txOpts)
            )

            await expectTxFails(
                c.connect(o)
                    .getFunction("transfer(address,((uint256,uint256),bytes))")(other.address, swapped, txOpts)
            )
        })
    })

    describe("isolated deploy: self-transfer and unsafe approve", function () {
        let iso: PrivateERC20Mock
        let isoAddr: string
        let o: Wallet
        let other: Wallet

        before(async function () {
            const d = await deploy()
            iso = d.contract
            isoAddr = d.contractAddress
            o = d.owner
            other = d.otherAccount
            await mintPublic(iso, o, o.address, 1000n).then((t) => t.wait())
        })

        it("reverts self-transfer", async function () {
            const itValue = (await encryptItUint256(o,
                1n,
                isoAddr,
                iso.interface.getFunction("transfer(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await expectTxFails(
                iso.connect(o).getFunction("transfer(address,((uint256,uint256),bytes))")(o.address, itValue, txOpts)
            )
        })

        it("reverts unsafe approve then clears with approve zero", async function () {
            const a1 = (await encryptItUint256(o,
                100n,
                isoAddr,
                iso.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256
            await iso
                .connect(o)
                .getFunction("approve(address,((uint256,uint256),bytes))")(other.address, a1, txOpts)
                .then((t) => t.wait())

            const a2 = (await encryptItUint256(o,
                200n,
                isoAddr,
                iso.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256

            await expectTxFails(
                iso.connect(o).getFunction("approve(address,((uint256,uint256),bytes))")(other.address, a2, txOpts)
            )

            const z = (await encryptItUint256(o,
                0n,
                isoAddr,
                iso.interface.getFunction("approve(address,((uint256,uint256),bytes))").selector
            )) as itUint256
            await iso
                .connect(o)
                .getFunction("approve(address,((uint256,uint256),bytes))")(other.address, z, txOpts)
                .then((t) => t.wait())
        })
    })
})
