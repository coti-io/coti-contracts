import hre, { ethers } from "hardhat"
import { expect } from "chai"

import { setupAccounts } from "../../utils/accounts"
import { PrivateERC20Mock, PrivateERC20WalletMock } from "../../../typechain-types"
import { ConfidentialAccount } from "@coti-io/coti-sdk-typescript"

const GAS_LIMIT = 12000000

async function deploy() {
    const [owner, otherAccount] = await setupAccounts()

    const tokenContract = await hre.ethers.getContractFactory("PrivateERC20Mock")

    const token = await tokenContract
        .connect(owner.wallet)
        .deploy({ gasLimit: GAS_LIMIT })

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
    let owner: ConfidentialAccount
    let otherAccount: ConfidentialAccount

    before(async function () {
        const deployment = await deploy()

        contract = deployment.contract
        contractAddress = deployment.contractAddress
        owner = deployment.owner
        otherAccount = deployment.otherAccount
    })

    describe("deploy", function () {
        it('has a name', async function () {
            await expect(await contract.name()).to.equal("PrivateERC20Mock");
        })

        it('has a symbol', async function () {
            await expect(await contract.symbol()).to.equal("PE20M");
        })

        it('has 2 decimals', async function () {
            await expect(await contract.decimals()).to.equal(2n);
        })
    })

    describe("mint", function () {
        const value = 5000n

        describe("successful mint", async function () {
            before("minting", async function () {
                this.tx = await contract
                    .connect(owner.wallet)
                    .mint(owner.wallet.address, value, { gasLimit: GAS_LIMIT })
                
                await this.tx.wait()
            })
            
            it('does not increment totalSupply', async function () {
                await expect(await contract.totalSupply()).to.equal(0n)
            })
            
            it('increments recipient balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.wallet.address)
                
                const balance = owner.decryptUint(ctBalance)
                
                await expect(balance).to.equal(value)
            })
            
            it('emits Transfer event', async function () {
                await expect(this.tx).to.emit(contract, "Transfer")
            })
        })
        
        describe('failed mint', async function () {
            it('rejects minting to the zero address', async function () {
                await expect(
                    contract
                        .connect(owner.wallet)
                        .mint(ethers.ZeroAddress, value)
                    )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidReceiver")
                    .withArgs(ethers.ZeroAddress)
            })
    
            // it('rejects overflow', async function () {
            //     const tx = await contract
            //         .connect(owner.wallet)
            //         .mint(owner.wallet.address, (BigInt(2) ** BigInt(64)) - BigInt(1), { gasLimit: GAS_LIMIT })
                
            //     await tx.wait()
    
            //     await expect(tx).to.be.reverted
            // })
        })
    })

    describe("burn", function () {
        const value = 5000n
        
        describe('failed burn', async function () {
            it('rejects burning from the zero address', async function () {
                await expect(
                    contract
                        .connect(owner.wallet)
                        .burn(ethers.ZeroAddress, value)
                    )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidSender")
                    .withArgs(ethers.ZeroAddress)
            })

            it('does not update balance when burning more than balance', async function () {
                const tx = await contract
                    .connect(owner.wallet)
                    .burn(owner.wallet.address, value + 1n, { gasLimit: GAS_LIMIT })
                
                await tx.wait()
                
                const ctBalance = await contract["balanceOf(address)"](owner.wallet.address)

                const balance = owner.decryptUint(ctBalance)
    
                await expect(balance).to.equal(value)
            })
        })

        describe('successful burn', async function () {
            before("burning", async function () {
                this.tx = await contract
                    .connect(owner.wallet)
                    .burn(owner.wallet.address, value, { gasLimit: GAS_LIMIT })
                
                await this.tx.wait()
            })

            it('decrements the senders balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.wallet.address)

                const balance = owner.decryptUint(ctBalance)
    
                await expect(balance).to.equal(0n)
            })

            it('emits Transfer event', async function () {
                await expect(this.tx).to.emit(contract, "Transfer")
            })
        })
    })

    describe("transfer", function () {
        const value = 10000n

        before("minting", async function () {
            this.tx = await contract
                .connect(owner.wallet)
                .mint(owner.wallet.address, value, { gasLimit: GAS_LIMIT })
            
            await this.tx.wait()
        })

        describe("failed transfer", async function () {
            it('rejects transferring to the zero address', async function () {
                const itValue = owner.encryptUint(value, contractAddress, contract["transfer(address,(uint256,bytes))"].fragment.selector)
    
                await expect(
                    contract
                        .connect(owner.wallet)
                        ["transfer(address,(uint256,bytes))"]
                        (ethers.ZeroAddress, itValue)
                    )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidReceiver")
                    .withArgs(ethers.ZeroAddress)
            })

            it('does not transfer tokens when amount exceeds balance', async function () {
                const itValue = owner.encryptUint(value + 1n, contractAddress, contract["transfer(address,(uint256,bytes))"].fragment.selector)

                const tx = await contract
                    .connect(owner.wallet)
                    ["transfer(address,(uint256,bytes))"]
                    (otherAccount.wallet.address, itValue, { gasLimit: GAS_LIMIT })
                
                await tx.wait()

                let ctBalance = await contract["balanceOf(address)"](owner.wallet.address)

                let balance = owner.decryptUint(ctBalance)
    
                await expect(balance).to.equal(value)

                ctBalance = await contract["balanceOf(address)"](otherAccount.wallet.address)

                balance = otherAccount.decryptUint(ctBalance)
    
                await expect(balance).to.equal(0n)
            })
        })

        describe("successful transfer", async function () {
            before("transferring", async function () {
                const itValue = owner.encryptUint(value / 2n, contractAddress, contract["transfer(address,(uint256,bytes))"].fragment.selector)

                const tx = await contract
                    .connect(owner.wallet)
                    ["transfer(address,(uint256,bytes))"]
                    (otherAccount.wallet.address, itValue, { gasLimit: GAS_LIMIT })
                
                await tx.wait()
            })

            it('decrements the senders balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.wallet.address)

                const balance = owner.decryptUint(ctBalance)
    
                await expect(balance).to.equal(value / 2n)
            })

            it('increments the receivers balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](otherAccount.wallet.address)

                const balance = otherAccount.decryptUint(ctBalance)
    
                await expect(balance).to.equal(value / 2n)
            })
        })
    })

    describe("approve", function () {
        const value = 5000n

        describe("failed approval", async function () {
            it('rejects when approving the zero address', async function () {
                const itValue = owner.encryptUint(value, contractAddress, contract["transfer(address,(uint256,bytes))"].fragment.selector)
    
                await expect(
                    contract
                        .connect(owner.wallet)
                        ["approve(address,(uint256,bytes))"]
                        (ethers.ZeroAddress, itValue)
                    )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidSpender")
                    .withArgs(ethers.ZeroAddress)
            })
        })

        describe("successful approval", async function () {
            before('approving', async function () {
                const itValue = owner.encryptUint(value, contractAddress, contract["approve(address,(uint256,bytes))"].fragment.selector)

                const tx = await contract
                    .connect(owner.wallet)
                    ["approve(address,(uint256,bytes))"]
                    (otherAccount.wallet.address, itValue, { gasLimit: GAS_LIMIT })
    
                await tx.wait()
            })

            it('increment the allowance encrypted with the owners key', async function () {
                const ctAllowance = await contract
                    ["allowance(address,address)"]
                    (owner.wallet.address, otherAccount.wallet.address)
                
                const allowance = owner.decryptUint(ctAllowance[1])

                await expect(allowance).to.equal(value)
            })

            it('increment the allowance encrypted with the spenders key', async function () {
                const ctAllowance = await contract
                    ["allowance(address,address)"]
                    (owner.wallet.address, otherAccount.wallet.address)
                
                const allowance = otherAccount.decryptUint(ctAllowance[2])

                await expect(allowance).to.equal(value)
            })
        })
    })

    describe('transferFrom', function () {
        const value = 3000n

        describe('failed transferFrom', async function () {
            it('rejects transferring to the zero address', async function () {
                const itValue = otherAccount.encryptUint(value, contractAddress, contract["transferFrom(address,address,(uint256,bytes))"].fragment.selector)
    
                await expect(
                    contract
                        .connect(otherAccount.wallet)
                        ["transferFrom(address,address,(uint256,bytes))"]
                        (owner.wallet.address, ethers.ZeroAddress, itValue)
                    )
                    .to.be.revertedWithCustomError(contract, "ERC20InvalidReceiver")
                    .withArgs(ethers.ZeroAddress)
            })

            describe("transferring more than the owners balance", async function () {
                before("transferring", async function () {
                    const itValue = otherAccount.encryptUint(2n * value, contractAddress, contract["transferFrom(address,address,(uint256,bytes))"].fragment.selector)

                    const tx = await contract
                        .connect(otherAccount.wallet)
                        ["transferFrom(address,address,(uint256,bytes))"]
                        (owner.wallet.address, "0x0000000000000000000000000000000000000001", itValue)
                    
                    await tx.wait()
                })

                it("does not decrement the owners balance", async function () {
                    const ctBalance = await contract["balanceOf(address)"](owner.wallet.address)

                    const balance = owner.decryptUint(ctBalance)
        
                    await expect(balance).to.equal(5000n)
                })

                it("does not decrement the spenders allowance", async function () {
                    const ctAllowance = await contract["allowance(address,address)"](owner.wallet.address, otherAccount.wallet.address)

                    const allowance = owner.decryptUint(ctAllowance[1])
        
                    await expect(allowance).to.equal(5000n)
                })
            })
        })

        describe('successful transferFrom', async function () {
            before('transferring', async function () {
                const itValue = otherAccount.encryptUint(value, contractAddress, contract["transferFrom(address,address,(uint256,bytes))"].fragment.selector)

                const tx = await contract
                    .connect(otherAccount.wallet)
                    ["transferFrom(address,address,(uint256,bytes))"]
                    (owner.wallet.address, otherAccount.wallet.address, itValue)
                
                await tx.wait()
            })

            it('decrement the owners balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](owner.wallet.address)

                const balance = owner.decryptUint(ctBalance)
    
                await expect(balance).to.equal(2000n)
            })

            it('increment the recipients balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](otherAccount.wallet.address)

                const balance = otherAccount.decryptUint(ctBalance)
    
                await expect(balance).to.equal(8000n)
            })

            it('decrement the spenders allowance', async function () {
                const ctAllowance = await contract["allowance(address,address)"](owner.wallet.address, otherAccount.wallet.address)

                const allowance = otherAccount.decryptUint(ctAllowance[2])
    
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

            walletContract = await walletContractFactory
                .connect(owner.wallet)
                .deploy({ gasLimit: GAS_LIMIT })

            walletContract = await walletContract.waitForDeployment()

            walletContractAddress = await walletContract.getAddress()

            this.tx = await contract
                .connect(owner.wallet)
                .mint(walletContractAddress, value, { gasLimit: GAS_LIMIT })
            
            await this.tx.wait()
        })

        describe("setAccountEncryptionAddress", async function () {
            before("setting account encryption address", async function () {
                const tx = await walletContract
                    .connect(otherAccount.wallet)
                    .setAccountEncryptionAddress(contractAddress, otherAccount.wallet.address, { gasLimit: GAS_LIMIT })
                
                await tx.wait()
            })

            it("update accountEncryptionAddress mapping", async function () {
                const accountEncryptionAddress = await contract.accountEncryptionAddress(walletContractAddress)
                
                await expect(accountEncryptionAddress).to.equal(otherAccount.wallet.address)
            })

            it("reencrypt balance using the new account encryption address", async function () {
                const ctBalance = await contract["balanceOf(address)"](walletContractAddress)

                const balance = otherAccount.decryptUint(ctBalance)

                await expect(balance).to.equal(value)
            })
        })

        describe("transfer", async function () {
            before("transferring", async function () {
                const tx = await walletContract
                    .connect(otherAccount.wallet)
                    .transfer(contractAddress, otherAccount.wallet.address, value / 2n, { gasLimit: GAS_LIMIT })
                
                await tx.wait()
            })

            it('decrement the senders balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](walletContractAddress)

                const balance = otherAccount.decryptUint(ctBalance)

                await expect(balance).to.equal(value / 2n)
            })

            it('increment the receivers balance', async function () {
                const ctBalance = await contract["balanceOf(address)"](otherAccount.wallet.address)

                const balance = otherAccount.decryptUint(ctBalance)

                await expect(balance).to.equal(13000n)
            })
        })

        describe("approve", async function () {
            before("approving", async function () {
                const tx = await walletContract
                    .connect(otherAccount.wallet)
                    .approve(contractAddress, owner.wallet.address, value / 2n, { gasLimit: GAS_LIMIT })
                
                await tx.wait()
            })

            it("increment the spenders allowance", async function () {
                const ctAllowance = await contract["allowance(address,address)"](walletContractAddress, owner.wallet.address)

                const allowance = otherAccount.decryptUint(ctAllowance[1])

                await expect(allowance).to.equal(value / 2n)
            })
        })

        describe("transferFrom", async function () {
            const value = 5000n

            before("transferring", async function () {
                const itValue = otherAccount.encryptUint(value, contractAddress, contract["approve(address,(uint256,bytes))"].fragment.selector)

                let tx = await contract
                    .connect(otherAccount.wallet)
                    ["approve(address,(uint256,bytes))"]
                    (walletContractAddress, itValue)
                
                await tx.wait()

                tx = await walletContract
                    .connect(otherAccount.wallet)
                    .transferFrom(contractAddress, otherAccount.wallet.address, owner.wallet.address, value)
                
                await tx.wait()
            })

            it('decrement the owners balance', async function () {
                const itBalance = await contract["balanceOf(address)"](otherAccount.wallet.address)

                const balance = otherAccount.decryptUint(itBalance)

                await expect(balance).to.equal(8000n)
            })

            it('increment the recipients balance', async function () {
                const itBalance = await contract["balanceOf(address)"](owner.wallet.address)

                const balance = owner.decryptUint(itBalance)

                await expect(balance).to.equal(7000n)
            })
        })
    })

    describe("maximum allowance", function () {
        const value = (2n ** 64n) - 1n

        before("transferring", async function () {
            let itValue = owner.encryptUint(value, contractAddress, contract["approve(address,(uint256,bytes))"].fragment.selector)

            let tx = await contract
                .connect(owner.wallet)
                ["approve(address,(uint256,bytes))"]
                (otherAccount.wallet.address, itValue)
            
            await tx.wait()

            itValue = otherAccount.encryptUint(7000n, contractAddress, contract["transferFrom(address,address,(uint256,bytes))"].fragment.selector)

            tx = await contract
                .connect(otherAccount.wallet)
                ["transferFrom(address,address,(uint256,bytes))"]
                (owner.wallet.address, "0x0000000000000000000000000000000000000001", itValue)
            
            await tx.wait()
        })

        it("decrement the owners balance", async function () {
            const ctBalance = await contract["balanceOf(address)"](owner.wallet.address)

            const balance = owner.decryptUint(ctBalance)

            await expect(balance).to.equal(0n)
        })

        it("does not decrement the spenders allowance", async function () {
            const ctAllowance = await contract["allowance(address,address)"](owner.wallet.address, otherAccount.wallet.address)

            const allowance = owner.decryptUint(ctAllowance[1])

            await expect(allowance).to.equal(value)
        })
    })
})
