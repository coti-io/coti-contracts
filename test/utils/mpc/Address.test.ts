import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../accounts"
import { buildAddressInputText, decryptAddress } from "@coti-io/coti-sdk-typescript"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("AddressTestsContract")
  const contract = await factory.connect(owner).deploy({ gasLimit })
  await contract.waitForDeployment()
  
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

function formatString(str: string) {
    return str.replace(/\0/g, '')
}

describe("MPC Core", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

    describe("Encrypted Addresses", function () {
        describe("Set user-encrypted address using encrypted value", function () {
            const addr = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' // vitalik.eth

            it("Should store the address encrypted using the users key", async function () {
                const { contract, contractAddress, owner } = deployment

                const itAddress = buildAddressInputText(
                    addr,
                    { wallet: owner.wallet, userKey: owner.userKey },
                    contractAddress,
                    contract.setUserEncryptedAddress.fragment.selector
                )

                const tx = await contract
                    .connect(owner.wallet)
                    .setUserEncryptedAddress(itAddress, { gasLimit })
                
                await tx.wait()
            })
    
            it("Should retrieve the address encrypted with the users key", async function () {
                const { contract, owner } = deployment
    
                const userEncryptedAddress = await contract.userEncryptedAddress()
    
                const decryptedAddress = decryptAddress(userEncryptedAddress, owner.userKey)
    
                expect(decryptedAddress).to.equal(addr)
            })
    
            it("Should fail to decrypt the string encrypted with the users key", async function () {
                const { contract, otherAccount } = deployment
    
                const userEncryptedAddr = await contract.userEncryptedAddress()
    
                let success = false

                // decryption will fail because the output will not be a valid address
                try {
                    decryptAddress(userEncryptedAddr, otherAccount.userKey)
                    success = true
                } catch (e) {
                    success = false
                }
    
                expect(success).to.equal(false)
            })
        })

        describe("Set network-encrypted address using an encrypted value", function () {
            const addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" // WETH
    
            it("Should store the address encrypted using the network key", async function () {
                const { contract, contractAddress, owner } = deployment
            
                const itAddress = buildAddressInputText(
                    addr,
                    { wallet: owner.wallet, userKey: owner.userKey },
                    contractAddress,
                    contract.setNetworkEncryptedAddress.fragment.selector
                )
    
                const tx = await contract
                    .connect(owner.wallet)
                    .setNetworkEncryptedAddress(itAddress, { gasLimit })
                
                await tx.wait()
            })
    
            it("Should decrypt the network-encrypted address and store it in clear text", async function () {
                const { contract, owner } = deployment
    
                const tx = await contract
                    .connect(owner.wallet)
                    .decryptNetworkEncryptedAddress()
    
                await tx.wait()
    
                const decryptedAddress = await contract.plaintextAddress()
    
                expect(decryptedAddress).to.equal(addr)
            })
        })

        describe("Set user-encrypted address using a non-encrypted value", function () {
            const addr = "0xdAC17F958D2ee523a2206206994597C13D831ec7" // USDT
    
            it("Should store the address encrypted using the network key", async function () {
                const { contract, owner } = deployment
    
                const tx = await contract
                    .connect(owner.wallet)
                    .setPublicAddress(addr, { gasLimit })
    
                await tx.wait()
            })
    
            it("Should retrieve the address encrypted with the users key", async function () {
                const { contract, owner } = deployment
    
                const userEncryptedAddress = await contract.userEncryptedAddress()
    
                const decryptedAddress = decryptAddress(userEncryptedAddress, owner.userKey)
    
                expect(decryptedAddress).to.equal(addr)
            })
        })

        describe("Set isEqual using two encrypted values", function () {
            const a = "0x0000000000000000000000000000000000000001"
            const b = "0x0000000000000000000000000000000000000002"
    
            describe("Using eq", function () {            
                it("Should set isEqual to false", async function () {
                    const { contract, contractAddress, owner } = deployment
            
                    const itAddressA = buildAddressInputText(
                        a,
                        { wallet: owner.wallet, userKey: owner.userKey },
                        contractAddress,
                        contract["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"].fragment.selector
                    )
            
                    const itAddressB = buildAddressInputText(
                        b,
                        { wallet: owner.wallet, userKey: owner.userKey },
                        contractAddress,
                        contract["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"].fragment.selector
                    )
            
                    const tx = await contract
                        .connect(owner.wallet)
                        ["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"](itAddressA, itAddressB, true, { gasLimit })
                    
                    await tx.wait()
            
                    const isEqual = await contract.isEqual()
            
                    expect(isEqual).to.equal(false)
                })

                it("Should set isEqual to true", async function () {
                    const { contract, contractAddress, owner } = deployment
            
                    const itAddress = buildAddressInputText(
                        a,
                        { wallet: owner.wallet, userKey: owner.userKey },
                        contractAddress,
                        contract["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"].fragment.selector
                    )
            
                    const tx = await contract
                        .connect(owner.wallet)
                        ["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"](itAddress, itAddress, true, { gasLimit })
                    
                    await tx.wait()
            
                    const isEqual = await contract.isEqual()
            
                    expect(isEqual).to.equal(true)
                })
            })
    
            describe("Using ne", function () {
                it("Should set isEqual to false", async function () {
                    const { contract, contractAddress, owner } = deployment
            
                    const itAddressA = buildAddressInputText(
                        a,
                        { wallet: owner.wallet, userKey: owner.userKey },
                        contractAddress,
                        contract["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"].fragment.selector
                    )
            
                    const itAddressB = buildAddressInputText(
                        b,
                        { wallet: owner.wallet, userKey: owner.userKey },
                        contractAddress,
                        contract["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"].fragment.selector
                    )
            
                    const tx = await contract
                        .connect(owner.wallet)
                        ["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"](itAddressA, itAddressB, false, { gasLimit })
                    
                    await tx.wait()
            
                    const isEqual = await contract.isEqual()
            
                    expect(isEqual).to.equal(false)
                })

                it("Should set isEqual to true", async function () {
                    const { contract, contractAddress, owner } = deployment
            
                    const itAddress = buildAddressInputText(
                        a,
                        { wallet: owner.wallet, userKey: owner.userKey },
                        contractAddress,
                        contract["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"].fragment.selector
                    )
            
                    const tx = await contract
                        .connect(owner.wallet)
                        ["setIsEqual(((uint256,uint256,uint256),bytes,bytes,bytes),((uint256,uint256,uint256),bytes,bytes,bytes),bool)"](itAddress, itAddress, false, { gasLimit })
                    
                    await tx.wait()
            
                    const isEqual = await contract.isEqual()
            
                    expect(isEqual).to.equal(true)
                })
            })
        })

        describe("Set user-encrypted address using a random value", function () {
            const addr = "0xdAC17F958D2ee523a2206206994597C13D831ec7" // USDT
    
            it("Should store the address encrypted using the network key", async function () {
                const { contract, owner } = deployment
    
                const tx = await contract
                    .connect(owner.wallet)
                    .setRandomAddress({ gasLimit })
    
                await tx.wait()
            })
    
            it("Should retrieve the address encrypted with the users key", async function () {
                const { contract, owner } = deployment
    
                const userEncryptedAddress = await contract.userEncryptedAddress()
    
                const decryptedAddress = decryptAddress(userEncryptedAddress, owner.userKey)
    
                expect(decryptedAddress).to.not.equal(addr)
            })
        })
    })

  describe("Set user-encrypted string using a random value", function () {
    const str = "Hello darkness, my old friend."

    it("It should store the encrypted string using the users key", async function () {
        const { contract, owner } = deployment

        const tx = await contract
            .connect(owner.wallet)
            .setRandomString({ gasLimit })

        await tx.wait()
    })

    it("It should retrieve the string encrypted with the users key", async function () {
        const { contract, owner } = deployment

        const userEncryptedString = await contract.getUserEncryptedString()

        const decryptedStr = decryptString(userEncryptedString, owner.userKey)

        expect(decryptedStr).to.not.equal(str)
    })
  })
})