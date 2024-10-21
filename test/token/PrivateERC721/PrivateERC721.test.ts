import hre from "hardhat"
import { expect } from "chai"

import { setupAccounts } from "../../utils/accounts"
import { ContractTransactionReceipt, itString } from "@coti-io/coti-ethers"

const gasLimit = 12000000

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const factory = await hre.ethers.getContractFactory("PrivateERC721URIStorageMock")
  const contract = await factory.connect(owner).deploy({ gasLimit })

  await contract.waitForDeployment()
  
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("Private ERC721", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Deployment", function () {
    it("Deployed address should be a valid Ethereum address", async function () {
      expect(hre.ethers.isAddress(deployment.contractAddress)).to.eq(true)
    })

    it("Name should match deployment name", async function () {
      expect(await deployment.contract.name()).to.equal("Example")
    })

    it("Symbol should match deployment symbol", async function () {
      expect(await deployment.contract.symbol()).to.equal("EXL")
    })
  })

  describe("Minting", function () {
    const tokenURI = 'https://api.pudgypenguins.io/lil/18707'

    describe("Successful mint", function () {
      let tx: ContractTransactionReceipt | null

      before(async function () {
        const { contract, contractAddress, owner, otherAccount } = deployment
        
        const encryptedTokenURI = await owner.encryptValue(tokenURI, contractAddress, contract.mint.fragment.selector) as itString

        tx = await (
          await contract
            .connect(owner)
            .mint(
              otherAccount.address,
              encryptedTokenURI,
              { gasLimit })
        ).wait()
      })
      
      it("Should emit a 'Minted' event", async function () {
        const { contract } = deployment
  
        expect(tx).to.emit(contract, "Minted")
      })

      it("Should update the owners mapping", async function () {
        const { contract, otherAccount } = deployment
  
        expect(await contract.ownerOf(BigInt(0))).to.equal(otherAccount.address)
      })

      it("Should update the balances mapping", async function () {
        const { contract, otherAccount } = deployment
  
        expect(await contract.balanceOf(otherAccount.address)).to.equal(BigInt(1))
      })

    })

    it("Should fail to mint if the encrypted token URI is faulty", async function () {
      const { contract, contractAddress, otherAccount, owner } = deployment

      const ownerEncryptedTokenURI = await owner.encryptValue(tokenURI, contractAddress, contract.mint.fragment.selector) as itString
      const otherAccountEncryptedTokenURI = await otherAccount.encryptValue(tokenURI, contractAddress, contract.mint.fragment.selector) as itString

      const encryptedTokenURI = {
        ciphertext: ownerEncryptedTokenURI.ciphertext,
        signature: otherAccountEncryptedTokenURI.signature
      }

      const tx = await contract
        .connect(otherAccount)
        .mint(
          otherAccount.address,
          encryptedTokenURI,
          { gasLimit }
        )
      
      expect(tx).to.be.reverted
    })
  })

  describe("URI", function () {
    it("should return 0 for token URI if not set", async function () {
      const { contract, owner } = deployment

      const tokenId = BigInt(1)
      const ctURI = await contract.connect(owner).tokenURI(tokenId)
      const uri = await owner.decryptValue(ctURI)
      
      expect(uri).to.equal("")
    })
  })

  describe("Transfers", function () {
    describe("Successful transfer", function () {
      const tokenId = BigInt(0)
      const tokenURI = 'https://api.pudgypenguins.io/lil/18707'

      before(async function () {
        const { contract, owner, otherAccount } = deployment

        await (await contract.connect(otherAccount).approve(owner.address, tokenId, { gasLimit })).wait()

        await (
          await contract
            .connect(owner)
            .transferFrom(otherAccount.address, owner.address, tokenId, { gasLimit })
        ).wait()
      })

      it("Should transfer token to other account", async function () {
        const { contract, owner, otherAccount } = deployment
  
        expect(await contract.ownerOf(tokenId)).to.equal(owner.address)
        expect(await contract.balanceOf(owner.address)).to.equal(BigInt(1))
        expect(await contract.balanceOf(otherAccount.address)).to.equal(BigInt(0))
      })

      it("Should allow the new owner to decrypt the token URI", async function () {
        const { contract, owner } = deployment

        const encryptedTokenURI = await contract.tokenURI(tokenId)

        const decryptedTokenURI = await owner.decryptValue(encryptedTokenURI)

        expect(decryptedTokenURI).to.equal(tokenURI)
      })
      
      it("Should not allow the previous owner to decrypt the token URI", async function () {
        const { contract, otherAccount } = deployment

        const encryptedTokenURI = await contract.tokenURI(tokenId)

        const decryptedTokenURI = await otherAccount.decryptValue(encryptedTokenURI)

        expect(decryptedTokenURI).to.not.equal(tokenURI)
      })
    })

    describe("Failed transfers", function () {
      const tokenURI = 'https://api.pudgypenguins.io/lil/9040'

      it("Should fail transfer token to other account for when no allowance", async function () {
        const { contract, contractAddress, owner, otherAccount } = deployment

        const encryptedTokenURI = await owner.encryptValue(tokenURI, contractAddress, contract.mint.fragment.selector) as itString
  
        const tokenId = await deployment.contract.totalSupply()
        
        await (
          await contract
            .connect(owner)
            .mint(
              owner.address,
              encryptedTokenURI,
              { gasLimit }
            )
        ).wait()
  
        const tx = await contract
          .connect(otherAccount)
          .transferFrom(owner.address, otherAccount.address, tokenId, { gasLimit })
        let reverted = true
        try {
          await tx.wait()
          reverted = false
        } catch (error) {}
        expect(reverted).to.eq(true, "Should have reverted")
      })
  
      it("Should fail to transfer from non-owner", async function () {
        const { contract, contractAddress, owner, otherAccount } = deployment

        const encryptedTokenURI = await owner.encryptValue(tokenURI, contractAddress, contract.mint.fragment.selector) as itString
  
        const tokenId = await deployment.contract.totalSupply()
        
        await (
          await contract
            .connect(owner)
            .mint(
              owner.address,
              encryptedTokenURI,
              { gasLimit }
            )
        ).wait()
  
        const tx = await contract
          .connect(otherAccount)
          .transferFrom(owner.address, otherAccount.address, tokenId, { gasLimit })
        let reverted = true
        try {
          await tx.wait()
          reverted = false
        } catch (error) {}
        expect(reverted).to.eq(true, "Should have reverted")
      })
    })
  })
})