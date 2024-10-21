// Data Privacy Framework (last updated v0.1.0)

import hre from "hardhat"
import { expect } from "chai"
import { setupAccounts } from "../../utils/accounts"
import { DataPrivacyFramework } from "../../../typechain-types"

async function deploy() {
  const [owner, otherAccount] = await setupAccounts()

  const DataPrivacyFrameworkMock = await hre.ethers.getContractFactory("DataPrivacyFrameworkMock")

  const dataPrivacyFrameworkMock = await DataPrivacyFrameworkMock
    .connect(owner)
    .deploy()

  const contract = await dataPrivacyFrameworkMock.waitForDeployment()
  
  return { contract, contractAddress: await contract.getAddress(), owner, otherAccount }
}

describe("Data Privacy Framework", function () {
  let deployment: Awaited<ReturnType<typeof deploy>>

  before(async function () {
    deployment = await deploy()
  })

  describe("Deployment", function () {
    it("Deployed address should not be undefined", async function () {
      const { contractAddress } = deployment

      expect(contractAddress).to.not.equal(undefined)
    })
  })

  describe("Allowing operations", function () {
    it("Should remove '*' from the allowed operations mapping", async function () {
      const { contract } = deployment

      const tx = await contract.removeAllowedOperation("*")
      
      await tx.wait()

      const isAllowed = await contract.allowedOperations("*")

      expect(isAllowed).to.equal(false)
    })

    it("Should update the allowed operations mapping", async function () {
      const { contract } = deployment

      const tx = await contract.addAllowedOperation("*")
      
      await tx.wait()

      const isAllowed = await contract.allowedOperations("*")

      expect(isAllowed).to.equal(true)
    })

    it("Should allow all operations for all users", async function () {
      const { contract } = deployment

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0xB75fc724A3F951b6D25310d476893b60f4B77C8F", // random address
        "yzfsvycmua" // random string
      )

      expect(permissionGranted).to.equal(true)
    })
  })

  describe("Restricting operations", function () {
    before(async function() {
      const { contract } = deployment

      const tx = await contract.addRestrictedOperation("decrypt")
      
      await tx.wait()
    })

    it("Should add 'decrypt' to the restricted operations mapping", async function () {
      const { contract } = deployment

      const isRestricted = await contract.restrictedOperations("decrypt")

      expect(isRestricted).to.equal(true)
    })

    it("Should not allow any user to decrypt", async function () {
      const { contract } = deployment

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0xb818166f592329B1c6122c447E078425AF522e96", // random address
        "decrypt"
      )

      expect(permissionGranted).to.equal(false)
    })

    it("Should allow all other operations for all users", async function () {
      const { contract } = deployment

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x21AF6033aaC0E75eD898a9742183aC06B562bc92", // random address
        "mztsdimwve" // random string
      )

      expect(permissionGranted).to.equal(true)
    })

    it("Should remove 'decrypt' from the restricted operations mapping", async function () {
      const { contract } = deployment

      const tx = await contract.removeRestrictedOperation("decrypt")

      await tx.wait()

      const isRestricted = await contract.restrictedOperations("decrypt")

      expect(isRestricted).to.equal(false)
    })

    after(async function() {
      const { contract } = deployment

      let tx = await contract.removeAllowedOperation("*")
      
      await tx.wait()

      tx = await contract.addAllowedOperation("gt")
      
      await tx.wait()
    })
  })

  describe("Updating default permissions", function () {
    before(async function() {
      const { contract } = deployment

      let tx = await contract.setAddressDefaultPermission(false)
      
      await tx.wait()

      tx = await contract.setOperationDefaultPermission(false)
      
      await tx.wait()
    })

    it("Should set default address permissions to false", async function () {
      const { contract } = deployment

      const defaultPermission = await contract.addressDefaultPermission()

      expect(defaultPermission).to.equal(false)
    })

    it("Should set default operation permissions to false", async function () {
      const { contract } = deployment

      const defaultPermission = await contract.operationDefaultPermission()

      expect(defaultPermission).to.equal(false)
    })
  })

  describe("Setting permissions", function () {
    before(async function() {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x0000000000000000000000000000000000000001",
        operation: "*",
        active: false,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      inputData = {
        caller: "0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562",
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      tx = await contract.setPermission(inputData)
      
      await tx.wait()
    })

    it("Should update the permissions mapping", async function () {
      const { contract } = deployment

      const conditionIdx = await contract.permissions("0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562", "gt")

      expect(conditionIdx).to.equal(3)
    })

    it("Should update the conditions mapping", async function () {
      const { contract } = deployment

      const condition = await contract.conditions(3)

      expect(condition[0]).to.equal(BigInt(3))
      expect(condition[1]).to.equal("0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562")
      expect(condition[2]).to.equal("gt")
      expect(condition[3]).to.equal(true)
      expect(condition[4]).to.equal(false)
      expect(condition[5]).to.equal(false)
      expect(condition[6]).to.equal(BigInt(0))
      expect(condition[7]).to.equal(BigInt(0))
      expect(condition[8]).to.equal(BigInt(0))
      expect(condition[9]).to.equal("0x0000000000000000000000000000000000000000")
      expect(condition[10]).to.equal("")
    })

    it("Should update the activePermissions mapping", async function () {
      const { contract } = deployment

      const rows = await contract.activePermissions("0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562")

      expect(rows).to.equal(1)
    })

    it("Should allow 0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562 to compute gt", async function () {
      const { contract } = deployment

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562",
        "gt"
      )

      expect(permissionGranted).to.equal(true)
    })

    it("Should not allow other addresses to compute gt", async function () {
      const { contract } = deployment

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x7dc13edFF17da7e6D903573E688A5e06746B85e1", // random address
        "gt"
      )

      expect(permissionGranted).to.equal(false)
    })

    it("Should not increment activePermissions", async function () {
      const { contract } = deployment

      const inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562",
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000001",
        stringParameter: ""
      }

      const tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const activePermissions = await contract.activePermissions("0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562")

      expect(activePermissions).to.equal(1)
    })

    it("Should decrement activePermissions", async function () {
      const { contract } = deployment

      const inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562",
        operation: "gt",
        active: false,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000001",
        stringParameter: ""
      }

      const tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const activePermissions = await contract.activePermissions("0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562")

      expect(activePermissions).to.equal(0)
    })

    it("Should increment activePermissions", async function () {
      const { contract } = deployment

      const inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562",
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000001",
        stringParameter: ""
      }

      const tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const activePermissions = await contract.activePermissions("0x70D6c0e13B60964D3A3e372Dd86acA7b75dcc562")

      expect(activePermissions).to.equal(1)
    })
  })

  describe("Downloading conditions table", function () {
    before(async function() {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x2943dE47d15538a99C25246Ac8628da5D3EC7DA8",
        operation: "ntyxygayec",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      inputData = {
        caller: "0x9794eA465f89231eaaB730d87A2083E1ae091Bc6",
        operation: "gkdswnhthi",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      tx = await contract.setPermission(inputData)
      
      await tx.wait()

      inputData = {
        caller: "0x377005C508C0a44Ee986fA344A61FDCA453Cb31F",
        operation: "zqotxlwxwz",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      tx = await contract.setPermission(inputData)
      
      await tx.wait()
    })

    it("Should return the first two conditions", async function () {
      const { contract } = deployment

      const conditions = await contract.getConditions(1, 2)

      expect(conditions.length).to.equal(2)
    })

    it("Should return the third, fourth and fifth conditions", async function () {
      const { contract } = deployment

      const conditions = await contract.getConditions(3, 3)

      expect(conditions.length).to.equal(3)
    })

    it("Should return the fifth condition", async function () {
      const { contract } = deployment

      const conditions = await contract.getConditions(6, 2)

      expect(conditions.length).to.equal(1)
    })
  })

  describe("Evaluate condition", function () {
    it("Should return false due to falseKey", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x5b8E1b957369135d58a86c736F5eea661B929227", // random address
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: true,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x5b8E1b957369135d58a86c736F5eea661B929227",
        "gt"
      )

      expect(permissionGranted).to.equal(false)
    })

    it("Should return true due to trueKey", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x5b8E1b957369135d58a86c736F5eea661B929227", // random address
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: true,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x5b8E1b957369135d58a86c736F5eea661B929227",
        "gt"
      )

      expect(permissionGranted).to.equal(true)
    })

    it("Should return false due to timestampBefore", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x5b8E1b957369135d58a86c736F5eea661B929227", // random address
        operation: "gt",
        active: true,
        timestampBefore: BigInt(1),
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x5b8E1b957369135d58a86c736F5eea661B929227",
        "gt"
      )

      expect(permissionGranted).to.equal(false)
    })

    it("Should return false due to timestampAfter", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x5b8E1b957369135d58a86c736F5eea661B929227", // random address
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: BigInt(2716990740),
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x5b8E1b957369135d58a86c736F5eea661B929227",
        "gt"
      )

      expect(permissionGranted).to.equal(false)
    })

    it("Should return false due to uintParameter", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x5b8E1b957369135d58a86c736F5eea661B929227", // random address
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: BigInt(1),
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string,uint256)"](
        "0x5b8E1b957369135d58a86c736F5eea661B929227",
        "gt",
        BigInt(2)
      )

      expect(permissionGranted).to.equal(false)
    })

    it("Should return false due to addressParameter", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x5b8E1b957369135d58a86c736F5eea661B929227", // random address
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000001",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string,address)"](
        "0x5b8E1b957369135d58a86c736F5eea661B929227",
        "gt",
        "0x0000000000000000000000000000000000000002"
      )

      expect(permissionGranted).to.equal(false)
    })

    it("Should return false due to addressParameter", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0x5b8E1b957369135d58a86c736F5eea661B929227", // random address
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: "abc"
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string,string)"](
        "0x5b8E1b957369135d58a86c736F5eea661B929227",
        "gt",
        "def"
      )

      expect(permissionGranted).to.equal(false)
    })
  })

  describe("Get permission", function () {
    before(async function() {
      const { contract } = deployment

      let tx = await contract.setAddressDefaultPermission(true)
      
      await tx.wait()

      tx = await contract.setOperationDefaultPermission(true)
      
      await tx.wait()
    })

    it("Should return true due to caller holding generic permission", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0xbC70898a84DE49d3aA3190b124542bc5eca88A5C", // random address
        operation: "*",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0xbC70898a84DE49d3aA3190b124542bc5eca88A5C",
        "gt"
      )

      expect(permissionGranted).to.equal(true)
    })

    it("Should return true due to default operation permission", async function () {
      const { contract } = deployment

      let inputData: DataPrivacyFramework.InputDataStruct = {
        caller: "0xbC70898a84DE49d3aA3190b124542bc5eca88A5C", // random address
        operation: "*",
        active: false,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      inputData = {
        caller: "0xbC70898a84DE49d3aA3190b124542bc5eca88A5C", // random address
        operation: "gte",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0xbC70898a84DE49d3aA3190b124542bc5eca88A5C",
        "gt"
      )

      expect(permissionGranted).to.equal(true)
    })

    it("Should return true due to generic address holding the specific permission", async function () {
      const { contract } = deployment

      let inputData = {
        caller: "0x0000000000000000000000000000000000000001", // generic address
        operation: "gt",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x9e874196782e439FD2CEFcF62bC5c59816a6ae8b",
        "gt"
      )

      expect(permissionGranted).to.equal(true)
    })

    it("Should return true due to generic address holding the generic permission", async function () {
      const { contract } = deployment

      let inputData = {
        caller: "0x0000000000000000000000000000000000000001", // generic address
        operation: "gt",
        active: false,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      let tx = await contract.setPermission(inputData)
      
      await tx.wait()

      inputData = {
        caller: "0x0000000000000000000000000000000000000001", // generic address
        operation: "*",
        active: true,
        timestampBefore: "0",
        timestampAfter: "0",
        falseKey: false,
        trueKey: false,
        uintParameter: "0",
        addressParameter: "0x0000000000000000000000000000000000000000",
        stringParameter: ""
      }

      tx = await contract.setPermission(inputData)
      
      await tx.wait()

      const permissionGranted = await contract["isOperationAllowed(address,string)"](
        "0x9e874196782e439FD2CEFcF62bC5c59816a6ae8b",
        "gt"
      )

      expect(permissionGranted).to.equal(true)
    })
  })
})