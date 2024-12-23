/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import {
  Contract,
  ContractFactory,
  ContractTransactionResponse,
  Interface,
} from "ethers";
import type { Signer, ContractDeployTransaction, ContractRunner } from "ethers";
import type { NonPayableOverrides } from "../../../../../../common";
import type {
  TransferWithAllowance64_8TestsContract,
  TransferWithAllowance64_8TestsContractInterface,
} from "../../../../../../contracts/mocks/utils/mpc/TransferWithAllowance64_64TestsContract.sol/TransferWithAllowance64_8TestsContract";

const _abi = [
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtUint8",
            name: "a8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint8",
            name: "b8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "a16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "b16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "a32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "b32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "a64_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "b64_s",
            type: "uint256",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllGTCastingValues",
        name: "allGTCastingValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "amount8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "amount16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "amount32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "amount64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "amount",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAmountValues",
        name: "allAmountValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "allowance8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "allowance16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "allowance32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "allowance64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "allowance",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAllowanceValues",
        name: "allAllowanceValues",
        type: "tuple",
      },
      {
        internalType: "uint8",
        name: "new_a",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "new_b",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "res",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "new_allowance",
        type: "uint8",
      },
    ],
    name: "computeAndCheckTransfer64_16_64",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtUint8",
            name: "a8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint8",
            name: "b8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "a16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "b16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "a32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "b32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "a64_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "b64_s",
            type: "uint256",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllGTCastingValues",
        name: "allGTCastingValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "amount8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "amount16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "amount32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "amount64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "amount",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAmountValues",
        name: "allAmountValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "allowance8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "allowance16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "allowance32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "allowance64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "allowance",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAllowanceValues",
        name: "allAllowanceValues",
        type: "tuple",
      },
      {
        internalType: "uint8",
        name: "new_a",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "new_b",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "res",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "new_allowance",
        type: "uint8",
      },
    ],
    name: "computeAndCheckTransfer64_32_64",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtUint8",
            name: "a8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint8",
            name: "b8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "a16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "b16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "a32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "b32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "a64_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "b64_s",
            type: "uint256",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllGTCastingValues",
        name: "allGTCastingValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "amount8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "amount16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "amount32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "amount64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "amount",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAmountValues",
        name: "allAmountValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "allowance8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "allowance16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "allowance32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "allowance64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "allowance",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAllowanceValues",
        name: "allAllowanceValues",
        type: "tuple",
      },
      {
        internalType: "uint8",
        name: "new_a",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "new_b",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "res",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "new_allowance",
        type: "uint8",
      },
    ],
    name: "computeAndCheckTransfer64_64_64",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtUint8",
            name: "a8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint8",
            name: "b8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "a16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "b16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "a32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "b32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "a64_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "b64_s",
            type: "uint256",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllGTCastingValues",
        name: "allGTCastingValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "amount8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "amount16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "amount32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "amount64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "amount",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAmountValues",
        name: "allAmountValues",
        type: "tuple",
      },
      {
        components: [
          {
            internalType: "gtUint8",
            name: "allowance8_s",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "allowance16_s",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "allowance32_s",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "allowance64_s",
            type: "uint256",
          },
          {
            internalType: "uint8",
            name: "allowance",
            type: "uint8",
          },
        ],
        internalType:
          "struct TransferWithAllowance64_8TestsContract.AllAllowanceValues",
        name: "allAllowanceValues",
        type: "tuple",
      },
      {
        internalType: "uint8",
        name: "new_a",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "new_b",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "res",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "new_allowance",
        type: "uint8",
      },
    ],
    name: "computeAndCheckTransfer64_8_64",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "getResults",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint8",
        name: "a",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "b",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "amount",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "allowance",
        type: "uint8",
      },
    ],
    name: "transferWithAllowance64Test",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b50612652806100206000396000f3fe608060405234801561001057600080fd5b50600436106100725760003560e01c8063c9d32ba911610050578063c9d32ba9146100f0578063f4fa211014610103578063f8ce73b81461011657600080fd5b80634717f97c14610077578063ad9926d6146100c8578063b4b92fac146100dd575b600080fd5b60005460ff80821691610100810482169162010000820481169163010000009004165b6040805160ff9586168152938516602085015291151583830152909216606082015290519081900360800190f35b6100db6100d636600461245e565b610129565b005b6100db6100eb36600461245e565b610766565b6100db6100fe36600461245e565b610ccc565b61009a61011136600461254a565b611232565b6100db61012436600461245e565b6115f5565b60008060008061014b8b60c001518c60e001518c606001518c60600151611b5b565b935093509350935061015c84611c46565b67ffffffffffffffff168860ff1614801561018b575061017b83611c46565b67ffffffffffffffff168760ff16145b80156101a2575061019b82611ce9565b1515861515145b80156101c257506101b281611c46565b67ffffffffffffffff168560ff16145b6102135760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064015b60405180910390fd5b61022f8b600001518c60e001518c606001518c60600151611d7a565b9296509094509250905061024284611c46565b67ffffffffffffffff168860ff16148015610271575061026183611c46565b67ffffffffffffffff168760ff16145b8015610288575061028182611ce9565b1515861515145b80156102a8575061029881611c46565b67ffffffffffffffff168560ff16145b6102f45760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6103108b60c001518c602001518c606001518c60600151611d99565b9296509094509250905061032384611c46565b67ffffffffffffffff168860ff16148015610352575061034283611c46565b67ffffffffffffffff168760ff16145b8015610369575061036282611ce9565b1515861515145b8015610389575061037981611c46565b67ffffffffffffffff168560ff16145b6103d55760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6103f18b604001518c60e001518c606001518c60600151611db8565b9296509094509250905061040484611c46565b67ffffffffffffffff168860ff16148015610433575061042383611c46565b67ffffffffffffffff168760ff16145b801561044a575061044382611ce9565b1515861515145b801561046a575061045a81611c46565b67ffffffffffffffff168560ff16145b6104b65760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6104d28b60c001518c606001518c606001518c60600151611dd7565b929650909450925090506104e584611c46565b67ffffffffffffffff168860ff16148015610514575061050483611c46565b67ffffffffffffffff168760ff16145b801561052b575061052482611ce9565b1515861515145b801561054b575061053b81611c46565b67ffffffffffffffff168560ff16145b6105975760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6105b38b608001518c60e001518c606001518c60600151611df6565b929650909450925090506105c684611c46565b67ffffffffffffffff168860ff161480156105f557506105e583611c46565b67ffffffffffffffff168760ff16145b801561060c575061060582611ce9565b1515861515145b801561062c575061061c81611c46565b67ffffffffffffffff168560ff16145b6106785760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60a001518c606001518c60600151611e15565b929650909450925090506106a784611c46565b67ffffffffffffffff168860ff161480156106d657506106c683611c46565b67ffffffffffffffff168760ff16145b80156106ed57506106e682611ce9565b1515861515145b801561070d57506106fd81611c46565b67ffffffffffffffff168560ff16145b6107595760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b5050505050505050505050565b6000806000806107888b600001518c60e001518c604001518c60600151611e34565b935093509350935061079984611c46565b67ffffffffffffffff168860ff161480156107c857506107b883611c46565b67ffffffffffffffff168760ff16145b80156107df57506107d882611ce9565b1515861515145b80156107ff57506107ef81611c46565b67ffffffffffffffff168560ff16145b61084b5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6108678b60c001518c602001518c604001518c60600151611e54565b9296509094509250905061087a84611c46565b67ffffffffffffffff168860ff161480156108a9575061089983611c46565b67ffffffffffffffff168760ff16145b80156108c057506108b982611ce9565b1515861515145b80156108e057506108d081611c46565b67ffffffffffffffff168560ff16145b61092c5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6109488b604001518c60e001518c604001518c60600151611e74565b9296509094509250905061095b84611c46565b67ffffffffffffffff168860ff1614801561098a575061097a83611c46565b67ffffffffffffffff168760ff16145b80156109a1575061099a82611ce9565b1515861515145b80156109c157506109b181611c46565b67ffffffffffffffff168560ff16145b610a0d5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610a298b60c001518c606001518c604001518c60600151611e94565b92965090945092509050610a3c84611c46565b67ffffffffffffffff168860ff16148015610a6b5750610a5b83611c46565b67ffffffffffffffff168760ff16145b8015610a825750610a7b82611ce9565b1515861515145b8015610aa25750610a9281611c46565b67ffffffffffffffff168560ff16145b610aee5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610b0a8b608001518c60e001518c604001518c60600151611eb4565b92965090945092509050610b1d84611c46565b67ffffffffffffffff168860ff16148015610b4c5750610b3c83611c46565b67ffffffffffffffff168760ff16145b8015610b635750610b5c82611ce9565b1515861515145b8015610b835750610b7381611c46565b67ffffffffffffffff168560ff16145b610bcf5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610beb8b60c001518c60a001518c604001518c60600151611ed3565b92965090945092509050610bfe84611c46565b67ffffffffffffffff168860ff16148015610c2d5750610c1d83611c46565b67ffffffffffffffff168760ff16145b8015610c445750610c3d82611ce9565b1515861515145b8015610c645750610c5481611c46565b67ffffffffffffffff168560ff16145b610cb05760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60e001518c604001518c60600151611ef2565b600080600080610cee8b600001518c60e001518c600001518c60600151611f11565b9350935093509350610cff84611c46565b67ffffffffffffffff168860ff16148015610d2e5750610d1e83611c46565b67ffffffffffffffff168760ff16145b8015610d455750610d3e82611ce9565b1515861515145b8015610d655750610d5581611c46565b67ffffffffffffffff168560ff16145b610db15760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610dcd8b60c001518c602001518c600001518c60600151611f30565b92965090945092509050610de084611c46565b67ffffffffffffffff168860ff16148015610e0f5750610dff83611c46565b67ffffffffffffffff168760ff16145b8015610e265750610e1f82611ce9565b1515861515145b8015610e465750610e3681611c46565b67ffffffffffffffff168560ff16145b610e925760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610eae8b60c001518c60e001518c600001518c60600151611f4f565b92965090945092509050610ec184611c46565b67ffffffffffffffff168860ff16148015610ef05750610ee083611c46565b67ffffffffffffffff168760ff16145b8015610f075750610f0082611ce9565b1515861515145b8015610f275750610f1781611c46565b67ffffffffffffffff168560ff16145b610f735760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610f8f8b604001518c60e001518c600001518c60600151611f6e565b92965090945092509050610fa284611c46565b67ffffffffffffffff168860ff16148015610fd15750610fc183611c46565b67ffffffffffffffff168760ff16145b8015610fe85750610fe182611ce9565b1515861515145b80156110085750610ff881611c46565b67ffffffffffffffff168560ff16145b6110545760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6110708b60c001518c606001518c600001518c60600151611f8e565b9296509094509250905061108384611c46565b67ffffffffffffffff168860ff161480156110b257506110a283611c46565b67ffffffffffffffff168760ff16145b80156110c957506110c282611ce9565b1515861515145b80156110e957506110d981611c46565b67ffffffffffffffff168560ff16145b6111355760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6111518b608001518c60e001518c600001518c60600151611fae565b9296509094509250905061116484611c46565b67ffffffffffffffff168860ff16148015611193575061118383611c46565b67ffffffffffffffff168760ff16145b80156111aa57506111a382611ce9565b1515861515145b80156111ca57506111ba81611c46565b67ffffffffffffffff168560ff16145b6112165760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60a001518c600001518c60600151611fce565b60008060008061128060405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b6112b56040518060a0016040528060008152602001600081526020016000815260200160008152602001600060ff1681525090565b6112ea6040518060a0016040528060008152602001600081526020016000815260200160008152602001600060ff1681525090565b6112f38b611fee565b83526112fe8a611fee565b602084015261130f60ff8c16612057565b604084015261132060ff8b16612057565b606084015261133160ff8c166120c1565b608084015261134260ff8b166120c1565b60a084015261135360ff8c1661212d565b60c084015261136460ff8b1661212d565b60e084015261137289611fee565b825261138060ff8a16612057565b602083015261139160ff8a166120c1565b60408301526113a260ff8a1661212d565b606083015260ff891660808301526113b988611fee565b81526113c760ff8916612057565b60208201526113d860ff89166120c1565b60408201526113e960ff891661212d565b606082015260ff8816608082015282516020840151835183516000938493849384936114179392919061219d565b9350935093509350611428846121bb565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff92909216919091179055611463836121bb565b600060016101000a81548160ff021916908360ff16021790555061148682611ce9565b6000805491151562010000027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff9092169190911790556114c5816121bb565b6000805460ff92831663010000009081027fffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffffff831681179384905561152c948c948c948c94938316908316179261010082048316926201000083048116929190910416610ccc565b60005461155d9088908890889060ff80821691610100810482169162010000820481169163010000009004166115f5565b60005461158e9088908890889060ff8082169161010081048216916201000082048116916301000000900416610766565b6000546115bf9088908890889060ff8082169161010081048216916201000082048116916301000000900416610129565b505060005460ff8082169f610100830482169f5062010000830482169e506301000000909204169b509950505050505050505050565b6000806000806116178b600001518c60e001518c602001518c606001516121cb565b935093509350935061162884611c46565b67ffffffffffffffff168860ff16148015611657575061164783611c46565b67ffffffffffffffff168760ff16145b801561166e575061166782611ce9565b1515861515145b801561168e575061167e81611c46565b67ffffffffffffffff168560ff16145b6116da5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6116f68b60c001518c602001518c602001518c606001516121eb565b9296509094509250905061170984611c46565b67ffffffffffffffff168860ff16148015611738575061172883611c46565b67ffffffffffffffff168760ff16145b801561174f575061174882611ce9565b1515861515145b801561176f575061175f81611c46565b67ffffffffffffffff168560ff16145b6117bb5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6117d78b604001518c60e001518c602001518c6060015161220b565b929650909450925090506117ea84611c46565b67ffffffffffffffff168860ff16148015611819575061180983611c46565b67ffffffffffffffff168760ff16145b8015611830575061182982611ce9565b1515861515145b8015611850575061184081611c46565b67ffffffffffffffff168560ff16145b61189c5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6118b88b60c001518c606001518c602001518c6060015161222a565b929650909450925090506118cb84611c46565b67ffffffffffffffff168860ff161480156118fa57506118ea83611c46565b67ffffffffffffffff168760ff16145b8015611911575061190a82611ce9565b1515861515145b8015611931575061192181611c46565b67ffffffffffffffff168560ff16145b61197d5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6119998b60c001518c60e001518c602001518c60600151612249565b929650909450925090506119ac84611c46565b67ffffffffffffffff168860ff161480156119db57506119cb83611c46565b67ffffffffffffffff168760ff16145b80156119f257506119eb82611ce9565b1515861515145b8015611a125750611a0281611c46565b67ffffffffffffffff168560ff16145b611a5e5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b611a7a8b608001518c60e001518c602001518c60600151612268565b92965090945092509050611a8d84611c46565b67ffffffffffffffff168860ff16148015611abc5750611aac83611c46565b67ffffffffffffffff168760ff16145b8015611ad35750611acc82611ce9565b1515861515145b8015611af35750611ae381611c46565b67ffffffffffffffff168560ff16145b611b3f5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60a001518c602001518c60600151612288565b600080808080808080606463c2ff267a611b796004808080876122a4565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffffffff0000000000000000000000000000000000000000000000000000009091166004820152602481018f9052604481018e9052606481018d9052608481018c905260a4016080604051808303816000875af1158015611c0c573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611c30919061259e565b929f919e509c50909a5098505050505050505050565b60006064630cfed56160045b60f81b846040518363ffffffff1660e01b8152600401611ca09291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af1158015611cbf573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611ce39190612603565b92915050565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015611d4d573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611d719190612603565b15159392505050565b600080808080808080606463c2ff267a611b79600160048080876122a4565b600080808080808080606463c2ff267a611b79600460018180876122a4565b600080808080808080606463c2ff267a611b79600260048080876122a4565b600080808080808080606463c2ff267a611b79600460028180876122a4565b600080808080808080606463c2ff267a611b79600360048080876122a4565b600080808080808080606463c2ff267a611b79600460038180876122a4565b600080808080808080606463c2ff267a611b7960016004600381876122a4565b600080808080808080606463c2ff267a611b7960046001600382876122a4565b600080808080808080606463c2ff267a611b7960026004600381876122a4565b600080808080808080606463c2ff267a611b7960046002600382876122a4565b600080808080808080606463c2ff267a611b79600360048181876122a4565b600080808080808080606463c2ff267a611b79600460038082876122a4565b600080808080808080606463c2ff267a611b79600480600381876122a4565b600080808080808080606463c2ff267a611b79600160048181876122a4565b600080808080808080606463c2ff267a611b79600460018082876122a4565b600080808080808080606463c2ff267a611b79600480600181876122a4565b600080808080808080606463c2ff267a611b7960026004600181876122a4565b600080808080808080606463c2ff267a611b7960046002600182876122a4565b600080808080808080606463c2ff267a611b7960036004600181876122a4565b600080808080808080606463c2ff267a611b7960046003600182876122a4565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b6090604401611ca0565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401611ca0565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401611ca0565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401611ca0565b600080808080808080606463c2ff267a611b796001808080876122a4565b60006064630cfed5616001611c52565b600080808080808080606463c2ff267a611b7960016004600281876122a4565b600080808080808080606463c2ff267a611b7960046001600282876122a4565b600080808080808080606463c2ff267a611b79600260048181876122a4565b600080808080808080606463c2ff267a611b79600460028082876122a4565b600080808080808080606463c2ff267a611b79600480600281876122a4565b600080808080808080606463c2ff267a611b7960036004600281876122a4565b600080808080808080606463c2ff267a611b7960046003600282875b60008160028111156122b8576122b86125d4565b60ff1660088460048111156122cf576122cf6125d4565b61ffff16901b61ffff1660108660048111156122ed576122ed6125d4565b62ffffff16901b62ffffff16601888600481111561230d5761230d6125d4565b63ffffffff16901b63ffffffff1660208a600481111561232f5761232f6125d4565b64ffffffffff16901b1717171760d81b9695505050505050565b604051610100810167ffffffffffffffff81118282101715612394577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b803560ff811681146123ab57600080fd5b919050565b600060a082840312156123c257600080fd5b60405160a0810181811067ffffffffffffffff8211171561240c577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250809150823581526020830135602082015260408301356040820152606083013560608201526124426080840161239a565b60808201525092915050565b803580151581146123ab57600080fd5b60008060008060008060008789036102c081121561247b57600080fd5b6101008082121561248b57600080fd5b612493612349565b91508935825260208a0135602083015260408a0135604083015260608a0135606083015260808a0135608083015260a08a013560a083015260c08a013560c083015260e08a013560e08301528198506124ee8b828c016123b0565b97505050612500896101a08a016123b0565b945061250f610240890161239a565b935061251e610260890161239a565b925061252d610280890161244e565b915061253c6102a0890161239a565b905092959891949750929550565b6000806000806080858703121561256057600080fd5b6125698561239a565b93506125776020860161239a565b92506125856040860161239a565b91506125936060860161239a565b905092959194509250565b600080600080608085870312156125b457600080fd5b505082516020840151604085015160609095015191969095509092509050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60006020828403121561261557600080fd5b505191905056fea26469706673582212201b99804955b1da13ec4d40dff270a571a1cc2ae8ec4b9c5a0bf4a8b49fdc1cc864736f6c63430008140033";

type TransferWithAllowance64_8TestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: TransferWithAllowance64_8TestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class TransferWithAllowance64_8TestsContract__factory extends ContractFactory {
  constructor(
    ...args: TransferWithAllowance64_8TestsContractConstructorParams
  ) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override getDeployTransaction(
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(overrides || {});
  }
  override deploy(overrides?: NonPayableOverrides & { from?: string }) {
    return super.deploy(overrides || {}) as Promise<
      TransferWithAllowance64_8TestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): TransferWithAllowance64_8TestsContract__factory {
    return super.connect(
      runner
    ) as TransferWithAllowance64_8TestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TransferWithAllowance64_8TestsContractInterface {
    return new Interface(
      _abi
    ) as TransferWithAllowance64_8TestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): TransferWithAllowance64_8TestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as TransferWithAllowance64_8TestsContract;
  }
}