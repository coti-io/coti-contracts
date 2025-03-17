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
import type { NonPayableOverrides } from "../../../../../common";
import type {
  TransferWithAllowance64_8TestsContract,
  TransferWithAllowance64_8TestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/TransferWithAllowance64_8TestsContract";

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
    name: "computeAndCheckTransfer64_16_8",
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
    name: "computeAndCheckTransfer64_32_8",
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
    name: "computeAndCheckTransfer64_64_8",
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
    name: "computeAndCheckTransfer64_8_8",
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
  "0x608060405234801561001057600080fd5b50612638806100206000396000f3fe608060405234801561001057600080fd5b50600436106100725760003560e01c8063505b1e0c11610050578063505b1e0c146100f0578063f4fa211014610103578063f825a8e81461011657600080fd5b806333c92907146100775780634717f97c1461008c5780634b5611de146100dd575b600080fd5b61008a61008536600461246d565b610129565b005b60005460ff80821691610100810482169162010000820481169163010000009004165b6040805160ff9586168152938516602085015291151583830152909216606082015290519081900360800190f35b61008a6100eb36600461246d565b610766565b61008a6100fe36600461246d565b610ccc565b6100af610111366004612559565b611232565b61008a61012436600461246d565b6115f5565b60008060008061014b8b600001518c60e001518c602001518c60000151611b5b565b935093509350935061015c84611c48565b67ffffffffffffffff168860ff1614801561018b575061017b83611c48565b67ffffffffffffffff168760ff16145b80156101a2575061019b82611ceb565b1515861515145b80156101c257506101b281611c48565b67ffffffffffffffff168560ff16145b6102135760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064015b60405180910390fd5b61022f8b60c001518c602001518c602001518c60000151611d7c565b9296509094509250905061024284611c48565b67ffffffffffffffff168860ff16148015610271575061026183611c48565b67ffffffffffffffff168760ff16145b8015610288575061028182611ceb565b1515861515145b80156102a8575061029881611c48565b67ffffffffffffffff168560ff16145b6102f45760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6103108b604001518c60e001518c602001518c60000151611d9c565b9296509094509250905061032384611c48565b67ffffffffffffffff168860ff16148015610352575061034283611c48565b67ffffffffffffffff168760ff16145b8015610369575061036282611ceb565b1515861515145b8015610389575061037981611c48565b67ffffffffffffffff168560ff16145b6103d55760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6103f18b60c001518c606001518c602001518c60000151611dbc565b9296509094509250905061040484611c48565b67ffffffffffffffff168860ff16148015610433575061042383611c48565b67ffffffffffffffff168760ff16145b801561044a575061044382611ceb565b1515861515145b801561046a575061045a81611c48565b67ffffffffffffffff168560ff16145b6104b65760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6104d28b60c001518c60e001518c602001518c60000151611ddc565b929650909450925090506104e584611c48565b67ffffffffffffffff168860ff16148015610514575061050483611c48565b67ffffffffffffffff168760ff16145b801561052b575061052482611ceb565b1515861515145b801561054b575061053b81611c48565b67ffffffffffffffff168560ff16145b6105975760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6105b38b608001518c60e001518c602001518c60000151611dfc565b929650909450925090506105c684611c48565b67ffffffffffffffff168860ff161480156105f557506105e583611c48565b67ffffffffffffffff168760ff16145b801561060c575061060582611ceb565b1515861515145b801561062c575061061c81611c48565b67ffffffffffffffff168560ff16145b6106785760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60a001518c602001518c60000151611e1d565b929650909450925090506106a784611c48565b67ffffffffffffffff168860ff161480156106d657506106c683611c48565b67ffffffffffffffff168760ff16145b80156106ed57506106e682611ceb565b1515861515145b801561070d57506106fd81611c48565b67ffffffffffffffff168560ff16145b6107595760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b5050505050505050505050565b6000806000806107888b600001518c60e001518c600001518c60000151611e3e565b935093509350935061079984611c48565b67ffffffffffffffff168860ff161480156107c857506107b883611c48565b67ffffffffffffffff168760ff16145b80156107df57506107d882611ceb565b1515861515145b80156107ff57506107ef81611c48565b67ffffffffffffffff168560ff16145b61084b5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6108678b60c001518c602001518c600001518c60000151611e5d565b9296509094509250905061087a84611c48565b67ffffffffffffffff168860ff161480156108a9575061089983611c48565b67ffffffffffffffff168760ff16145b80156108c057506108b982611ceb565b1515861515145b80156108e057506108d081611c48565b67ffffffffffffffff168560ff16145b61092c5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6109488b60c001518c60e001518c600001518c60000151611e7c565b9296509094509250905061095b84611c48565b67ffffffffffffffff168860ff1614801561098a575061097a83611c48565b67ffffffffffffffff168760ff16145b80156109a1575061099a82611ceb565b1515861515145b80156109c157506109b181611c48565b67ffffffffffffffff168560ff16145b610a0d5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610a298b604001518c60e001518c600001518c60000151611e9b565b92965090945092509050610a3c84611c48565b67ffffffffffffffff168860ff16148015610a6b5750610a5b83611c48565b67ffffffffffffffff168760ff16145b8015610a825750610a7b82611ceb565b1515861515145b8015610aa25750610a9281611c48565b67ffffffffffffffff168560ff16145b610aee5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610b0a8b60c001518c606001518c600001518c60000151611ebb565b92965090945092509050610b1d84611c48565b67ffffffffffffffff168860ff16148015610b4c5750610b3c83611c48565b67ffffffffffffffff168760ff16145b8015610b635750610b5c82611ceb565b1515861515145b8015610b835750610b7381611c48565b67ffffffffffffffff168560ff16145b610bcf5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610beb8b608001518c60e001518c600001518c60000151611edb565b92965090945092509050610bfe84611c48565b67ffffffffffffffff168860ff16148015610c2d5750610c1d83611c48565b67ffffffffffffffff168760ff16145b8015610c445750610c3d82611ceb565b1515861515145b8015610c645750610c5481611c48565b67ffffffffffffffff168560ff16145b610cb05760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60a001518c600001518c60000151611efb565b600080600080610cee8b600001518c60e001518c606001518c60000151611f1b565b9350935093509350610cff84611c48565b67ffffffffffffffff168860ff16148015610d2e5750610d1e83611c48565b67ffffffffffffffff168760ff16145b8015610d455750610d3e82611ceb565b1515861515145b8015610d655750610d5581611c48565b67ffffffffffffffff168560ff16145b610db15760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610dcd8b60c001518c602001518c606001518c60000151611f3a565b92965090945092509050610de084611c48565b67ffffffffffffffff168860ff16148015610e0f5750610dff83611c48565b67ffffffffffffffff168760ff16145b8015610e265750610e1f82611ceb565b1515861515145b8015610e465750610e3681611c48565b67ffffffffffffffff168560ff16145b610e925760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610eae8b60c001518c60e001518c606001518c60000151611f59565b92965090945092509050610ec184611c48565b67ffffffffffffffff168860ff16148015610ef05750610ee083611c48565b67ffffffffffffffff168760ff16145b8015610f075750610f0082611ceb565b1515861515145b8015610f275750610f1781611c48565b67ffffffffffffffff168560ff16145b610f735760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b610f8f8b604001518c60e001518c606001518c60000151611f78565b92965090945092509050610fa284611c48565b67ffffffffffffffff168860ff16148015610fd15750610fc183611c48565b67ffffffffffffffff168760ff16145b8015610fe85750610fe182611ceb565b1515861515145b80156110085750610ff881611c48565b67ffffffffffffffff168560ff16145b6110545760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6110708b60c001518c606001518c606001518c60000151611f98565b9296509094509250905061108384611c48565b67ffffffffffffffff168860ff161480156110b257506110a283611c48565b67ffffffffffffffff168760ff16145b80156110c957506110c282611ceb565b1515861515145b80156110e957506110d981611c48565b67ffffffffffffffff168560ff16145b6111355760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6111518b608001518c60e001518c606001518c60000151611fb8565b9296509094509250905061116484611c48565b67ffffffffffffffff168860ff16148015611193575061118383611c48565b67ffffffffffffffff168760ff16145b80156111aa57506111a382611ceb565b1515861515145b80156111ca57506111ba81611c48565b67ffffffffffffffff168560ff16145b6112165760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60a001518c606001518c60000151611fd8565b60008060008061128060405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b6112b56040518060a0016040528060008152602001600081526020016000815260200160008152602001600060ff1681525090565b6112ea6040518060a0016040528060008152602001600081526020016000815260200160008152602001600060ff1681525090565b6112f38b611ff8565b83526112fe8a611ff8565b602084015261130f60ff8c16612061565b604084015261132060ff8b16612061565b606084015261133160ff8c166120cb565b608084015261134260ff8b166120cb565b60a084015261135360ff8c16612137565b60c084015261136460ff8b16612137565b60e084015261137289611ff8565b825261138060ff8a16612061565b602083015261139160ff8a166120cb565b60408301526113a260ff8a16612137565b606083015260ff891660808301526113b988611ff8565b81526113c760ff8916612061565b60208201526113d860ff89166120cb565b60408201526113e960ff8916612137565b606082015260ff881660808201528251602084015183518351600093849384938493611417939291906121a7565b9350935093509350611428846121c5565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff92909216919091179055611463836121c5565b600060016101000a81548160ff021916908360ff16021790555061148682611ceb565b6000805491151562010000027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff9092169190911790556114c5816121c5565b6000805460ff92831663010000009081027fffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffffff831681179384905561152c948c948c948c94938316908316179261010082048316926201000083048116929190910416610766565b60005461155d9088908890889060ff8082169161010081048216916201000082048116916301000000900416610129565b60005461158e9088908890889060ff80821691610100810482169162010000820481169163010000009004166115f5565b6000546115bf9088908890889060ff8082169161010081048216916201000082048116916301000000900416610ccc565b505060005460ff8082169f610100830482169f5062010000830482169e506301000000909204169b509950505050505050505050565b6000806000806116178b600001518c60e001518c604001518c600001516121d5565b935093509350935061162884611c48565b67ffffffffffffffff168860ff16148015611657575061164783611c48565b67ffffffffffffffff168760ff16145b801561166e575061166782611ceb565b1515861515145b801561168e575061167e81611c48565b67ffffffffffffffff168560ff16145b6116da5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6116f68b60c001518c602001518c604001518c600001516121f5565b9296509094509250905061170984611c48565b67ffffffffffffffff168860ff16148015611738575061172883611c48565b67ffffffffffffffff168760ff16145b801561174f575061174882611ceb565b1515861515145b801561176f575061175f81611c48565b67ffffffffffffffff168560ff16145b6117bb5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6117d78b608001518c60e001518c604001518c60000151612215565b929650909450925090506117ea84611c48565b67ffffffffffffffff168860ff16148015611819575061180983611c48565b67ffffffffffffffff168760ff16145b8015611830575061182982611ceb565b1515861515145b8015611850575061184081611c48565b67ffffffffffffffff168560ff16145b61189c5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6118b88b60c001518c60a001518c604001518c60000151612235565b929650909450925090506118cb84611c48565b67ffffffffffffffff168860ff161480156118fa57506118ea83611c48565b67ffffffffffffffff168760ff16145b8015611911575061190a82611ceb565b1515861515145b8015611931575061192181611c48565b67ffffffffffffffff168560ff16145b61197d5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6119998b604001518c60e001518c604001518c60000151612255565b929650909450925090506119ac84611c48565b67ffffffffffffffff168860ff161480156119db57506119cb83611c48565b67ffffffffffffffff168760ff16145b80156119f257506119eb82611ceb565b1515861515145b8015611a125750611a0281611c48565b67ffffffffffffffff168560ff16145b611a5e5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b611a7a8b60c001518c606001518c604001518c60000151612276565b92965090945092509050611a8d84611c48565b67ffffffffffffffff168860ff16148015611abc5750611aac83611c48565b67ffffffffffffffff168760ff16145b8015611ad35750611acc82611ceb565b1515861515145b8015611af35750611ae381611c48565b67ffffffffffffffff168560ff16145b611b3f5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c656400000000604482015260640161020a565b6106948b60c001518c60e001518c604001518c60000151612297565b600080808080808080606463c2ff267a611b7b60016004600282876122b3565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffffffff0000000000000000000000000000000000000000000000000000009091166004820152602481018f9052604481018e9052606481018d9052608481018c905260a4016080604051808303816000875af1158015611c0e573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611c3291906125ad565b929f919e509c50909a5098505050505050505050565b60006064630cfed56160045b60f81b846040518363ffffffff1660e01b8152600401611ca29291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af1158015611cc1573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611ce59190612612565b92915050565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015611d4f573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611d739190612612565b15159392505050565b600080808080808080606463c2ff267a611b7b60046001600281876122b3565b600080808080808080606463c2ff267a611b7b60026004816001876122b3565b600080808080808080606463c2ff267a611b7b60046002806001876122b3565b600080808080808080606463c2ff267a611b7b60048060026001876122b3565b600080808080808080606463c2ff267a611b7b6003600460026001876122b3565b600080808080808080606463c2ff267a611b7b6004600360026001876122b3565b600080808080808080606463c2ff267a611b7b600160048180876122b3565b600080808080808080606463c2ff267a611b7b600460018080876122b3565b600080808080808080606463c2ff267a611b7b600480600180876122b3565b600080808080808080606463c2ff267a611b7b60026004600180876122b3565b600080808080808080606463c2ff267a611b7b60046002600180876122b3565b600080808080808080606463c2ff267a611b7b60036004600180876122b3565b600080808080808080606463c2ff267a611b7b60046003600180876122b3565b600080808080808080606463c2ff267a611b7b600160048082876122b3565b600080808080808080606463c2ff267a611b7b600460018181876122b3565b600080808080808080606463c2ff267a611b7b600480806001876122b3565b600080808080808080606463c2ff267a611b7b60026004806001876122b3565b600080808080808080606463c2ff267a611b7b60046002816001876122b3565b600080808080808080606463c2ff267a611b7b60036004806001876122b3565b600080808080808080606463c2ff267a611b7b60046003816001876122b3565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b6090604401611ca2565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401611ca2565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401611ca2565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401611ca2565b600080808080808080606463c2ff267a611b7b6001808080876122b3565b60006064630cfed5616001611c54565b600080808080808080606463c2ff267a611b7b60016004600382876122b3565b600080808080808080606463c2ff267a611b7b60046001600381876122b3565b600080808080808080606463c2ff267a611b7b60036004816001876122b3565b600080808080808080606463c2ff267a611b7b60046003806001876122b3565b600080808080808080606463c2ff267a611b7b6002600460036001876122b3565b600080808080808080606463c2ff267a611b7b6004600260036001876122b3565b600080808080808080606463c2ff267a611b7b60048060036001875b60008160028111156122c7576122c76125e3565b60ff1660088460048111156122de576122de6125e3565b61ffff16901b61ffff1660108660048111156122fc576122fc6125e3565b62ffffff16901b62ffffff16601888600481111561231c5761231c6125e3565b63ffffffff16901b63ffffffff1660208a600481111561233e5761233e6125e3565b64ffffffffff16901b1717171760d81b9695505050505050565b604051610100810167ffffffffffffffff811182821017156123a3577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b803560ff811681146123ba57600080fd5b919050565b600060a082840312156123d157600080fd5b60405160a0810181811067ffffffffffffffff8211171561241b577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b806040525080915082358152602083013560208201526040830135604082015260608301356060820152612451608084016123a9565b60808201525092915050565b803580151581146123ba57600080fd5b60008060008060008060008789036102c081121561248a57600080fd5b6101008082121561249a57600080fd5b6124a2612358565b91508935825260208a0135602083015260408a0135604083015260608a0135606083015260808a0135608083015260a08a013560a083015260c08a013560c083015260e08a013560e08301528198506124fd8b828c016123bf565b9750505061250f896101a08a016123bf565b945061251e61024089016123a9565b935061252d61026089016123a9565b925061253c610280890161245d565b915061254b6102a089016123a9565b905092959891949750929550565b6000806000806080858703121561256f57600080fd5b612578856123a9565b9350612586602086016123a9565b9250612594604086016123a9565b91506125a2606086016123a9565b905092959194509250565b600080600080608085870312156125c357600080fd5b505082516020840151604085015160609095015191969095509092509050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60006020828403121561262457600080fd5b505191905056fea164736f6c6343000813000a";

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
