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
  TransferTestsContract,
  TransferTestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/TransferTestsContract";

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
        internalType: "struct TransferTestsContract.AllGTCastingValues",
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
        internalType: "struct TransferTestsContract.AllAmountValues",
        name: "allAmountValues",
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
    ],
    name: "computeAndCheckTransfer16",
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
        internalType: "struct TransferTestsContract.AllGTCastingValues",
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
        internalType: "struct TransferTestsContract.AllAmountValues",
        name: "allAmountValues",
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
    ],
    name: "computeAndCheckTransfer32",
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
        internalType: "struct TransferTestsContract.AllGTCastingValues",
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
        internalType: "struct TransferTestsContract.AllAmountValues",
        name: "allAmountValues",
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
    ],
    name: "computeAndCheckTransfer64",
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
    ],
    name: "transferTest",
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
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b50613308806100206000396000f3fe608060405234801561001057600080fd5b50600436106100675760003560e01c8063701251311161005057806370125131146100c1578063d7b0fe63146100d4578063f6029cb3146100e757600080fd5b80634717f97c1461006c5780636a3ae654146100ac575b600080fd5b60005460ff80821691610100810482169162010000909104165b6040805160ff948516815293909216602084015215159082015260600160405180910390f35b6100bf6100ba36600461317a565b6100fa565b005b6100866100cf366004613242565b610b69565b6100bf6100e236600461317a565b610e0a565b6100bf6100f536600461317a565b6112c6565b600080600061011688608001518960a0015189604001516126af565b9250925092506101258361276d565b63ffffffff168660ff1614801561014c57506101408261276d565b63ffffffff168560ff16145b8015610163575061015c81612810565b1515841515145b6101b45760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064015b60405180910390fd5b6101cb88600001518960a0015189604001516128a1565b919450925090506101db8361276d565b63ffffffff168660ff1614801561020257506101f68261276d565b63ffffffff168560ff16145b8015610219575061021281612810565b1515841515145b6102655760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b61027c8860800151896020015189604001516128bd565b9194509250905061028c8361276d565b63ffffffff168660ff161480156102b357506102a78261276d565b63ffffffff168560ff16145b80156102ca57506102c381612810565b1515841515145b6103165760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b61032d88604001518960a0015189604001516128d9565b9194509250905061033d8361276d565b63ffffffff168660ff1614801561036457506103588261276d565b63ffffffff168560ff16145b801561037b575061037481612810565b1515841515145b6103c75760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b6103de8860800151896060015189604001516128f5565b919450925090506103ee8361276d565b63ffffffff168660ff1614801561041557506104098261276d565b63ffffffff168560ff16145b801561042c575061042581612810565b1515841515145b6104785760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b61048f88608001518960a001518960000151612911565b9194509250905061049f8361276d565b63ffffffff168660ff161480156104c657506104ba8261276d565b63ffffffff168560ff16145b80156104dd57506104d681612810565b1515841515145b6105295760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b875160a0890151885161053d92919061292d565b9194509250905061054d8361276d565b63ffffffff168660ff1614801561057457506105688261276d565b63ffffffff168560ff16145b801561058b575061058481612810565b1515841515145b6105d75760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b6105ee886080015189602001518960000151612949565b919450925090506105fe8361276d565b63ffffffff168660ff1614801561062557506106198261276d565b63ffffffff168560ff16145b801561063c575061063581612810565b1515841515145b6106885760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b61069f88604001518960a001518960000151612965565b919450925090506106af8361276d565b63ffffffff168660ff161480156106d657506106ca8261276d565b63ffffffff168560ff16145b80156106ed57506106e681612810565b1515841515145b6107395760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b610750886080015189606001518960000151612982565b919450925090506107608361276d565b63ffffffff168660ff16148015610787575061077b8261276d565b63ffffffff168560ff16145b801561079e575061079781612810565b1515841515145b6107ea5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b61080188608001518960a00151896020015161299f565b919450925090506108118361276d565b63ffffffff168660ff16148015610838575061082c8261276d565b63ffffffff168560ff16145b801561084f575061084881612810565b1515841515145b61089b5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b6108b288600001518960a0015189602001516129bb565b919450925090506108c28361276d565b63ffffffff168660ff161480156108e957506108dd8261276d565b63ffffffff168560ff16145b801561090057506108f981612810565b1515841515145b61094c5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b6109638860800151896020015189602001516129d8565b919450925090506109738361276d565b63ffffffff168660ff1614801561099a575061098e8261276d565b63ffffffff168560ff16145b80156109b157506109aa81612810565b1515841515145b6109fd5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b610a1488604001518960a0015189602001516129f5565b91945092509050610a248361276d565b63ffffffff168660ff16148015610a4b5750610a3f8261276d565b63ffffffff168560ff16145b8015610a625750610a5b81612810565b1515841515145b610aae5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b610ac5886080015189606001518960200151612a11565b91945092509050610ad58361276d565b63ffffffff168660ff16148015610afc5750610af08261276d565b63ffffffff168560ff16145b8015610b135750610b0c81612810565b1515841515145b610b5f5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b5050505050505050565b6000806000610bb660405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610beb6040518060a0016040528060008152602001600081526020016000815260200160008152602001600060ff1681525090565b610bf488612a2d565b8252610bff87612a2d565b6020830152610c1060ff8916612a96565b6040830152610c2160ff8816612a96565b6060830152610c3260ff8916612b00565b6080830152610c4360ff8816612b00565b60a0830152610c5460ff8916612b6c565b60c0830152610c6560ff8816612b6c565b60e0830152610c7386612a2d565b8152610c8160ff8716612a96565b6020820152610c9260ff8716612b00565b6040820152610ca360ff8716612b6c565b606082015260ff8616608082015281516020830151825160009283928392610ccc929190612bdc565b925092509250610cdb83612bf7565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff92909216919091179055610d1682612bf7565b600060016101000a81548160ff021916908360ff160217905550610d3981612810565b60008054911515620100009081027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff8416811792839055610d96938993899360ff9384169284169290921792610100820481169290910416610e0a565b600054610dbc908690869060ff80821691610100810482169162010000909104166100fa565b600054610de2908690869060ff80821691610100810482169162010000909104166112c6565b505060005460ff8082169b610100830482169b50620100009092041698509650505050505050565b6000806000610e26886040015189606001518960000151612c07565b925092509250610e3583612c23565b61ffff168660ff16148015610e585750610e4e82612c23565b61ffff168560ff16145b8015610e6f5750610e6881612810565b1515841515145b610ebb5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b875160608901518851610ecf929190612c33565b91945092509050610edf83612c23565b61ffff168660ff16148015610f025750610ef882612c23565b61ffff168560ff16145b8015610f195750610f1281612810565b1515841515145b610f655760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b610f7c886040015189602001518960000151612c4f565b91945092509050610f8c83612c23565b61ffff168660ff16148015610faf5750610fa582612c23565b61ffff168560ff16145b8015610fc65750610fbf81612810565b1515841515145b6110125760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b611029886040015189606001518960200151612c6b565b9194509250905061103983612c23565b61ffff168660ff1614801561105c575061105282612c23565b61ffff168560ff16145b8015611073575061106c81612810565b1515841515145b6110bf5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b6110d6886000015189606001518960200151612c86565b919450925090506110e683612c23565b61ffff168660ff1614801561110957506110ff82612c23565b61ffff168560ff16145b8015611120575061111981612810565b1515841515145b61116c5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b611183886040015189602001518960200151612ca2565b9194509250905061119383612c23565b61ffff168660ff161480156111b657506111ac82612c23565b61ffff168560ff16145b80156111cd57506111c681612810565b1515841515145b6112195760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b611230886040015189606001518960000151612c07565b9194509250905061124083612c23565b61ffff168660ff16148015611263575061125982612c23565b61ffff168560ff16145b801561127a575061127381612810565b1515841515145b610b5f5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b60008060006112e28860c001518960e001518960600151612cbe565b9250925092506112f183612cd9565b67ffffffffffffffff168660ff16148015611320575061131082612cd9565b67ffffffffffffffff168560ff16145b8015611337575061133081612810565b1515841515145b6113835760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064016101ab565b61139a88600001518960e001518960600151612ce9565b919450925090506113aa83612cd9565b67ffffffffffffffff168660ff161480156113d957506113c982612cd9565b67ffffffffffffffff168560ff16145b80156113f057506113e981612810565b1515841515145b61143c5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064016101ab565b6114538860c0015189602001518960600151612d05565b9194509250905061146383612cd9565b67ffffffffffffffff168660ff16148015611492575061148282612cd9565b67ffffffffffffffff168560ff16145b80156114a957506114a281612810565b1515841515145b6114f55760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064016101ab565b61150c88604001518960e001518960600151612d21565b9194509250905061151c83612cd9565b67ffffffffffffffff168660ff1614801561154b575061153b82612cd9565b67ffffffffffffffff168560ff16145b8015611562575061155b81612810565b1515841515145b6115ae5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064016101ab565b6115c58860c0015189606001518960600151612d3d565b919450925090506115d583612cd9565b67ffffffffffffffff168660ff1614801561160457506115f482612cd9565b67ffffffffffffffff168560ff16145b801561161b575061161481612810565b1515841515145b6116675760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064016101ab565b61167e88608001518960e001518960600151612d59565b9194509250905061168e83612cd9565b67ffffffffffffffff168660ff161480156116bd57506116ad82612cd9565b67ffffffffffffffff168560ff16145b80156116d457506116cd81612810565b1515841515145b6117205760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064016101ab565b6117378860c001518960a001518960600151612d75565b9194509250905061174783612cd9565b67ffffffffffffffff168660ff16148015611776575061176682612cd9565b67ffffffffffffffff168560ff16145b801561178d575061178681612810565b1515841515145b6117d95760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203634206661696c65640000000060448201526064016101ab565b6117f08860c001518960e001518960400151612d91565b9194509250905061180083612cd9565b67ffffffffffffffff168660ff1614801561182f575061181f82612cd9565b67ffffffffffffffff168560ff16145b8015611846575061183f81612810565b1515841515145b6118925760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b6118a988600001518960e001518960400151612dad565b919450925090506118b983612cd9565b67ffffffffffffffff168660ff161480156118e857506118d882612cd9565b67ffffffffffffffff168560ff16145b80156118ff57506118f881612810565b1515841515145b61194b5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b6119628860c0015189602001518960400151612dca565b9194509250905061197283612cd9565b67ffffffffffffffff168660ff161480156119a1575061199182612cd9565b67ffffffffffffffff168560ff16145b80156119b857506119b181612810565b1515841515145b611a045760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b611a1b88604001518960e001518960400151612de7565b91945092509050611a2b83612cd9565b67ffffffffffffffff168660ff16148015611a5a5750611a4a82612cd9565b67ffffffffffffffff168560ff16145b8015611a715750611a6a81612810565b1515841515145b611abd5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b611ad48860c0015189606001518960400151612e04565b91945092509050611ae483612cd9565b67ffffffffffffffff168660ff16148015611b135750611b0382612cd9565b67ffffffffffffffff168560ff16145b8015611b2a5750611b2381612810565b1515841515145b611b765760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b611b8d88608001518960e001518960400151612e21565b91945092509050611b9d83612cd9565b67ffffffffffffffff168660ff16148015611bcc5750611bbc82612cd9565b67ffffffffffffffff168560ff16145b8015611be35750611bdc81612810565b1515841515145b611c2f5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b611c468860c001518960a001518960400151612e3d565b91945092509050611c5683612cd9565b67ffffffffffffffff168660ff16148015611c855750611c7582612cd9565b67ffffffffffffffff168560ff16145b8015611c9c5750611c9581612810565b1515841515145b611ce85760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203332206661696c65640000000060448201526064016101ab565b611cff8860c001518960e001518960000151612e59565b91945092509050611d0f83612cd9565b67ffffffffffffffff168660ff16148015611d3e5750611d2e82612cd9565b67ffffffffffffffff168560ff16145b8015611d555750611d4e81612810565b1515841515145b611da15760405162461bcd60e51b815260206004820152601b60248201527f7472616e73666572546573743a20636173742038206661696c6564000000000060448201526064016101ab565b875160e08901518851611db5929190612e75565b91945092509050611dc583612cd9565b67ffffffffffffffff168660ff16148015611df45750611de482612cd9565b67ffffffffffffffff168560ff16145b8015611e0b5750611e0481612810565b1515841515145b611e575760405162461bcd60e51b815260206004820152601b60248201527f7472616e73666572546573743a20636173742038206661696c6564000000000060448201526064016101ab565b611e6e8860c0015189602001518960000151612e91565b91945092509050611e7e83612cd9565b67ffffffffffffffff168660ff16148015611ead5750611e9d82612cd9565b67ffffffffffffffff168560ff16145b8015611ec45750611ebd81612810565b1515841515145b611f105760405162461bcd60e51b815260206004820152601b60248201527f7472616e73666572546573743a20636173742038206661696c6564000000000060448201526064016101ab565b611f2788604001518960e001518960000151612ead565b91945092509050611f3783612cd9565b67ffffffffffffffff168660ff16148015611f665750611f5682612cd9565b67ffffffffffffffff168560ff16145b8015611f7d5750611f7681612810565b1515841515145b611fc95760405162461bcd60e51b815260206004820152601b60248201527f7472616e73666572546573743a20636173742038206661696c6564000000000060448201526064016101ab565b611fe08860c0015189606001518960000151612eca565b91945092509050611ff083612cd9565b67ffffffffffffffff168660ff1614801561201f575061200f82612cd9565b67ffffffffffffffff168560ff16145b8015612036575061202f81612810565b1515841515145b6120825760405162461bcd60e51b815260206004820152601b60248201527f7472616e73666572546573743a20636173742038206661696c6564000000000060448201526064016101ab565b61209988608001518960e001518960000151612ee7565b919450925090506120a983612cd9565b67ffffffffffffffff168660ff161480156120d857506120c882612cd9565b67ffffffffffffffff168560ff16145b80156120ef57506120e881612810565b1515841515145b61213b5760405162461bcd60e51b815260206004820152601b60248201527f7472616e73666572546573743a20636173742038206661696c6564000000000060448201526064016101ab565b6121528860c001518960a001518960000151612f04565b9194509250905061216283612cd9565b67ffffffffffffffff168660ff16148015612191575061218182612cd9565b67ffffffffffffffff168560ff16145b80156121a857506121a181612810565b1515841515145b6121f45760405162461bcd60e51b815260206004820152601b60248201527f7472616e73666572546573743a20636173742038206661696c6564000000000060448201526064016101ab565b61220b8860c001518960e001518960200151612f21565b9194509250905061221b83612cd9565b67ffffffffffffffff168660ff1614801561224a575061223a82612cd9565b67ffffffffffffffff168560ff16145b8015612261575061225a81612810565b1515841515145b6122ad5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b6122c488600001518960e001518960200151612f3d565b919450925090506122d483612cd9565b67ffffffffffffffff168660ff1614801561230357506122f382612cd9565b67ffffffffffffffff168560ff16145b801561231a575061231381612810565b1515841515145b6123665760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b61237d8860c0015189602001518960200151612f5a565b9194509250905061238d83612cd9565b67ffffffffffffffff168660ff161480156123bc57506123ac82612cd9565b67ffffffffffffffff168560ff16145b80156123d357506123cc81612810565b1515841515145b61241f5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b61243688604001518960e001518960200151612f77565b9194509250905061244683612cd9565b67ffffffffffffffff168660ff16148015612475575061246582612cd9565b67ffffffffffffffff168560ff16145b801561248c575061248581612810565b1515841515145b6124d85760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b6124ef8860c0015189606001518960200151612f93565b919450925090506124ff83612cd9565b67ffffffffffffffff168660ff1614801561252e575061251e82612cd9565b67ffffffffffffffff168560ff16145b8015612545575061253e81612810565b1515841515145b6125915760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b6125a888608001518960e001518960200151612faf565b919450925090506125b883612cd9565b67ffffffffffffffff168660ff161480156125e757506125d782612cd9565b67ffffffffffffffff168560ff16145b80156125fe57506125f781612810565b1515841515145b61264a5760405162461bcd60e51b815260206004820152601c60248201527f7472616e73666572546573743a2063617374203136206661696c65640000000060448201526064016101ab565b6126618860c001518960a001518960200151612fcc565b9194509250905061267183612cd9565b67ffffffffffffffff168660ff16148015611263575061269082612cd9565b67ffffffffffffffff168560ff1614801561127a575061127381612810565b6000808080808060646356c72d286126ca6003808086612fe5565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b81168252919091166004820152602481018c9052604481018b9052606481018a90526084016060604051808303816000875af1158015612737573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061275b9190613285565b919b909a509098509650505050505050565b60006064630cfed56160035b60f81b846040518363ffffffff1660e01b81526004016127c79291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af11580156127e6573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061280a91906132e2565b92915050565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015612874573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061289891906132e2565b15159392505050565b6000808080808060646356c72d286126ca600160038086612fe5565b6000808080808060646356c72d286126ca600360018186612fe5565b6000808080808060646356c72d286126ca600260038086612fe5565b6000808080808060646356c72d286126ca600360028186612fe5565b6000808080808060646356c72d286126ca600380600186612fe5565b6000808080808060646356c72d286126ca600160038186612fe5565b6000808080808060646356c72d286126ca600360018086612fe5565b6000808080808060646356c72d286126ca60026003600186612fe5565b6000808080808060646356c72d286126ca60036002600186612fe5565b6000808080808060646356c72d286126ca600380600286612fe5565b6000808080808060646356c72d286126ca60016003600286612fe5565b6000808080808060646356c72d286126ca60036001600286612fe5565b6000808080808060646356c72d286126ca600260038186612fe5565b6000808080808060646356c72d286126ca600360028086612fe5565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b60906044016127c7565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b60906044016127c7565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b60906044016127c7565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b60906044016127c7565b6000808080808060646356c72d286126ca6001808086612fe5565b60006064630cfed5616001612779565b6000808080808060646356c72d286126ca600280600186612fe5565b60006064630cfed5616002612779565b6000808080808060646356c72d286126ca600160028186612fe5565b6000808080808060646356c72d286126ca600260018086612fe5565b6000808080808060646356c72d286126ca6002808086612fe5565b6000808080808060646356c72d286126ca600160028086612fe5565b6000808080808060646356c72d286126ca600260018186612fe5565b6000808080808060646356c72d286126ca6004808086612fe5565b60006064630cfed5616004612779565b6000808080808060646356c72d286126ca600160048086612fe5565b6000808080808060646356c72d286126ca600460018186612fe5565b6000808080808060646356c72d286126ca600260048086612fe5565b6000808080808060646356c72d286126ca600460028186612fe5565b6000808080808060646356c72d286126ca600360048086612fe5565b6000808080808060646356c72d286126ca600460038186612fe5565b6000808080808060646356c72d286126ca600480600386612fe5565b6000808080808060646356c72d286126ca60016004600386612fe5565b6000808080808060646356c72d286126ca60046001600386612fe5565b6000808080808060646356c72d286126ca60026004600386612fe5565b6000808080808060646356c72d286126ca60046002600386612fe5565b6000808080808060646356c72d286126ca600360048186612fe5565b6000808080808060646356c72d286126ca600460038086612fe5565b6000808080808060646356c72d286126ca600480600186612fe5565b6000808080808060646356c72d286126ca600160048186612fe5565b6000808080808060646356c72d286126ca600460018086612fe5565b6000808080808060646356c72d286126ca60026004600186612fe5565b6000808080808060646356c72d286126ca60046002600186612fe5565b6000808080808060646356c72d286126ca60036004600186612fe5565b6000808080808060646356c72d286126ca60046003600186612fe5565b6000808080808060646356c72d286126ca600480600286612fe5565b6000808080808060646356c72d286126ca60016004600286612fe5565b6000808080808060646356c72d286126ca60046001600286612fe5565b6000808080808060646356c72d286126ca600260048186612fe5565b6000808080808060646356c72d286126ca600460028086612fe5565b6000808080808060646356c72d286126ca60036004600286612fe5565b6000808080808060646356c72d286126ca600460036002865b6000816002811115612ff957612ff96132b3565b60ff166008846004811115613010576130106132b3565b61ffff16901b61ffff16601086600481111561302e5761302e6132b3565b62ffffff16901b62ffffff16601888600481111561304e5761304e6132b3565b63ffffffff16901b17171760e01b95945050505050565b604051610100810167ffffffffffffffff811182821017156130b0577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b803560ff811681146130c757600080fd5b919050565b600060a082840312156130de57600080fd5b60405160a0810181811067ffffffffffffffff82111715613128577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b80604052508091508235815260208301356020820152604083013560408201526060830135606082015261315e608084016130b6565b60808201525092915050565b803580151581146130c757600080fd5b600080600080600085870361020081121561319457600080fd5b610100808212156131a457600080fd5b6131ac613065565b9150873582526020880135602083015260408801356040830152606088013560608301526080880135608083015260a088013560a083015260c088013560c083015260e088013560e083015281965061320789828a016130cc565b955050506132186101a087016130b6565b92506132276101c087016130b6565b91506132366101e0870161316a565b90509295509295909350565b60008060006060848603121561325757600080fd5b613260846130b6565b925061326e602085016130b6565b915061327c604085016130b6565b90509250925092565b60008060006060848603121561329a57600080fd5b8351925060208401519150604084015190509250925092565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b6000602082840312156132f457600080fd5b505191905056fea164736f6c6343000813000a";

type TransferTestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: TransferTestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class TransferTestsContract__factory extends ContractFactory {
  constructor(...args: TransferTestsContractConstructorParams) {
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
      TransferTestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): TransferTestsContract__factory {
    return super.connect(runner) as TransferTestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TransferTestsContractInterface {
    return new Interface(_abi) as TransferTestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): TransferTestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as TransferTestsContract;
  }
}
