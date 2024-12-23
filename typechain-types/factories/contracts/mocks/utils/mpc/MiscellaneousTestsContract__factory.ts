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
  MiscellaneousTestsContract,
  MiscellaneousTestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/MiscellaneousTestsContract";

const _abi = [
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtUint16",
            name: "res16_16",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "res8_16",
            type: "uint256",
          },
          {
            internalType: "gtUint16",
            name: "res16_8",
            type: "uint256",
          },
        ],
        internalType: "struct MiscellaneousTestsContract.Check16",
        name: "check16",
        type: "tuple",
      },
    ],
    name: "decryptAndCompareResults16",
    outputs: [
      {
        internalType: "uint16",
        name: "",
        type: "uint16",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtUint32",
            name: "res32_32",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "res8_32",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "res32_8",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "res16_32",
            type: "uint256",
          },
          {
            internalType: "gtUint32",
            name: "res32_16",
            type: "uint256",
          },
        ],
        internalType: "struct MiscellaneousTestsContract.Check32",
        name: "check32",
        type: "tuple",
      },
    ],
    name: "decryptAndCompareResults32",
    outputs: [
      {
        internalType: "uint32",
        name: "",
        type: "uint32",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtUint64",
            name: "res64_64",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "res8_64",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "res64_8",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "res16_64",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "res64_16",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "res32_64",
            type: "uint256",
          },
          {
            internalType: "gtUint64",
            name: "res64_32",
            type: "uint256",
          },
        ],
        internalType: "struct MiscellaneousTestsContract.Check64",
        name: "check64",
        type: "tuple",
      },
    ],
    name: "decryptAndCompareResults64",
    outputs: [
      {
        internalType: "uint64",
        name: "",
        type: "uint64",
      },
    ],
    stateMutability: "nonpayable",
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
    ],
    name: "divTest",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "getBoolResult",
    outputs: [
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
    inputs: [],
    name: "getDivResult",
    outputs: [
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
    inputs: [],
    name: "getMuxResult",
    outputs: [
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
    inputs: [],
    name: "getRemResult",
    outputs: [
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
        internalType: "bool",
        name: "selectionBit",
        type: "bool",
      },
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
    ],
    name: "muxTest",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bool",
        name: "a",
        type: "bool",
      },
    ],
    name: "notTest",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
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
    ],
    name: "remTest",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
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
        internalType: "struct MiscellaneousTestsContract.AllGTCastingValues",
        name: "castingValues",
        type: "tuple",
      },
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
    ],
    name: "setPublicValues",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b506131bc806100206000396000f3fe608060405234801561001057600080fd5b50600436106100d45760003560e01c806392bba35611610081578063acb381691161005b578063acb38169146101c7578063d74e55e7146101ef578063ebb571fd1461020057600080fd5b806392bba3561461018f578063a103e4c0146101a1578063a609476a146101b457600080fd5b8063690ec3d9116100b2578063690ec3d91461012d5780636c74e7141461015057806380f937bc1461016357600080fd5b80632684f863146100d95780632e544aa0146100f75780632e5dda1e1461011d575b600080fd5b60005460ff165b60405160ff90911681526020015b60405180910390f35b61010a610105366004612e28565b610215565b60405161ffff90911681526020016100ee565b600054610100900460ff166100e0565b61014061013b366004612ec0565b610300565b60405190151581526020016100ee565b6100e061015e366004612eec565b610367565b610176610171366004612f2f565b610a65565b60405167ffffffffffffffff90911681526020016100ee565b6000546301000000900460ff16610140565b6100e06101af366004612fda565b610c08565b6100e06101c2366004612fda565b6112c8565b6101da6101d536600461300d565b611975565b60405163ffffffff90911681526020016100ee565b60005462010000900460ff166100e0565b61021361020e3660046130a4565b611aa2565b005b6000806102258360000151611b29565b90506102348360200151611b29565b61ffff168161ffff1614801561025d57506102528360400151611b29565b61ffff168161ffff16145b6102fa5760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4015b60405180910390fd5b92915050565b60008061030c83611bc6565b9050600061031982611c6b565b905061032481611c7a565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffffff1663010000009215158302179081905560ff91900416949350505050565b60006103b160405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b6103d560405180606001604052806000815260200160008152602001600081525090565b6104076040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6104476040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610452848888611aa2565b600061045d89611bc6565b9050600061047c6104778388600001518960200151611d0b565b611dd9565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff166201000060ff841602179055604087015160608801519192506104c791849190611de9565b8552855160608701516104db918491611dfe565b8560200181815250506104f78287604001518860200151611e14565b6040860152600061050786610215565b90508160ff168161ffff161461055f5760405162461bcd60e51b815260206004820152601760248201527f6d7578546573743a2063617374203136206661696c656400000000000000000060448201526064016102f1565b6105728388608001518960a00151611e2a565b8552865160a0880151610586918591611e3f565b8560200181815250506105a28388608001518960200151611e55565b8560400181815250506105be8388604001518960a00151611e6b565b8560600181815250506105da8388608001518960600151611e81565b608086015260006105ea86611975565b90508063ffffffff168360ff16146106445760405162461bcd60e51b815260206004820152601760248201527f6d7578546573743a2063617374203332206661696c656400000000000000000060448201526064016102f1565b610657848960c001518a60e00151611e97565b8552875160e089015161066b918691611eac565b856020018181525050610687848960c001518a60200151611ec2565b8560400181815250506106a38489604001518a60e00151611ed8565b8560600181815250506106bf848960c001518a60600151611eee565b8560800181815250506106db8489608001518a60e00151611f04565b8560a00181815250506106f7848960c001518a60a00151611f1a565b60c0860152600061070786610a65565b90508067ffffffffffffffff168460ff16146107655760405162461bcd60e51b815260206004820152601760248201527f6d7578546573743a2063617374203634206661696c656400000000000000000060448201526064016102f1565b610777610477868e8c60200151611f30565b60ff168460ff161480156107a15750610798610477868b600001518e611fb9565b60ff168460ff16145b6108135760405162461bcd60e51b815260206004820152602760248201527f6d7578546573743a2074657374203820626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016102f1565b61082d610828868e60ff168c60600151612043565b611b29565b61ffff168460ff1614801561085c5750610852610828868b604001518e60ff166120ce565b61ffff168460ff16145b6108ce5760405162461bcd60e51b815260206004820152602860248201527f6d7578546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b6108e86108e3868e60ff168c60a00151612158565b6121e5565b63ffffffff168460ff1614801561091b575061090f6108e3868b608001518e60ff166121f5565b63ffffffff168460ff16145b61098d5760405162461bcd60e51b815260206004820152602860248201527f6d7578546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b6109a76109a2868e60ff168c60e00151612282565b612313565b67ffffffffffffffff168460ff161480156109e257506109d26109a2868b60c001518e60ff16612323565b67ffffffffffffffff168460ff16145b610a545760405162461bcd60e51b815260206004820152602860248201527f6d7578546573743a207465737420363420626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b50919b9a5050505050505050505050565b600080610a758360000151612313565b9050610a848360200151612313565b67ffffffffffffffff168167ffffffffffffffff16148015610ac55750610aae8360400151612313565b67ffffffffffffffff168167ffffffffffffffff16145b8015610af05750610ad98360800151612313565b67ffffffffffffffff168167ffffffffffffffff16145b8015610b1b5750610b048360600151612313565b67ffffffffffffffff168167ffffffffffffffff16145b8015610b465750610b2f8360c00151612313565b67ffffffffffffffff168167ffffffffffffffff16145b801561025d5750610b5a8360a00151612313565b67ffffffffffffffff168167ffffffffffffffff16146102fa5760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4016102f1565b6000610c5260405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610c7660405180606001604052806000815260200160008152602001600081525090565b610ca86040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b610ce86040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610cf3848888611aa2565b6000610d0a610477866000015187602001516123b4565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1661010060ff84160217905560408601516060870151919250610d519161244e565b845284516060860151610d649190612463565b846020018181525050610d7f85604001518660200151612479565b60408501526000610d8f85610215565b90508160ff168161ffff1614610de75760405162461bcd60e51b815260206004820152601760248201527f72656d546573743a2063617374203136206661696c656400000000000000000060448201526064016102f1565b610df986608001518760a0015161248f565b8452855160a0870151610e0c91906124a4565b846020018181525050610e27866080015187602001516124ba565b846040018181525050610e4286604001518760a001516124d0565b846060018181525050610e5d866080015187606001516124e6565b60808501526000610e6d85611975565b90508063ffffffff168360ff1614610ec75760405162461bcd60e51b815260206004820152601760248201527f72656d546573743a2063617374203332206661696c656400000000000000000060448201526064016102f1565b610ed98760c001518860e001516124fc565b8452865160e0880151610eec9190612511565b846020018181525050610f078760c001518860200151612527565b846040018181525050610f2287604001518860e0015161253d565b846060018181525050610f3d8760c001518860600151612553565b846080018181525050610f5887608001518860e00151612569565b8460a0018181525050610f738760c001518860a0015161257f565b60c08501526000610f8385610a65565b90508067ffffffffffffffff168460ff1614610fe15760405162461bcd60e51b815260206004820152601760248201527f72656d546573743a2063617374203634206661696c656400000000000000000060448201526064016102f1565b610ff26104778c8a60200151612595565b60ff168460ff1614801561101b575061101261047789600001518c612617565b60ff168460ff16145b61108d5760405162461bcd60e51b815260206004820152602760248201527f72656d546573743a2074657374203820626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016102f1565b6110a16108288c60ff168a6060015161269a565b61ffff168460ff161480156110cf57506110c561082889604001518c60ff1661271e565b61ffff168460ff16145b6111415760405162461bcd60e51b815260206004820152602860248201527f72656d546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b6111556108e38c60ff168a60a001516127a1565b63ffffffff168460ff16148015611187575061117b6108e389608001518c60ff16612827565b63ffffffff168460ff16145b6111f95760405162461bcd60e51b815260206004820152602860248201527f72656d546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b61120d6109a28c60ff168a60e001516128ad565b67ffffffffffffffff168460ff1614801561124757506112376109a28960c001518c60ff16612937565b67ffffffffffffffff168460ff16145b6112b95760405162461bcd60e51b815260206004820152602860248201527f72656d546573743a207465737420363420626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b50919998505050505050505050565b600061131260405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61133660405180606001604052806000815260200160008152602001600081525090565b6113686040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6113a86040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b6113b3848888611aa2565b60006113ca610477866000015187602001516129c1565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff83161790556040860151606087015191925061140d916129d6565b84528451606086015161142091906129eb565b84602001818152505061143b85604001518660200151612a01565b6040850152600061144b85610215565b90508160ff168161ffff16146114a35760405162461bcd60e51b815260206004820152601760248201527f646976546573743a2063617374203136206661696c656400000000000000000060448201526064016102f1565b6114b586608001518760a00151612a17565b8452855160a08701516114c89190612a2c565b8460200181815250506114e386608001518760200151612a42565b8460400181815250506114fe86604001518760a00151612a58565b84606001818152505061151986608001518760600151612a6e565b6080850152600061152985611975565b90508063ffffffff168360ff16146115835760405162461bcd60e51b815260206004820152601760248201527f646976546573743a2063617374203332206661696c656400000000000000000060448201526064016102f1565b6115958760c001518860e00151612a84565b8452865160e08801516115a89190612a99565b8460200181815250506115c38760c001518860200151612aaf565b8460400181815250506115de87604001518860e00151612ac5565b8460600181815250506115f98760c001518860600151612adb565b84608001818152505061161487608001518860e00151612af1565b8460a001818152505061162f8760c001518860a00151612b07565b60c0850152600061163f85610a65565b90508067ffffffffffffffff168460ff161461169d5760405162461bcd60e51b815260206004820152601760248201527f646976546573743a2063617374203634206661696c656400000000000000000060448201526064016102f1565b6116ae6104778c8a60200151612b1d565b60ff168460ff161480156116d757506116ce61047789600001518c612b32565b60ff168460ff16145b6117495760405162461bcd60e51b815260206004820152602760248201527f646976546573743a2074657374203820626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016102f1565b61175d6108288c60ff168a60600151612b48565b61ffff168460ff1614801561178b575061178161082889604001518c60ff16612b5e565b61ffff168460ff16145b6117fd5760405162461bcd60e51b815260206004820152602860248201527f646976546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b6118116108e38c60ff168a60a00151612b73565b63ffffffff168460ff1614801561184357506118376108e389608001518c60ff16612b89565b63ffffffff168460ff16145b6118b55760405162461bcd60e51b815260206004820152602860248201527f646976546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b6118c96109a28c60ff168a60e00151612b9f565b67ffffffffffffffff168460ff1614801561190357506118f36109a28960c001518c60ff16612bb5565b67ffffffffffffffff168460ff16145b6112b95760405162461bcd60e51b815260206004820152602860248201527f646976546573743a207465737420363420626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016102f1565b60008061198583600001516121e5565b905061199483602001516121e5565b63ffffffff168163ffffffff161480156119c557506119b683604001516121e5565b63ffffffff168163ffffffff16145b80156119e857506119d983608001516121e5565b63ffffffff168163ffffffff16145b801561025d57506119fc83606001516121e5565b63ffffffff168163ffffffff16146102fa5760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4016102f1565b611aab82612bcb565b8352611ab681612bcb565b6020840152611ac760ff8316612c34565b6040840152611ad860ff8216612c34565b6060840152611ae960ff8316612c9e565b6080840152611afa60ff8216612c9e565b60a0840152611b0b60ff8316612d0a565b60c0840152611b1c60ff8216612d0a565b60e0909301929092525050565b60006064630cfed56160025b60f81b846040518363ffffffff1660e01b8152600401611b839291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af1158015611ba2573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102fa919061316d565b60008082611bd5576000611bd8565b60015b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081526000600482015260ff9190911660248201819052915060649063d9b60b60906044015b6020604051808303816000875af1158015611c40573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611c64919061316d565b9392505050565b60006064631d79e49a82611b35565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015611cde573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611d02919061316d565b15159392505050565b600060646320cc408d611d2060018085612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810187905260448101869052606481018590526084015b6020604051808303816000875af1158015611dad573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611dd1919061316d565b949350505050565b60006064630cfed5616001611b35565b600060646320cc408d611d2060028085612d7a565b600060646320cc408d611d206001600285612d7a565b600060646320cc408d611d206002600185612d7a565b600060646320cc408d611d2060038085612d7a565b600060646320cc408d611d206001600385612d7a565b600060646320cc408d611d206003600185612d7a565b600060646320cc408d611d206002600385612d7a565b600060646320cc408d611d206003600285612d7a565b600060646320cc408d611d2060048085612d7a565b600060646320cc408d611d206001600485612d7a565b600060646320cc408d611d206004600185612d7a565b600060646320cc408d611d206002600485612d7a565b600060646320cc408d611d206004600285612d7a565b600060646320cc408d611d206003600485612d7a565b600060646320cc408d611d206004600385612d7a565b600060646320cc408d611f4560018080612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810187905260ff8616604482015260648101859052608401611d8e565b600060646320cc408d611fcf6001806002612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff00000000000000000000000000000000000000000000000000000000009091166004820152602481018790526044810186905260ff85166064820152608401611d8e565b600060646320cc408d6120596002806001612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810187905261ffff8616604482015260648101859052608401611d8e565b600060646320cc408d6120e360028080612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff00000000000000000000000000000000000000000000000000000000009091166004820152602481018790526044810186905261ffff85166064820152608401611d8e565b600060646320cc408d61216e6003806001612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810187905263ffffffff8616604482015260648101859052608401611d8e565b60006064630cfed5616003611b35565b600060646320cc408d61220b6003806002612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff00000000000000000000000000000000000000000000000000000000009091166004820152602481018790526044810186905263ffffffff85166064820152608401611d8e565b600060646320cc408d6122986004806001612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810187905267ffffffffffffffff8616604482015260648101859052608401611d8e565b60006064630cfed5616004611b35565b600060646320cc408d6123396004806002612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff00000000000000000000000000000000000000000000000000000000009091166004820152602481018790526044810186905267ffffffffffffffff85166064820152608401611d8e565b600060646386e3b7b96123c960018085612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260248101869052604481018590526064016020604051808303816000875af1158015611c40573d6000803e3d6000fd5b600060646386e3b7b96123c960028085612d7a565b600060646386e3b7b96123c96001600285612d7a565b600060646386e3b7b96123c96002600185612d7a565b600060646386e3b7b96123c960038085612d7a565b600060646386e3b7b96123c96001600385612d7a565b600060646386e3b7b96123c96003600185612d7a565b600060646386e3b7b96123c96002600385612d7a565b600060646386e3b7b96123c96003600285612d7a565b600060646386e3b7b96123c960048085612d7a565b600060646386e3b7b96123c96001600485612d7a565b600060646386e3b7b96123c96004600185612d7a565b600060646386e3b7b96123c96002600485612d7a565b600060646386e3b7b96123c96004600285612d7a565b600060646386e3b7b96123c96003600485612d7a565b600060646386e3b7b96123c96004600385612d7a565b600060646386e3b7b96125aa60018080612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260ff8616602482015260448101859052606401611c21565b600060646386e3b7b961262d6001806002612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905260ff85166044820152606401611c21565b600060646386e3b7b96126b06002806001612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015261ffff8616602482015260448101859052606401611c21565b600060646386e3b7b961273360028080612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905261ffff85166044820152606401611c21565b600060646386e3b7b96127b76003806001612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015263ffffffff8616602482015260448101859052606401611c21565b600060646386e3b7b961283d6003806002612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905263ffffffff85166044820152606401611c21565b600060646386e3b7b96128c36004806001612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015267ffffffffffffffff8616602482015260448101859052606401611c21565b600060646386e3b7b961294d6004806002612d7a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905267ffffffffffffffff85166044820152606401611c21565b60006064634e9ba4b56123c960018085612d7a565b60006064634e9ba4b56123c960028085612d7a565b60006064634e9ba4b56123c96001600285612d7a565b60006064634e9ba4b56123c96002600185612d7a565b60006064634e9ba4b56123c960038085612d7a565b60006064634e9ba4b56123c96001600385612d7a565b60006064634e9ba4b56123c96003600185612d7a565b60006064634e9ba4b56123c96002600385612d7a565b60006064634e9ba4b56123c96003600285612d7a565b60006064634e9ba4b56123c960048085612d7a565b60006064634e9ba4b56123c96001600485612d7a565b60006064634e9ba4b56123c96004600185612d7a565b60006064634e9ba4b56123c96002600485612d7a565b60006064634e9ba4b56123c96004600285612d7a565b60006064634e9ba4b56123c96003600485612d7a565b60006064634e9ba4b56123c96004600385612d7a565b60006064634e9ba4b56125aa60018080612d7a565b60006064634e9ba4b561262d6001806002612d7a565b60006064634e9ba4b56126b06002806001612d7a565b60006064634e9ba4b561273360028080612d7a565b60006064634e9ba4b56127b76003806001612d7a565b60006064634e9ba4b561283d6003806002612d7a565b60006064634e9ba4b56128c36004806001612d7a565b60006064634e9ba4b561294d6004806002612d7a565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b6090604401611b83565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401611b83565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401611b83565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401611b83565b6000816002811115612d8e57612d8e61313e565b60ff166008846004811115612da557612da561313e565b61ffff16901b61ffff166010866004811115612dc357612dc361313e565b62ffffff16901b171760e81b949350505050565b604051610100810167ffffffffffffffff81118282101715612e22577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b600060608284031215612e3a57600080fd5b6040516060810181811067ffffffffffffffff82111715612e84577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b80604052508235815260208301356020820152604083013560408201528091505092915050565b80358015158114612ebb57600080fd5b919050565b600060208284031215612ed257600080fd5b611c6482612eab565b803560ff81168114612ebb57600080fd5b600080600060608486031215612f0157600080fd5b612f0a84612eab565b9250612f1860208501612edb565b9150612f2660408501612edb565b90509250925092565b600060e08284031215612f4157600080fd5b60405160e0810181811067ffffffffffffffff82111715612f8b577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250823581526020830135602082015260408301356040820152606083013560608201526080830135608082015260a083013560a082015260c083013560c08201528091505092915050565b60008060408385031215612fed57600080fd5b612ff683612edb565b915061300460208401612edb565b90509250929050565b600060a0828403121561301f57600080fd5b60405160a0810181811067ffffffffffffffff82111715613069577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b806040525082358152602083013560208201526040830135604082015260608301356060820152608083013560808201528091505092915050565b60008060008385036101408112156130bb57600080fd5b610100808212156130cb57600080fd5b6130d3612dd7565b9150853582526020860135602083015260408601356040830152606086013560608301526080860135608083015260a086013560a083015260c086013560c083015260e086013560e083015281945061312d818701612edb565b93505050612f266101208501612edb565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60006020828403121561317f57600080fd5b505191905056fea2646970667358221220a0a0e3233a4b2b0afb7623ddac8749ad01259aa9078c9406ef84f6630693e21264736f6c63430008130033";

type MiscellaneousTestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: MiscellaneousTestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class MiscellaneousTestsContract__factory extends ContractFactory {
  constructor(...args: MiscellaneousTestsContractConstructorParams) {
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
      MiscellaneousTestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): MiscellaneousTestsContract__factory {
    return super.connect(runner) as MiscellaneousTestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): MiscellaneousTestsContractInterface {
    return new Interface(_abi) as MiscellaneousTestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): MiscellaneousTestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as MiscellaneousTestsContract;
  }
}
