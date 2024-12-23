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
  BitwiseTestsContract,
  BitwiseTestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/BitwiseTestsContract";

const _abi = [
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
    name: "andTest",
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
        internalType: "struct BitwiseTestsContract.Check16",
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
        internalType: "struct BitwiseTestsContract.Check32",
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
        internalType: "struct BitwiseTestsContract.Check64",
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
    inputs: [],
    name: "getAndResult",
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
    name: "getOrResult",
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
    name: "getXorResult",
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
    name: "orTest",
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
            internalType: "gtBool",
            name: "aBool_s",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "bBool_s",
            type: "uint256",
          },
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
        internalType: "struct BitwiseTestsContract.AllGTCastingValues",
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
    name: "xorTest",
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
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b50612ccb806100206000396000f3fe608060405234801561001057600080fd5b50600436106100be5760003560e01c80636b04608f11610076578063991e65321161005b578063991e653214610180578063acb3816914610193578063f3367ccb146101bb57600080fd5b80636b04608f1461013f57806380f937bc1461015457600080fd5b80632e544aa0116100a75780632e544aa0146100fd578063535e40d114610123578063538301e81461012e57600080fd5b80631e977321146100c357806325a3b580146100ed575b600080fd5b6100d66100d1366004612949565b6101ce565b60405160ff90911681526020015b60405180910390f35b600054610100900460ff166100d6565b61011061010b3660046129cd565b6108d1565b60405161ffff90911681526020016100e4565b60005460ff166100d6565b60005462010000900460ff166100d6565b61015261014d366004612a50565b6109b7565b005b610167610162366004612b0b565b610a6c565b60405167ffffffffffffffff90911681526020016100e4565b6100d661018e366004612949565b610c0f565b6101a66101a1366004612bb6565b6112e6565b60405163ffffffff90911681526020016100e4565b6100d66101c9366004612949565b611413565b6000610226604051806101400160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61024a60405180606001604052806000815260200160008152602001600081525090565b61027c6040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6102bc6040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b6102c78488886109b7565b6102e16102dc85600001518660200151611ae5565b611baa565b5060006102fe6102f986604001518760600151611c3b565b611c50565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1661010060ff841602179055608086015160a087015191925061034591611ced565b8452604085015160a086015161035b9190611d02565b6020850152608085015160608601516103749190611d18565b60408501526000610384856108d1565b90508160ff168161ffff16146103e15760405162461bcd60e51b815260206004820152601660248201527f6f72546573743a2063617374203136206661696c65640000000000000000000060448201526064015b60405180910390fd5b6103f38660c001518760e00151611d2e565b8452604086015160e08701516104099190611d43565b602085015260c086015160608701516104229190611d59565b6040850152608086015160e087015161043b9190611d6f565b606085015260c086015160a08701516104549190611d85565b60808501526000610464856112e6565b90508063ffffffff168360ff16146104be5760405162461bcd60e51b815260206004820152601660248201527f6f72546573743a2063617374203332206661696c65640000000000000000000060448201526064016103d8565b6104d2876101000151886101200151611d9b565b845260408701516101208801516104e99190611db0565b602085015261010087015160608801516105039190611dc6565b6040850152608087015161012088015161051d9190611ddc565b606085015261010087015160a08801516105379190611df2565b608085015260c08701516101208801516105519190611e08565b60a085015261010087015160e088015161056b9190611e1e565b60c0850152600061057b85610a6c565b90508067ffffffffffffffff168460ff16146105d95760405162461bcd60e51b815260206004820152601660248201527f6f72546573743a2063617374203634206661696c65640000000000000000000060448201526064016103d8565b6105ea6102f98c8a60600151611e34565b60ff168460ff16148015610613575061060a6102f989604001518c611eb6565b60ff168460ff16145b6106855760405162461bcd60e51b815260206004820152602660248201527f6f72546573743a2074657374203820626974732077697468207363616c61722060448201527f6661696c6564000000000000000000000000000000000000000000000000000060648201526084016103d8565b61069e6106998c60ff168a60a00151611f39565b611fbd565b61ffff168460ff161480156106cc57506106c261069989608001518c60ff16611fcd565b61ffff168460ff16145b61073e5760405162461bcd60e51b815260206004820152602760248201527f6f72546573743a207465737420313620626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016103d8565b6107576107528c60ff168a60e00151612050565b6120d6565b63ffffffff168460ff16148015610789575061077d6107528960c001518c60ff166120e6565b63ffffffff168460ff16145b6107fb5760405162461bcd60e51b815260206004820152602760248201527f6f72546573743a207465737420333220626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016103d8565b6108156108108c60ff168a610120015161216c565b6121f6565b67ffffffffffffffff168460ff1614801561085057506108406108108961010001518c60ff16612206565b67ffffffffffffffff168460ff16145b6108c25760405162461bcd60e51b815260206004820152602760248201527f6f72546573743a207465737420363420626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016103d8565b50919998505050505050505050565b6000806108e18360000151611fbd565b90506108f08360200151611fbd565b61ffff168161ffff16148015610919575061090e8360400151611fbd565b61ffff168161ffff16145b6109b15760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4016103d8565b92915050565b6109c88160ff168360ff1611612290565b83526109db60ff80841690831611612290565b60208401526109e9826122ef565b60408401526109f7816122ef565b6060840152610a0860ff8316612358565b6080840152610a1960ff8216612358565b60a0840152610a2a60ff83166123c2565b60c0840152610a3b60ff82166123c2565b60e0840152610a4c60ff831661242e565b610100840152610a5e60ff821661242e565b610120909301929092525050565b600080610a7c83600001516121f6565b9050610a8b83602001516121f6565b67ffffffffffffffff168167ffffffffffffffff16148015610acc5750610ab583604001516121f6565b67ffffffffffffffff168167ffffffffffffffff16145b8015610af75750610ae083608001516121f6565b67ffffffffffffffff168167ffffffffffffffff16145b8015610b225750610b0b83606001516121f6565b67ffffffffffffffff168167ffffffffffffffff16145b8015610b4d5750610b368360c001516121f6565b67ffffffffffffffff168167ffffffffffffffff16145b80156109195750610b618360a001516121f6565b67ffffffffffffffff168167ffffffffffffffff16146109b15760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4016103d8565b6000610c67604051806101400160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610c8b60405180606001604052806000815260200160008152602001600081525090565b610cbd6040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b610cfd6040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610d088488886109b7565b610d1d6102dc8560000151866020015161249e565b506000610d356102f9866040015187606001516124b2565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff166201000060ff841602179055608086015160a0870151919250610d7d916124c7565b8452604085015160a0860151610d9391906124dc565b602085015260808501516060860151610dac91906124f2565b60408501526000610dbc856108d1565b90508160ff168161ffff1614610e145760405162461bcd60e51b815260206004820152601760248201527f786f72546573743a2063617374203136206661696c656400000000000000000060448201526064016103d8565b610e268660c001518760e00151612508565b8452604086015160e0870151610e3c919061251d565b602085015260c08601516060870151610e559190612533565b6040850152608086015160e0870151610e6e9190612549565b606085015260c086015160a0870151610e87919061255f565b60808501526000610e97856112e6565b90508063ffffffff168360ff1614610ef15760405162461bcd60e51b815260206004820152601760248201527f786f72546573743a2063617374203332206661696c656400000000000000000060448201526064016103d8565b610f05876101000151886101200151612575565b84526040870151610120880151610f1c919061258a565b60208501526101008701516060880151610f3691906125a0565b60408501526080870151610120880151610f5091906125b6565b606085015261010087015160a0880151610f6a91906125cc565b608085015260c0870151610120880151610f8491906125e2565b60a085015261010087015160e0880151610f9e91906125f8565b60c08501526000610fae85610a6c565b90508067ffffffffffffffff168460ff161461100c5760405162461bcd60e51b815260206004820152601760248201527f786f72546573743a2063617374203634206661696c656400000000000000000060448201526064016103d8565b61101d6102f98c8a6060015161260e565b60ff168460ff16148015611046575061103d6102f989604001518c612623565b60ff168460ff16145b6110b85760405162461bcd60e51b815260206004820152602760248201527f786f72546573743a2074657374203820626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016103d8565b6110cc6106998c60ff168a60a00151612639565b61ffff168460ff161480156110fa57506110f061069989608001518c60ff1661264f565b61ffff168460ff16145b61116c5760405162461bcd60e51b815260206004820152602860248201527f786f72546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016103d8565b6111806107528c60ff168a60e00151612664565b63ffffffff168460ff161480156111b257506111a66107528960c001518c60ff1661267a565b63ffffffff168460ff16145b6112245760405162461bcd60e51b815260206004820152602860248201527f786f72546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016103d8565b6112396108108c60ff168a6101200151612690565b67ffffffffffffffff168460ff1614801561127457506112646108108961010001518c60ff166126a6565b67ffffffffffffffff168460ff16145b6108c25760405162461bcd60e51b815260206004820152602860248201527f786f72546573743a207465737420363420626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016103d8565b6000806112f683600001516120d6565b905061130583602001516120d6565b63ffffffff168163ffffffff16148015611336575061132783604001516120d6565b63ffffffff168163ffffffff16145b8015611359575061134a83608001516120d6565b63ffffffff168163ffffffff16145b8015610919575061136d83606001516120d6565b63ffffffff168163ffffffff16146109b15760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4016103d8565b600061146b604051806101400160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61148f60405180606001604052806000815260200160008152602001600081525090565b6114c16040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6115016040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61150c8488886109b7565b6115216102dc856000015186602001516126bc565b5060006115396102f9866040015187606001516126d0565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff8316179055608086015160a087015191925061157c916126e5565b8452604085015160a086015161159291906126fa565b6020850152608085015160608601516115ab9190612710565b604085015260006115bb856108d1565b90508160ff168161ffff16146116135760405162461bcd60e51b815260206004820152601760248201527f616e64546573743a2063617374203136206661696c656400000000000000000060448201526064016103d8565b6116258660c001518760e00151612726565b8452604086015160e087015161163b919061273b565b602085015260c086015160608701516116549190612751565b6040850152608086015160e087015161166d9190612767565b606085015260c086015160a0870151611686919061277d565b60808501526000611696856112e6565b90508063ffffffff168360ff16146116f05760405162461bcd60e51b815260206004820152601760248201527f616e64546573743a2063617374203332206661696c656400000000000000000060448201526064016103d8565b611704876101000151886101200151612793565b8452604087015161012088015161171b91906127a8565b6020850152610100870151606088015161173591906127be565b6040850152608087015161012088015161174f91906127d4565b606085015261010087015160a088015161176991906127ea565b608085015260c08701516101208801516117839190612800565b60a085015261010087015160e088015161179d9190612816565b60c085015260006117ad85610a6c565b90508067ffffffffffffffff168460ff161461180b5760405162461bcd60e51b815260206004820152601760248201527f616e64546573743a2063617374203634206661696c656400000000000000000060448201526064016103d8565b61181c6102f98c8a6060015161282c565b60ff168460ff16148015611845575061183c6102f989604001518c612841565b60ff168460ff16145b6118b75760405162461bcd60e51b815260206004820152602760248201527f616e64546573743a2074657374203820626974732077697468207363616c617260448201527f206661696c65640000000000000000000000000000000000000000000000000060648201526084016103d8565b6118cb6106998c60ff168a60a00151612857565b61ffff168460ff161480156118f957506118ef61069989608001518c60ff1661286d565b61ffff168460ff16145b61196b5760405162461bcd60e51b815260206004820152602860248201527f616e64546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016103d8565b61197f6107528c60ff168a60e00151612882565b63ffffffff168460ff161480156119b157506119a56107528960c001518c60ff16612898565b63ffffffff168460ff16145b611a235760405162461bcd60e51b815260206004820152602860248201527f616e64546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016103d8565b611a386108108c60ff168a61012001516128ae565b67ffffffffffffffff168460ff16148015611a735750611a636108108961010001518c60ff166128c4565b67ffffffffffffffff168460ff16145b6108c25760405162461bcd60e51b815260206004820152602860248201527f616e64546573743a207465737420363420626974732077697468207363616c6160448201527f72206661696c656400000000000000000000000000000000000000000000000060648201526084016103d8565b6000606463fb7da35f611af98380806128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260248101869052604481018590526064015b6020604051808303816000875af1158015611b7f573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611ba39190612c4d565b9392505050565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015611c0e573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611c329190612c4d565b15159392505050565b6000606463fb7da35f611af9600180856128d6565b60006064630cfed56160015b60f81b846040518363ffffffff1660e01b8152600401611caa9291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af1158015611cc9573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906109b19190612c4d565b6000606463fb7da35f611af9600280856128d6565b6000606463fb7da35f611af960016002856128d6565b6000606463fb7da35f611af960026001856128d6565b6000606463fb7da35f611af9600380856128d6565b6000606463fb7da35f611af960016003856128d6565b6000606463fb7da35f611af960036001856128d6565b6000606463fb7da35f611af960026003856128d6565b6000606463fb7da35f611af960036002856128d6565b6000606463fb7da35f611af9600480856128d6565b6000606463fb7da35f611af960016004856128d6565b6000606463fb7da35f611af960046001856128d6565b6000606463fb7da35f611af960026004856128d6565b6000606463fb7da35f611af960046002856128d6565b6000606463fb7da35f611af960036004856128d6565b6000606463fb7da35f611af960046003856128d6565b6000606463fb7da35f611e49600180806128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260ff8616602482015260448101859052606401611b60565b6000606463fb7da35f611ecc60018060026128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905260ff85166044820152606401611b60565b6000606463fb7da35f611f4f60028060016128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015261ffff8616602482015260448101859052606401611b60565b60006064630cfed5616002611c5c565b6000606463fb7da35f611fe2600280806128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905261ffff85166044820152606401611b60565b6000606463fb7da35f61206660038060016128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015263ffffffff8616602482015260448101859052606401611b60565b60006064630cfed5616003611c5c565b6000606463fb7da35f6120fc60038060026128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905263ffffffff85166044820152606401611b60565b6000606463fb7da35f61218260048060016128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015267ffffffffffffffff8616602482015260448101859052606401611b60565b60006064630cfed5616004611c5c565b6000606463fb7da35f61221c60048060026128d6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905267ffffffffffffffff85166044820152606401611b60565b6000808261229f5760006122a2565b60015b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081526000600482015260ff9190911660248201819052915060649063d9b60b6090604401611b60565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b6090604401611caa565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401611caa565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401611caa565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401611caa565b60006064636f962e2c611af98380806128d6565b60006064636f962e2c611af9600180856128d6565b60006064636f962e2c611af9600280856128d6565b60006064636f962e2c611af960016002856128d6565b60006064636f962e2c611af960026001856128d6565b60006064636f962e2c611af9600380856128d6565b60006064636f962e2c611af960016003856128d6565b60006064636f962e2c611af960036001856128d6565b60006064636f962e2c611af960026003856128d6565b60006064636f962e2c611af960036002856128d6565b60006064636f962e2c611af9600480856128d6565b60006064636f962e2c611af960016004856128d6565b60006064636f962e2c611af960046001856128d6565b60006064636f962e2c611af960026004856128d6565b60006064636f962e2c611af960046002856128d6565b60006064636f962e2c611af960036004856128d6565b60006064636f962e2c611af960046003856128d6565b60006064636f962e2c611e49600180806128d6565b60006064636f962e2c611ecc60018060026128d6565b60006064636f962e2c611f4f60028060016128d6565b60006064636f962e2c611fe2600280806128d6565b60006064636f962e2c61206660038060016128d6565b60006064636f962e2c6120fc60038060026128d6565b60006064636f962e2c61218260048060016128d6565b60006064636f962e2c61221c60048060026128d6565b6000606463fe9c73d1611af98380806128d6565b6000606463fe9c73d1611af9600180856128d6565b6000606463fe9c73d1611af9600280856128d6565b6000606463fe9c73d1611af960016002856128d6565b6000606463fe9c73d1611af960026001856128d6565b6000606463fe9c73d1611af9600380856128d6565b6000606463fe9c73d1611af960016003856128d6565b6000606463fe9c73d1611af960036001856128d6565b6000606463fe9c73d1611af960026003856128d6565b6000606463fe9c73d1611af960036002856128d6565b6000606463fe9c73d1611af9600480856128d6565b6000606463fe9c73d1611af960016004856128d6565b6000606463fe9c73d1611af960046001856128d6565b6000606463fe9c73d1611af960026004856128d6565b6000606463fe9c73d1611af960046002856128d6565b6000606463fe9c73d1611af960036004856128d6565b6000606463fe9c73d1611af960046003856128d6565b6000606463fe9c73d1611e49600180806128d6565b6000606463fe9c73d1611ecc60018060026128d6565b6000606463fe9c73d1611f4f60028060016128d6565b6000606463fe9c73d1611fe2600280806128d6565b6000606463fe9c73d161206660038060016128d6565b6000606463fe9c73d16120fc60038060026128d6565b6000606463fe9c73d161218260048060016128d6565b6000606463fe9c73d161221c60048060025b60008160028111156128ea576128ea612c66565b60ff16600884600481111561290157612901612c66565b61ffff16901b61ffff16601086600481111561291f5761291f612c66565b62ffffff16901b171760e81b949350505050565b803560ff8116811461294457600080fd5b919050565b6000806040838503121561295c57600080fd5b61296583612933565b915061297360208401612933565b90509250929050565b604051610140810167ffffffffffffffff811182821017156129c7577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b6000606082840312156129df57600080fd5b6040516060810181811067ffffffffffffffff82111715612a29577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b80604052508235815260208301356020820152604083013560408201528091505092915050565b6000806000838503610180811215612a6757600080fd5b61014080821215612a7757600080fd5b612a7f61297c565b9150853582526020860135602083015260408601356040830152606086013560608301526080860135608083015260a086013560a083015260c086013560c083015260e086013560e0830152610100808701358184015250610120808701358184015250819450612af1818701612933565b93505050612b026101608501612933565b90509250925092565b600060e08284031215612b1d57600080fd5b60405160e0810181811067ffffffffffffffff82111715612b67577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250823581526020830135602082015260408301356040820152606083013560608201526080830135608082015260a083013560a082015260c083013560c08201528091505092915050565b600060a08284031215612bc857600080fd5b60405160a0810181811067ffffffffffffffff82111715612c12577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b806040525082358152602083013560208201526040830135604082015260608301356060820152608083013560808201528091505092915050565b600060208284031215612c5f57600080fd5b5051919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fdfea26469706673582212203c4c958207fa61c10eac99531022389d5e5bd72b5c4cf31ab785364af18b0ddf64736f6c63430008140033";

type BitwiseTestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: BitwiseTestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class BitwiseTestsContract__factory extends ContractFactory {
  constructor(...args: BitwiseTestsContractConstructorParams) {
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
      BitwiseTestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): BitwiseTestsContract__factory {
    return super.connect(runner) as BitwiseTestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): BitwiseTestsContractInterface {
    return new Interface(_abi) as BitwiseTestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): BitwiseTestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as BitwiseTestsContract;
  }
}
