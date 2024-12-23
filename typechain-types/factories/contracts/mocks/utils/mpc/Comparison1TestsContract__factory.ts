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
  Comparison1TestsContract,
  Comparison1TestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/Comparison1TestsContract";

const _abi = [
  {
    inputs: [
      {
        components: [
          {
            internalType: "gtBool",
            name: "res16_16",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res8_16",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res16_8",
            type: "uint256",
          },
        ],
        internalType: "struct Comparison1TestsContract.Check16",
        name: "check16",
        type: "tuple",
      },
    ],
    name: "decryptAndCompareResults16",
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
        components: [
          {
            internalType: "gtBool",
            name: "res32_32",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res8_32",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res32_8",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res16_32",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res32_16",
            type: "uint256",
          },
        ],
        internalType: "struct Comparison1TestsContract.Check32",
        name: "check32",
        type: "tuple",
      },
    ],
    name: "decryptAndCompareResults32",
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
        components: [
          {
            internalType: "gtBool",
            name: "res64_64",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res8_64",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res64_8",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res16_64",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res64_16",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res32_64",
            type: "uint256",
          },
          {
            internalType: "gtBool",
            name: "res64_32",
            type: "uint256",
          },
        ],
        internalType: "struct Comparison1TestsContract.Check64",
        name: "check64",
        type: "tuple",
      },
    ],
    name: "decryptAndCompareResults64",
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
    inputs: [],
    name: "getGtResult",
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
    name: "getLeResult",
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
    name: "getLtResult",
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
    name: "gtTest",
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
    name: "leTest",
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
    name: "ltTest",
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
        internalType: "struct Comparison1TestsContract.AllGTCastingValues",
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
  "0x608060405234801561001057600080fd5b50612793806100206000396000f3fe608060405234801561001057600080fd5b50600436106100be5760003560e01c80637d2e0f48116100765780638b6e7a8c1161005b5780638b6e7a8c1461014f578063acb3816914610162578063ebb571fd1461017557600080fd5b80637d2e0f481461013157806380f937bc1461013c57600080fd5b80632e544aa0116100a75780632e544aa0146100fa5780632e5950eb1461010d578063791175491461011e57600080fd5b806308c90f0d146100c357806329875348146100ea575b600080fd5b6100d66100d1366004612429565b61018a565b604051901515815260200160405180910390f35b600054610100900460ff166100d6565b6100d66101083660046124ad565b6107d6565b60005462010000900460ff166100d6565b6100d661012c366004612429565b6108b4565b60005460ff166100d6565b6100d661014a366004612530565b610eeb565b6100d661015d366004612429565b610f90565b6100d66101703660046125db565b6115f4565b610188610183366004612672565b611663565b005b60006101d460405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b6101f860405180606001604052806000815260200160008152602001600081525090565b61022a6040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b61026a6040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610275848888611663565b600061029161028c866000015187602001516116ea565b6117b0565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0016821515179055604086015160608701519192506102d391611841565b8452845160608601516102e69190611856565b8460200181815250506103018560400151866020015161186c565b60408501526000610311856107d6565b90508115158115151461036b5760405162461bcd60e51b815260206004820152601660248201527f6774546573743a2063617374203136206661696c65640000000000000000000060448201526064015b60405180910390fd5b61037d86608001518760a00151611882565b8452855160a08701516103909190611897565b8460200181815250506103ab866080015187602001516118ad565b8460400181815250506103c686604001518760a001516118c3565b8460600181815250506103e1866080015187606001516118d9565b608085015260006103f1856115f4565b9050801515831515146104465760405162461bcd60e51b815260206004820152601660248201527f6774546573743a2063617374203332206661696c6564000000000000000000006044820152606401610362565b6104588760c001518860e001516118ef565b8452865160e088015161046b9190611904565b8460200181815250506104868760c00151886020015161191a565b8460400181815250506104a187604001518860e00151611930565b8460600181815250506104bc8760c001518860600151611946565b8460800181815250506104d787608001518860e0015161195c565b8460a00181815250506104f28760c001518860a00151611972565b60c0850152600061050285610eeb565b9050801515841515146105575760405162461bcd60e51b815260206004820152601660248201527f6774546573743a2063617374203634206661696c6564000000000000000000006044820152606401610362565b61056861028c8c8a60200151611988565b151584151514801561058d575061058661028c89600001518c611a0a565b1515841515145b6105ff5760405162461bcd60e51b815260206004820152602660248201527f6774546573743a2074657374203820626974732077697468207363616c61722060448201527f6661696c656400000000000000000000000000000000000000000000000000006064820152608401610362565b61061361028c8c60ff168a60600151611a8d565b151584151514801561063b575061063461028c89604001518c60ff16611b11565b1515841515145b6106975760405162461bcd60e51b815260206004820152602760248201527f6774546573743a207465737420313620626974732077697468207363616c61726044820152660819985a5b195960ca1b6064820152608401610362565b6106ab61028c8c60ff168a60a00151611b94565b15158415151480156106d357506106cc61028c89608001518c60ff16611c1a565b1515841515145b61072f5760405162461bcd60e51b815260206004820152602760248201527f6774546573743a207465737420333220626974732077697468207363616c61726044820152660819985a5b195960ca1b6064820152608401610362565b61074361028c8c60ff168a60e00151611ca0565b151584151514801561076b575061076461028c8960c001518c60ff16611d2a565b1515841515145b6107c75760405162461bcd60e51b815260206004820152602760248201527f6774546573743a207465737420363420626974732077697468207363616c61726044820152660819985a5b195960ca1b6064820152608401610362565b50919998505050505050505050565b6000806107e683600001516117b0565b90506107f583602001516117b0565b1515811515148015610816575061080f83604001516117b0565b1515811515145b6108ae5760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a401610362565b92915050565b60006108fe60405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61092260405180606001604052806000815260200160008152602001600081525090565b6109546040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6109946040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61099f848888611663565b60006109b661028c86600001518760200151611db4565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1661010083151502179055604086015160608701519192506109fc91611dc9565b845284516060860151610a0f9190611dde565b846020018181525050610a2a85604001518660200151611df4565b60408501526000610a3a856107d6565b905081151581151514610a8f5760405162461bcd60e51b815260206004820152601660248201527f6c65546573743a2063617374203136206661696c6564000000000000000000006044820152606401610362565b610aa186608001518760a00151611e0a565b8452855160a0870151610ab49190611e1f565b846020018181525050610acf86608001518760200151611e35565b846040018181525050610aea86604001518760a00151611e4b565b846060018181525050610b0586608001518760600151611e61565b60808501526000610b15856115f4565b905080151583151514610b6a5760405162461bcd60e51b815260206004820152601660248201527f6c65546573743a2063617374203332206661696c6564000000000000000000006044820152606401610362565b610b7c8760c001518860e00151611e77565b8452865160e0880151610b8f9190611e8c565b846020018181525050610baa8760c001518860200151611ea2565b846040018181525050610bc587604001518860e00151611eb8565b846060018181525050610be08760c001518860600151611ece565b846080018181525050610bfb87608001518860e00151611ee4565b8460a0018181525050610c168760c001518860a00151611efa565b60c08501526000610c2685610eeb565b905080151584151514610c7b5760405162461bcd60e51b815260206004820152601660248201527f6c65546573743a2063617374203634206661696c6564000000000000000000006044820152606401610362565b610c8c61028c8c8a60200151611f10565b1515841515148015610cb15750610caa61028c89600001518c611f25565b1515841515145b610d235760405162461bcd60e51b815260206004820152602660248201527f6c65546573743a2074657374203820626974732077697468207363616c61722060448201527f6661696c656400000000000000000000000000000000000000000000000000006064820152608401610362565b610d3761028c8c60ff168a60600151611f3b565b1515841515148015610d5f5750610d5861028c89604001518c60ff16611f51565b1515841515145b610dbb5760405162461bcd60e51b815260206004820152602760248201527f6c65546573743a207465737420313620626974732077697468207363616c61726044820152660819985a5b195960ca1b6064820152608401610362565b610dcf61028c8c60ff168a60a00151611f66565b1515841515148015610df75750610df061028c89608001518c60ff16611f7c565b1515841515145b610e535760405162461bcd60e51b815260206004820152602760248201527f6c65546573743a207465737420333220626974732077697468207363616c61726044820152660819985a5b195960ca1b6064820152608401610362565b610e6761028c8c60ff168a60e00151611f92565b1515841515148015610e8f5750610e8861028c8960c001518c60ff16611fa8565b1515841515145b6107c75760405162461bcd60e51b815260206004820152602760248201527f6c65546573743a207465737420363420626974732077697468207363616c61726044820152660819985a5b195960ca1b6064820152608401610362565b600080610efb83600001516117b0565b9050610f0a83602001516117b0565b1515811515148015610f2b5750610f2483604001516117b0565b1515811515145b8015610f465750610f3f83608001516117b0565b1515811515145b8015610f615750610f5a83606001516117b0565b1515811515145b8015610f7c5750610f758360c001516117b0565b1515811515145b8015610816575061080f8360a001516117b0565b6000610fda60405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610ffe60405180606001604052806000815260200160008152602001600081525090565b6110306040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6110706040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61107b848888611663565b600061109261028c86600001518760200151611fbe565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff166201000083151502179055604086015160608701519192506110d991611fd3565b8452845160608601516110ec9190611fe8565b84602001818152505061110785604001518660200151611ffe565b60408501526000611117856107d6565b90508115158115151461116c5760405162461bcd60e51b815260206004820152601760248201527f6c6574546573743a2063617374203136206661696c65640000000000000000006044820152606401610362565b61117e86608001518760a00151612014565b8452855160a08701516111919190612029565b8460200181815250506111ac8660800151876020015161203f565b8460400181815250506111c786604001518760a00151612055565b8460600181815250506111e28660800151876060015161206b565b608085015260006111f2856115f4565b9050801515831515146112475760405162461bcd60e51b815260206004820152601760248201527f6c6574546573743a2063617374203332206661696c65640000000000000000006044820152606401610362565b6112598760c001518860e00151612081565b8452865160e088015161126c9190612096565b8460200181815250506112878760c0015188602001516120ac565b8460400181815250506112a287604001518860e001516120c2565b8460600181815250506112bd8760c0015188606001516120d8565b8460800181815250506112d887608001518860e001516120ee565b8460a00181815250506112f38760c001518860a00151612104565b60c0850152600061130385610eeb565b9050801515841515146113585760405162461bcd60e51b815260206004820152601760248201527f6c6574546573743a2063617374203634206661696c65640000000000000000006044820152606401610362565b61136961028c8c8a6020015161211a565b151584151514801561138e575061138761028c89600001518c61212f565b1515841515145b6113ea5760405162461bcd60e51b815260206004820152602760248201527f6c6574546573743a2074657374203820626974732077697468207363616c61726044820152660819985a5b195960ca1b6064820152608401610362565b6113fe61028c8c60ff168a60600151612145565b1515841515148015611426575061141f61028c89604001518c60ff1661215b565b1515841515145b6114985760405162461bcd60e51b815260206004820152602860248201527f6c6574546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c65640000000000000000000000000000000000000000000000006064820152608401610362565b6114ac61028c8c60ff168a60a00151612170565b15158415151480156114d457506114cd61028c89608001518c60ff16612186565b1515841515145b6115465760405162461bcd60e51b815260206004820152602860248201527f6c6574546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c65640000000000000000000000000000000000000000000000006064820152608401610362565b61155a61028c8c60ff168a60e0015161219c565b1515841515148015611582575061157b61028c8960c001518c60ff166121b2565b1515841515145b6107c75760405162461bcd60e51b815260206004820152602860248201527f6c6574546573743a207465737420363420626974732077697468207363616c6160448201527f72206661696c65640000000000000000000000000000000000000000000000006064820152608401610362565b60008061160483600001516117b0565b905061161383602001516117b0565b1515811515148015611634575061162d83604001516117b0565b1515811515145b801561164f575061164883608001516117b0565b1515811515145b8015610816575061080f83606001516117b0565b61166c826121c8565b8352611677816121c8565b602084015261168860ff8316612270565b604084015261169960ff8216612270565b60608401526116aa60ff83166122da565b60808401526116bb60ff82166122da565b60a08401526116cc60ff8316612346565b60c08401526116dd60ff8216612346565b60e0909301929092525050565b60006064636d82e45e6116ff600180856123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260248101869052604481018590526064015b6020604051808303816000875af1158015611785573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906117a99190612715565b9392505050565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015611814573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906118389190612715565b15159392505050565b60006064636d82e45e6116ff600280856123b6565b60006064636d82e45e6116ff60016002856123b6565b60006064636d82e45e6116ff60026001856123b6565b60006064636d82e45e6116ff600380856123b6565b60006064636d82e45e6116ff60016003856123b6565b60006064636d82e45e6116ff60036001856123b6565b60006064636d82e45e6116ff60026003856123b6565b60006064636d82e45e6116ff60036002856123b6565b60006064636d82e45e6116ff600480856123b6565b60006064636d82e45e6116ff60016004856123b6565b60006064636d82e45e6116ff60046001856123b6565b60006064636d82e45e6116ff60026004856123b6565b60006064636d82e45e6116ff60046002856123b6565b60006064636d82e45e6116ff60036004856123b6565b60006064636d82e45e6116ff60046003856123b6565b60006064636d82e45e61199d600180806123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260ff8616602482015260448101859052606401611766565b60006064636d82e45e611a2060018060026123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905260ff85166044820152606401611766565b60006064636d82e45e611aa360028060016123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015261ffff8616602482015260448101859052606401611766565b60006064636d82e45e611b26600280806123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905261ffff85166044820152606401611766565b60006064636d82e45e611baa60038060016123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015263ffffffff8616602482015260448101859052606401611766565b60006064636d82e45e611c3060038060026123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905263ffffffff85166044820152606401611766565b60006064636d82e45e611cb660048060016123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015267ffffffffffffffff8616602482015260448101859052606401611766565b60006064636d82e45e611d4060048060026123b6565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905267ffffffffffffffff85166044820152606401611766565b6000606463145fca2c6116ff600180856123b6565b6000606463145fca2c6116ff600280856123b6565b6000606463145fca2c6116ff60016002856123b6565b6000606463145fca2c6116ff60026001856123b6565b6000606463145fca2c6116ff600380856123b6565b6000606463145fca2c6116ff60016003856123b6565b6000606463145fca2c6116ff60036001856123b6565b6000606463145fca2c6116ff60026003856123b6565b6000606463145fca2c6116ff60036002856123b6565b6000606463145fca2c6116ff600480856123b6565b6000606463145fca2c6116ff60016004856123b6565b6000606463145fca2c6116ff60046001856123b6565b6000606463145fca2c6116ff60026004856123b6565b6000606463145fca2c6116ff60046002856123b6565b6000606463145fca2c6116ff60036004856123b6565b6000606463145fca2c6116ff60046003856123b6565b6000606463145fca2c61199d600180806123b6565b6000606463145fca2c611a2060018060026123b6565b6000606463145fca2c611aa360028060016123b6565b6000606463145fca2c611b26600280806123b6565b6000606463145fca2c611baa60038060016123b6565b6000606463145fca2c611c3060038060026123b6565b6000606463145fca2c611cb660048060016123b6565b6000606463145fca2c611d4060048060026123b6565b6000606463dd1486936116ff600180856123b6565b6000606463dd1486936116ff600280856123b6565b6000606463dd1486936116ff60016002856123b6565b6000606463dd1486936116ff60026001856123b6565b6000606463dd1486936116ff600380856123b6565b6000606463dd1486936116ff60016003856123b6565b6000606463dd1486936116ff60036001856123b6565b6000606463dd1486936116ff60026003856123b6565b6000606463dd1486936116ff60036002856123b6565b6000606463dd1486936116ff600480856123b6565b6000606463dd1486936116ff60016004856123b6565b6000606463dd1486936116ff60046001856123b6565b6000606463dd1486936116ff60026004856123b6565b6000606463dd1486936116ff60046002856123b6565b6000606463dd1486936116ff60036004856123b6565b6000606463dd1486936116ff60046003856123b6565b6000606463dd14869361199d600180806123b6565b6000606463dd148693611a2060018060026123b6565b6000606463dd148693611aa360028060016123b6565b6000606463dd148693611b26600280806123b6565b6000606463dd148693611baa60038060016123b6565b6000606463dd148693611c3060038060026123b6565b6000606463dd148693611cb660048060016123b6565b6000606463dd148693611d4060048060026123b6565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b60906044015b6020604051808303816000875af115801561224c573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906108ae9190612715565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b609060440161222d565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b609060440161222d565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b609060440161222d565b60008160028111156123ca576123ca61272e565b60ff1660088460048111156123e1576123e161272e565b61ffff16901b61ffff1660108660048111156123ff576123ff61272e565b62ffffff16901b171760e81b949350505050565b803560ff8116811461242457600080fd5b919050565b6000806040838503121561243c57600080fd5b61244583612413565b915061245360208401612413565b90509250929050565b604051610100810167ffffffffffffffff811182821017156124a7577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b6000606082840312156124bf57600080fd5b6040516060810181811067ffffffffffffffff82111715612509577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b80604052508235815260208301356020820152604083013560408201528091505092915050565b600060e0828403121561254257600080fd5b60405160e0810181811067ffffffffffffffff8211171561258c577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250823581526020830135602082015260408301356040820152606083013560608201526080830135608082015260a083013560a082015260c083013560c08201528091505092915050565b600060a082840312156125ed57600080fd5b60405160a0810181811067ffffffffffffffff82111715612637577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b806040525082358152602083013560208201526040830135604082015260608301356060820152608083013560808201528091505092915050565b600080600083850361014081121561268957600080fd5b6101008082121561269957600080fd5b6126a161245c565b9150853582526020860135602083015260408601356040830152606086013560608301526080860135608083015260a086013560a083015260c086013560c083015260e086013560e08301528194506126fb818701612413565b9350505061270c6101208501612413565b90509250925092565b60006020828403121561272757600080fd5b5051919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fdfea2646970667358221220e21703bd97b3e6d206b5895f833ae6d8bd6abac09e06fa582cb176e9e7b42f4564736f6c63430008140033";

type Comparison1TestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: Comparison1TestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class Comparison1TestsContract__factory extends ContractFactory {
  constructor(...args: Comparison1TestsContractConstructorParams) {
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
      Comparison1TestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): Comparison1TestsContract__factory {
    return super.connect(runner) as Comparison1TestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): Comparison1TestsContractInterface {
    return new Interface(_abi) as Comparison1TestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): Comparison1TestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as Comparison1TestsContract;
  }
}
