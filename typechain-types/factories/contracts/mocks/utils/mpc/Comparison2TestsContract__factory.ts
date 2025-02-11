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
  Comparison2TestsContract,
  Comparison2TestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/Comparison2TestsContract";

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
        internalType: "struct Comparison2TestsContract.Check16",
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
        internalType: "struct Comparison2TestsContract.Check32",
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
        internalType: "struct Comparison2TestsContract.Check64",
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
    name: "eqTest",
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
    name: "geTest",
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
    name: "getEqResult",
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
    name: "getGeResult",
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
    name: "getNeResult",
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
    name: "neTest",
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
        internalType: "struct Comparison2TestsContract.AllGTCastingValues",
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
  "0x608060405234801561001057600080fd5b5061294b806100206000396000f3fe608060405234801561001057600080fd5b50600436106100be5760003560e01c806370eb37ee116100765780639a0c13d81161005b5780639a0c13d814610155578063acb3816914610160578063bc3aa1ed1461017357600080fd5b806370eb37ee1461012f57806380f937bc1461014257600080fd5b80632e544aa0116100a75780632e544aa0146100f65780632fd37f4b146101095780636b04608f1461011a57600080fd5b80630d980bf0146100c35780631988e322146100e3575b600080fd5b600054610100900460ff165b604051901515815260200160405180910390f35b6100cf6100f13660046125c9565b610186565b6100cf61010436600461264d565b610828565b60005462010000900460ff166100cf565b61012d6101283660046126d0565b610906565b005b6100cf61013d3660046125c9565b6109bb565b6100cf61015036600461278b565b611055565b60005460ff166100cf565b6100cf61016e366004612836565b6110fa565b6100cf6101813660046125c9565b611169565b60006101de604051806101400160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61020260405180606001604052806000815260200160008152602001600081525090565b6102346040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6102746040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61027f848888610906565b600061029b61029686604001518760600151611807565b6118cd565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff166201000083151502179055608086015160a08701519192506102e29161195e565b8452604085015160a08601516102f89190611973565b6020850152608085015160608601516103119190611989565b6040850152600061032185610828565b90508115158115151461037b5760405162461bcd60e51b815260206004820152601660248201527f6765546573743a2063617374203136206661696c65640000000000000000000060448201526064015b60405180910390fd5b61038d8660c001518760e0015161199f565b8452604086015160e08701516103a391906119b4565b602085015260c086015160608701516103bc91906119ca565b6040850152608086015160e08701516103d591906119e0565b606085015260c086015160a08701516103ee91906119f6565b608085015260006103fe856110fa565b9050801515831515146104535760405162461bcd60e51b815260206004820152601660248201527f6765546573743a2063617374203332206661696c6564000000000000000000006044820152606401610372565b610467876101000151886101200151611a0c565b8452604087015161012088015161047e9190611a21565b602085015261010087015160608801516104989190611a37565b604085015260808701516101208801516104b29190611a4d565b606085015261010087015160a08801516104cc9190611a63565b608085015260c08701516101208801516104e69190611a79565b60a085015261010087015160e08801516105009190611a8f565b60c0850152600061051085611055565b9050801515841515146105655760405162461bcd60e51b815260206004820152601660248201527f6765546573743a2063617374203634206661696c6564000000000000000000006044820152606401610372565b6105766102968c8a60600151611aa5565b151584151514801561059b575061059461029689604001518c611b27565b1515841515145b61060d5760405162461bcd60e51b815260206004820152602660248201527f6765546573743a2074657374203820626974732077697468207363616c61722060448201527f6661696c656400000000000000000000000000000000000000000000000000006064820152608401610372565b6106216102968c60ff168a60a00151611baa565b1515841515148015610649575061064261029689608001518c60ff16611c2e565b1515841515145b6106bb5760405162461bcd60e51b815260206004820152602760248201527f6765546573743a207465737420313620626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b6106cf6102968c60ff168a60e00151611cb1565b15158415151480156106f757506106f06102968960c001518c60ff16611d37565b1515841515145b6107695760405162461bcd60e51b815260206004820152602760248201527f6765546573743a207465737420333220626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b61077e6102968c60ff168a6101200151611dbd565b15158415151480156107a757506107a06102968961010001518c60ff16611e47565b1515841515145b6108195760405162461bcd60e51b815260206004820152602760248201527f6765546573743a207465737420363420626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b50919998505050505050505050565b60008061083883600001516118cd565b905061084783602001516118cd565b1515811515148015610868575061086183604001516118cd565b1515811515145b6109005760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a401610372565b92915050565b6109178160ff168360ff1611611ed1565b835261092a60ff80841690831611611ed1565b602084015261093882611f30565b604084015261094681611f30565b606084015261095760ff8316611fd8565b608084015261096860ff8216611fd8565b60a084015261097960ff8316612042565b60c084015261098a60ff8216612042565b60e084015261099b60ff83166120ae565b6101008401526109ad60ff82166120ae565b610120909301929092525050565b6000610a13604051806101400160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610a3760405180606001604052806000815260200160008152602001600081525090565b610a696040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b610aa96040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610ab4848888610906565b610ac96102968560000151866020015161211e565b506000610ae161029686604001518760600151612132565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0016821515179055608086015160a0870151919250610b2391612147565b8452604085015160a0860151610b39919061215c565b602085015260808501516060860151610b529190612172565b60408501526000610b6285610828565b905081151581151514610bb75760405162461bcd60e51b815260206004820152601660248201527f6571546573743a2063617374203136206661696c6564000000000000000000006044820152606401610372565b610bc98660c001518760e00151612188565b8452604086015160e0870151610bdf919061219d565b602085015260c08601516060870151610bf891906121b3565b6040850152608086015160e0870151610c1191906121c9565b606085015260c086015160a0870151610c2a91906121df565b60808501526000610c3a856110fa565b905080151583151514610c8f5760405162461bcd60e51b815260206004820152601660248201527f6571546573743a2063617374203332206661696c6564000000000000000000006044820152606401610372565b610ca38761010001518861012001516121f5565b84526040870151610120880151610cba919061220a565b60208501526101008701516060880151610cd49190612220565b60408501526080870151610120880151610cee9190612236565b606085015261010087015160a0880151610d08919061224c565b608085015260c0870151610120880151610d229190612262565b60a085015261010087015160e0880151610d3c9190612278565b60c08501526000610d4c85611055565b905080151584151514610da15760405162461bcd60e51b815260206004820152601660248201527f6571546573743a2063617374203634206661696c6564000000000000000000006044820152606401610372565b610db26102968c8a6060015161228e565b1515841515148015610dd75750610dd061029689604001518c6122a3565b1515841515145b610e495760405162461bcd60e51b815260206004820152602660248201527f6571546573743a2074657374203820626974732077697468207363616c61722060448201527f6661696c656400000000000000000000000000000000000000000000000000006064820152608401610372565b610e5d6102968c60ff168a60a001516122b9565b1515841515148015610e855750610e7e61029689608001518c60ff166122cf565b1515841515145b610ef75760405162461bcd60e51b815260206004820152602760248201527f6571546573743a207465737420313620626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b610f0b6102968c60ff168a60e001516122e4565b1515841515148015610f335750610f2c6102968960c001518c60ff166122fa565b1515841515145b610fa55760405162461bcd60e51b815260206004820152602760248201527f6571546573743a207465737420333220626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b610fba6102968c60ff168a6101200151612310565b1515841515148015610fe35750610fdc6102968961010001518c60ff16612326565b1515841515145b6108195760405162461bcd60e51b815260206004820152602760248201527f6571546573743a207465737420363420626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b60008061106583600001516118cd565b905061107483602001516118cd565b1515811515148015611095575061108e83604001516118cd565b1515811515145b80156110b057506110a983608001516118cd565b1515811515145b80156110cb57506110c483606001516118cd565b1515811515145b80156110e657506110df8360c001516118cd565b1515811515145b801561086857506108618360a001516118cd565b60008061110a83600001516118cd565b905061111983602001516118cd565b151581151514801561113a575061113383604001516118cd565b1515811515145b8015611155575061114e83608001516118cd565b1515811515145b8015610868575061086183606001516118cd565b60006111c1604051806101400160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b6111e560405180606001604052806000815260200160008152602001600081525090565b6112176040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6112576040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b611262848888610906565b6112776102968560000151866020015161233c565b50600061128f61029686604001518760600151612350565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1661010083151502179055608086015160a08701519192506112d591612365565b8452604085015160a08601516112eb919061237a565b6020850152608085015160608601516113049190612390565b6040850152600061131485610828565b9050811515811515146113695760405162461bcd60e51b815260206004820152601660248201527f6e65546573743a2063617374203136206661696c6564000000000000000000006044820152606401610372565b61137b8660c001518760e001516123a6565b8452604086015160e087015161139191906123bb565b602085015260c086015160608701516113aa91906123d1565b6040850152608086015160e08701516113c391906123e7565b606085015260c086015160a08701516113dc91906123fd565b608085015260006113ec856110fa565b9050801515831515146114415760405162461bcd60e51b815260206004820152601660248201527f6e65546573743a2063617374203332206661696c6564000000000000000000006044820152606401610372565b611455876101000151886101200151612413565b8452604087015161012088015161146c9190612428565b60208501526101008701516060880151611486919061243e565b604085015260808701516101208801516114a09190612454565b606085015261010087015160a08801516114ba919061246a565b608085015260c08701516101208801516114d49190612480565b60a085015261010087015160e08801516114ee9190612496565b60c085015260006114fe85611055565b9050801515841515146115535760405162461bcd60e51b815260206004820152601660248201527f6e65546573743a2063617374203634206661696c6564000000000000000000006044820152606401610372565b6115646102968c8a606001516124ac565b1515841515148015611589575061158261029689604001518c6124c1565b1515841515145b6115fb5760405162461bcd60e51b815260206004820152602660248201527f6e65546573743a2074657374203820626974732077697468207363616c61722060448201527f6661696c656400000000000000000000000000000000000000000000000000006064820152608401610372565b61160f6102968c60ff168a60a001516124d7565b1515841515148015611637575061163061029689608001518c60ff166124ed565b1515841515145b6116a95760405162461bcd60e51b815260206004820152602760248201527f6e65546573743a207465737420313620626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b6116bd6102968c60ff168a60e00151612502565b15158415151480156116e557506116de6102968960c001518c60ff16612518565b1515841515145b6117575760405162461bcd60e51b815260206004820152602760248201527f6e65546573743a207465737420333220626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b61176c6102968c60ff168a610120015161252e565b1515841515148015611795575061178e6102968961010001518c60ff16612544565b1515841515145b6108195760405162461bcd60e51b815260206004820152602760248201527f6e65546573743a207465737420363420626974732077697468207363616c617260448201527f206661696c6564000000000000000000000000000000000000000000000000006064820152608401610372565b6000606463813b207461181c60018085612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260248101869052604481018590526064015b6020604051808303816000875af11580156118a2573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906118c691906128cd565b9392505050565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015611931573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061195591906128cd565b15159392505050565b6000606463813b207461181c60028085612556565b6000606463813b207461181c6001600285612556565b6000606463813b207461181c6002600185612556565b6000606463813b207461181c60038085612556565b6000606463813b207461181c6001600385612556565b6000606463813b207461181c6003600185612556565b6000606463813b207461181c6002600385612556565b6000606463813b207461181c6003600285612556565b6000606463813b207461181c60048085612556565b6000606463813b207461181c6001600485612556565b6000606463813b207461181c6004600185612556565b6000606463813b207461181c6002600485612556565b6000606463813b207461181c6004600285612556565b6000606463813b207461181c6003600485612556565b6000606463813b207461181c6004600385612556565b6000606463813b2074611aba60018080612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260ff8616602482015260448101859052606401611883565b6000606463813b2074611b3d6001806002612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905260ff85166044820152606401611883565b6000606463813b2074611bc06002806001612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015261ffff8616602482015260448101859052606401611883565b6000606463813b2074611c4360028080612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905261ffff85166044820152606401611883565b6000606463813b2074611cc76003806001612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015263ffffffff8616602482015260448101859052606401611883565b6000606463813b2074611d4d6003806002612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905263ffffffff85166044820152606401611883565b6000606463813b2074611dd36004806001612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015267ffffffffffffffff8616602482015260448101859052606401611883565b6000606463813b2074611e5d6004806002612556565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905267ffffffffffffffff85166044820152606401611883565b60008082611ee0576000611ee3565b60015b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081526000600482015260ff9190911660248201819052915060649063d9b60b6090604401611883565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b60906044015b6020604051808303816000875af1158015611fb4573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061090091906128cd565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401611f95565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401611f95565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401611f95565b60006064637c12a1eb61181c838080612556565b60006064637c12a1eb61181c60018085612556565b60006064637c12a1eb61181c60028085612556565b60006064637c12a1eb61181c6001600285612556565b60006064637c12a1eb61181c6002600185612556565b60006064637c12a1eb61181c60038085612556565b60006064637c12a1eb61181c6001600385612556565b60006064637c12a1eb61181c6003600185612556565b60006064637c12a1eb61181c6002600385612556565b60006064637c12a1eb61181c6003600285612556565b60006064637c12a1eb61181c60048085612556565b60006064637c12a1eb61181c6001600485612556565b60006064637c12a1eb61181c6004600185612556565b60006064637c12a1eb61181c6002600485612556565b60006064637c12a1eb61181c6004600285612556565b60006064637c12a1eb61181c6003600485612556565b60006064637c12a1eb61181c6004600385612556565b60006064637c12a1eb611aba60018080612556565b60006064637c12a1eb611b3d6001806002612556565b60006064637c12a1eb611bc06002806001612556565b60006064637c12a1eb611c4360028080612556565b60006064637c12a1eb611cc76003806001612556565b60006064637c12a1eb611d4d6003806002612556565b60006064637c12a1eb611dd36004806001612556565b60006064637c12a1eb611e5d6004806002612556565b600060646342094c5661181c838080612556565b600060646342094c5661181c60018085612556565b600060646342094c5661181c60028085612556565b600060646342094c5661181c6001600285612556565b600060646342094c5661181c6002600185612556565b600060646342094c5661181c60038085612556565b600060646342094c5661181c6001600385612556565b600060646342094c5661181c6003600185612556565b600060646342094c5661181c6002600385612556565b600060646342094c5661181c6003600285612556565b600060646342094c5661181c60048085612556565b600060646342094c5661181c6001600485612556565b600060646342094c5661181c6004600185612556565b600060646342094c5661181c6002600485612556565b600060646342094c5661181c6004600285612556565b600060646342094c5661181c6003600485612556565b600060646342094c5661181c6004600385612556565b600060646342094c56611aba60018080612556565b600060646342094c56611b3d6001806002612556565b600060646342094c56611bc06002806001612556565b600060646342094c56611c4360028080612556565b600060646342094c56611cc76003806001612556565b600060646342094c56611d4d6003806002612556565b600060646342094c56611dd36004806001612556565b600060646342094c56611e5d60048060025b600081600281111561256a5761256a6128e6565b60ff166008846004811115612581576125816128e6565b61ffff16901b61ffff16601086600481111561259f5761259f6128e6565b62ffffff16901b171760e81b949350505050565b803560ff811681146125c457600080fd5b919050565b600080604083850312156125dc57600080fd5b6125e5836125b3565b91506125f3602084016125b3565b90509250929050565b604051610140810167ffffffffffffffff81118282101715612647577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b60006060828403121561265f57600080fd5b6040516060810181811067ffffffffffffffff821117156126a9577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b80604052508235815260208301356020820152604083013560408201528091505092915050565b60008060008385036101808112156126e757600080fd5b610140808212156126f757600080fd5b6126ff6125fc565b9150853582526020860135602083015260408601356040830152606086013560608301526080860135608083015260a086013560a083015260c086013560c083015260e086013560e08301526101008087013581840152506101208087013581840152508194506127718187016125b3565b9350505061278261016085016125b3565b90509250925092565b600060e0828403121561279d57600080fd5b60405160e0810181811067ffffffffffffffff821117156127e7577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250823581526020830135602082015260408301356040820152606083013560608201526080830135608082015260a083013560a082015260c083013560c08201528091505092915050565b600060a0828403121561284857600080fd5b60405160a0810181811067ffffffffffffffff82111715612892577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b806040525082358152602083013560208201526040830135604082015260608301356060820152608083013560808201528091505092915050565b6000602082840312156128df57600080fd5b5051919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fdfea2646970667358221220c2db15751f6e4362e92df07d2934d6a277dfa5d094d3b772d80b9ee979445c6964736f6c63430008130033";

type Comparison2TestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: Comparison2TestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class Comparison2TestsContract__factory extends ContractFactory {
  constructor(...args: Comparison2TestsContractConstructorParams) {
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
      Comparison2TestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): Comparison2TestsContract__factory {
    return super.connect(runner) as Comparison2TestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): Comparison2TestsContractInterface {
    return new Interface(_abi) as Comparison2TestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): Comparison2TestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as Comparison2TestsContract;
  }
}
