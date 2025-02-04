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
  MinMaxTestsContract,
  MinMaxTestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/MinMaxTestsContract";

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
        internalType: "struct MinMaxTestsContract.Check16",
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
        internalType: "struct MinMaxTestsContract.Check32",
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
        internalType: "struct MinMaxTestsContract.Check64",
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
    name: "getMaxResult",
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
    name: "getMinResult",
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
    name: "maxTest",
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
    name: "minTest",
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
        internalType: "struct MinMaxTestsContract.AllGTCastingValues",
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
  "0x608060405234801561001057600080fd5b50612172806100206000396000f3fe608060405234801561001057600080fd5b50600436106100885760003560e01c8063d4c1db711161005b578063d4c1db7114610125578063dad85e0a14610135578063e23a217614610148578063ebb571fd1461015b57600080fd5b80632e544aa01461008d5780634ea83705146100b857806380f937bc146100d1578063acb38169146100fd575b600080fd5b6100a061009b366004611e43565b610170565b60405161ffff90911681526020015b60405180910390f35b60005460ff165b60405160ff90911681526020016100af565b6100e46100df366004611ec6565b61025b565b60405167ffffffffffffffff90911681526020016100af565b61011061010b366004611f71565b6103fe565b60405163ffffffff90911681526020016100af565b600054610100900460ff166100bf565b6100bf61014336600461201e565b61052b565b6100bf61015636600461201e565b610c11565b61016e610169366004612051565b61124f565b005b60008061018083600001516112d6565b905061018f83602001516112d6565b61ffff168161ffff161480156101b857506101ad83604001516112d6565b61ffff168161ffff16145b6102555760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4015b60405180910390fd5b92915050565b60008061026b8360000151611373565b905061027a8360200151611373565b67ffffffffffffffff168167ffffffffffffffff161480156102bb57506102a48360400151611373565b67ffffffffffffffff168167ffffffffffffffff16145b80156102e657506102cf8360800151611373565b67ffffffffffffffff168167ffffffffffffffff16145b801561031157506102fa8360600151611373565b67ffffffffffffffff168167ffffffffffffffff16145b801561033c57506103258360c00151611373565b67ffffffffffffffff168167ffffffffffffffff16145b80156101b857506103508360a00151611373565b67ffffffffffffffff168167ffffffffffffffff16146102555760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a40161024c565b60008061040e8360000151611383565b905061041d8360200151611383565b63ffffffff168163ffffffff1614801561044e575061043f8360400151611383565b63ffffffff168163ffffffff16145b801561047157506104628360800151611383565b63ffffffff168163ffffffff16145b80156101b857506104858360600151611383565b63ffffffff168163ffffffff16146102555760405162461bcd60e51b815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a40161024c565b600061057560405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61059960405180606001604052806000815260200160008152602001600081525090565b6105cb6040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b61060b6040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b61061684888861124f565b600061063261062d86600001518760200151611393565b611459565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff83161790556040860151606087015191925061067591611469565b845284516060860151610688919061147e565b8460200181815250506106a385604001518660200151611494565b604085015260006106b385610170565b90508160ff168161ffff161461070b5760405162461bcd60e51b815260206004820152601760248201527f6d696e546573743a2063617374203136206661696c6564000000000000000000604482015260640161024c565b61071d86608001518760a001516114aa565b8452855160a087015161073091906114bf565b84602001818152505061074b866080015187602001516114d5565b84604001818152505061076686604001518760a001516114eb565b84606001818152505061078186608001518760600151611501565b60808501526000610791856103fe565b90508063ffffffff168360ff16146107eb5760405162461bcd60e51b815260206004820152601760248201527f6d696e546573743a2063617374203332206661696c6564000000000000000000604482015260640161024c565b6107fd8760c001518860e00151611517565b8452865160e0880151610810919061152c565b84602001818152505061082b8760c001518860200151611542565b84604001818152505061084687604001518860e00151611558565b8460600181815250506108618760c00151886060015161156e565b84608001818152505061087c87608001518860e00151611584565b8460a00181815250506108978760c001518860a0015161159a565b60c085015260006108a78561025b565b90508067ffffffffffffffff168460ff16146109055760405162461bcd60e51b815260206004820152601760248201527f6d696e546573743a2063617374203634206661696c6564000000000000000000604482015260640161024c565b61091661062d8c8a602001516115b0565b60ff168460ff1614801561093f575061093661062d89600001518c611632565b60ff168460ff16145b6109b15760405162461bcd60e51b815260206004820152602760248201527f6d696e546573743a2074657374203820626974732077697468207363616c617260448201527f206661696c656400000000000000000000000000000000000000000000000000606482015260840161024c565b6109ca6109c58c60ff168a606001516116b5565b6112d6565b61ffff168361ffff161480156109fa57506109ef6109c589604001518c60ff16611739565b61ffff168361ffff16145b610a6c5760405162461bcd60e51b815260206004820152602860248201527f6d696e546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c6564000000000000000000000000000000000000000000000000606482015260840161024c565b610a85610a808c60ff168a60a001516117bc565b611383565b63ffffffff168263ffffffff16148015610abd5750610aae610a8089608001518c60ff16611842565b63ffffffff168263ffffffff16145b610b2f5760405162461bcd60e51b815260206004820152602860248201527f6d696e546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c6564000000000000000000000000000000000000000000000000606482015260840161024c565b610b48610b438c60ff168a60e001516118c8565b611373565b67ffffffffffffffff168167ffffffffffffffff16148015610b905750610b79610b438960c001518c60ff16611952565b67ffffffffffffffff168167ffffffffffffffff16145b610c025760405162461bcd60e51b815260206004820152602860248201527f6d696e546573743a207465737420363420626974732077697468207363616c6160448201527f72206661696c6564000000000000000000000000000000000000000000000000606482015260840161024c565b50919998505050505050505050565b6000610c5b60405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610c7f60405180606001604052806000815260200160008152602001600081525090565b610cb16040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b610cf16040518060e00160405280600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610cfc84888861124f565b6000610d1361062d866000015187602001516119dc565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1661010060ff84160217905560408601516060870151919250610d5a916119f1565b845284516060860151610d6d9190611a06565b846020018181525050610d8885604001518660200151611a1c565b60408501526000610d9885610170565b90508160ff168161ffff1614610df05760405162461bcd60e51b815260206004820152601760248201527f6d6178546573743a2063617374203136206661696c6564000000000000000000604482015260640161024c565b610e0286608001518760a00151611a32565b8452855160a0870151610e159190611a47565b846020018181525050610e3086608001518760200151611a5d565b846040018181525050610e4b86604001518760a00151611a73565b846060018181525050610e6686608001518760600151611a89565b60808501526000610e76856103fe565b90508063ffffffff168360ff1614610ed05760405162461bcd60e51b815260206004820152601760248201527f6d6178546573743a2063617374203332206661696c6564000000000000000000604482015260640161024c565b610ee28760c001518860e00151611a9f565b8452865160e0880151610ef59190611ab4565b846020018181525050610f108760c001518860200151611aca565b846040018181525050610f2b87604001518860e00151611ae0565b846060018181525050610f468760c001518860600151611af6565b846080018181525050610f6187608001518860e00151611b0c565b8460a0018181525050610f7c8760c001518860a00151611b22565b60c08501526000610f8c8561025b565b90508067ffffffffffffffff168460ff1614610fea5760405162461bcd60e51b815260206004820152601760248201527f6d6178546573743a2063617374203634206661696c6564000000000000000000604482015260640161024c565b610ffb61062d8c8a60200151611b38565b60ff168460ff16148015611024575061101b61062d89600001518c611b4d565b60ff168460ff16145b6110965760405162461bcd60e51b815260206004820152602760248201527f6d696e546573743a2074657374203820626974732077697468207363616c617260448201527f206661696c656400000000000000000000000000000000000000000000000000606482015260840161024c565b6110aa6109c58c60ff168a60600151611b63565b61ffff168361ffff161480156110da57506110cf6109c589604001518c60ff16611b79565b61ffff168361ffff16145b61114c5760405162461bcd60e51b815260206004820152602860248201527f6d696e546573743a207465737420313620626974732077697468207363616c6160448201527f72206661696c6564000000000000000000000000000000000000000000000000606482015260840161024c565b611160610a808c60ff168a60a00151611b8e565b63ffffffff168263ffffffff161480156111985750611189610a8089608001518c60ff16611ba4565b63ffffffff168263ffffffff16145b61120a5760405162461bcd60e51b815260206004820152602860248201527f6d696e546573743a207465737420333220626974732077697468207363616c6160448201527f72206661696c6564000000000000000000000000000000000000000000000000606482015260840161024c565b61121e610b438c60ff168a60e00151611bba565b67ffffffffffffffff168167ffffffffffffffff16148015610b905750610b79610b438960c001518c60ff16611bd0565b61125882611be6565b835261126381611be6565b602084015261127460ff8316611c4f565b604084015261128560ff8216611c4f565b606084015261129660ff8316611cb9565b60808401526112a760ff8216611cb9565b60a08401526112b860ff8316611d25565b60c08401526112c960ff8216611d25565b60e0909301929092525050565b60006064630cfed56160025b60f81b846040518363ffffffff1660e01b81526004016113309291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af115801561134f573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102559190612123565b60006064630cfed56160046112e2565b60006064630cfed56160036112e2565b600060646369ca08746113a860018085611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260248101869052604481018590526064015b6020604051808303816000875af115801561142e573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114529190612123565b9392505050565b60006064630cfed56160016112e2565b600060646369ca08746113a860028085611d95565b600060646369ca08746113a86001600285611d95565b600060646369ca08746113a86002600185611d95565b600060646369ca08746113a860038085611d95565b600060646369ca08746113a86001600385611d95565b600060646369ca08746113a86003600185611d95565b600060646369ca08746113a86002600385611d95565b600060646369ca08746113a86003600285611d95565b600060646369ca08746113a860048085611d95565b600060646369ca08746113a86001600485611d95565b600060646369ca08746113a86004600185611d95565b600060646369ca08746113a86002600485611d95565b600060646369ca08746113a86004600285611d95565b600060646369ca08746113a86003600485611d95565b600060646369ca08746113a86004600385611d95565b600060646369ca08746115c560018080611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015260ff861660248201526044810185905260640161140f565b600060646369ca08746116486001806002611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905260ff8516604482015260640161140f565b600060646369ca08746116cb6002806001611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015261ffff861660248201526044810185905260640161140f565b600060646369ca087461174e60028080611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905261ffff8516604482015260640161140f565b600060646369ca08746117d26003806001611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015263ffffffff861660248201526044810185905260640161140f565b600060646369ca08746118586003806002611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905263ffffffff8516604482015260640161140f565b600060646369ca08746118de6004806001611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff0000000000000000000000000000000000000000000000000000000000909116600482015267ffffffffffffffff861660248201526044810185905260640161140f565b600060646369ca08746119686004806002611d95565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905267ffffffffffffffff8516604482015260640161140f565b60006064639bda07826113a860018085611d95565b60006064639bda07826113a860028085611d95565b60006064639bda07826113a86001600285611d95565b60006064639bda07826113a86002600185611d95565b60006064639bda07826113a860038085611d95565b60006064639bda07826113a86001600385611d95565b60006064639bda07826113a86003600185611d95565b60006064639bda07826113a86002600385611d95565b60006064639bda07826113a86003600285611d95565b60006064639bda07826113a860048085611d95565b60006064639bda07826113a86001600485611d95565b60006064639bda07826113a86004600185611d95565b60006064639bda07826113a86002600485611d95565b60006064639bda07826113a86004600285611d95565b60006064639bda07826113a86003600485611d95565b60006064639bda07826113a86004600385611d95565b60006064639bda07826115c560018080611d95565b60006064639bda07826116486001806002611d95565b60006064639bda07826116cb6002806001611d95565b60006064639bda078261174e60028080611d95565b60006064639bda07826117d26003806001611d95565b60006064639bda07826118586003806002611d95565b60006064639bda07826118de6004806001611d95565b60006064639bda07826119686004806002611d95565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b6090604401611330565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401611330565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401611330565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401611330565b6000816002811115611da957611da96120f4565b60ff166008846004811115611dc057611dc06120f4565b61ffff16901b61ffff166010866004811115611dde57611dde6120f4565b62ffffff16901b171760e81b949350505050565b604051610100810167ffffffffffffffff81118282101715611e3d577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b600060608284031215611e5557600080fd5b6040516060810181811067ffffffffffffffff82111715611e9f577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b80604052508235815260208301356020820152604083013560408201528091505092915050565b600060e08284031215611ed857600080fd5b60405160e0810181811067ffffffffffffffff82111715611f22577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250823581526020830135602082015260408301356040820152606083013560608201526080830135608082015260a083013560a082015260c083013560c08201528091505092915050565b600060a08284031215611f8357600080fd5b60405160a0810181811067ffffffffffffffff82111715611fcd577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b806040525082358152602083013560208201526040830135604082015260608301356060820152608083013560808201528091505092915050565b803560ff8116811461201957600080fd5b919050565b6000806040838503121561203157600080fd5b61203a83612008565b915061204860208401612008565b90509250929050565b600080600083850361014081121561206857600080fd5b6101008082121561207857600080fd5b612080611df2565b9150853582526020860135602083015260408601356040830152606086013560608301526080860135608083015260a086013560a083015260c086013560c083015260e086013560e08301528194506120da818701612008565b935050506120eb6101208501612008565b90509250925092565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60006020828403121561213557600080fd5b505191905056fea2646970667358221220b0bb60f8becf44d8165b2a7ce03d8b966a8c22e085331bd006c700309b02c8b264736f6c63430008130033";

type MinMaxTestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: MinMaxTestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class MinMaxTestsContract__factory extends ContractFactory {
  constructor(...args: MinMaxTestsContractConstructorParams) {
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
      MinMaxTestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): MinMaxTestsContract__factory {
    return super.connect(runner) as MinMaxTestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): MinMaxTestsContractInterface {
    return new Interface(_abi) as MinMaxTestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): MinMaxTestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as MinMaxTestsContract;
  }
}
