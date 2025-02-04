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
  ShiftTestsContract,
  ShiftTestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/ShiftTestsContract";

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
        internalType: "struct ShiftTestsContract.Check16",
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
        internalType: "struct ShiftTestsContract.Check32",
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
        internalType: "struct ShiftTestsContract.Check64",
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
    name: "getAllShiftResults",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
      {
        internalType: "uint16",
        name: "",
        type: "uint16",
      },
      {
        internalType: "uint32",
        name: "",
        type: "uint32",
      },
      {
        internalType: "uint64",
        name: "",
        type: "uint64",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getResult",
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
        internalType: "struct ShiftTestsContract.AllGTCastingValues",
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
    name: "shlTest",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
      {
        internalType: "uint16",
        name: "",
        type: "uint16",
      },
      {
        internalType: "uint32",
        name: "",
        type: "uint32",
      },
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
    name: "shrTest",
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
  "0x608060405234801561001057600080fd5b506112a0806100206000396000f3fe608060405234801561001057600080fd5b50600436106100885760003560e01c8063d2becd381161005b578063d2becd381461015b578063de2927891461019c578063ebb571fd146101b5578063ee49a6ea146101ca57600080fd5b806308e9d12a1461008d5780632e544aa0146100e157806380f937bc14610107578063acb3816914610133575b600080fd5b6100a061009b366004610f36565b6101dd565b6040805160ff909516855261ffff909316602085015263ffffffff9091169183019190915267ffffffffffffffff1660608201526080015b60405180910390f35b6100f46100ef366004610fba565b61037f565b60405161ffff90911681526020016100d8565b61011a61011536600461103d565b610484565b60405167ffffffffffffffff90911681526020016100d8565b6101466101413660046110e8565b610641565b60405163ffffffff90911681526020016100d8565b600054610100810460ff169062010000810461ffff1690640100000000810463ffffffff169068010000000000000000900467ffffffffffffffff166100a0565b60005460ff165b60405160ff90911681526020016100d8565b6101c86101c336600461117f565b610788565b005b6101a36101d8366004610f36565b61080f565b60008060008061022b60405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610236818888610788565b61024c610247826000015188610996565b610a5f565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1661010060ff9384160217905560408201516102989161029391908916610afc565b610b80565b600060026101000a81548161ffff021916908361ffff1602179055506102cd6102c882608001518860ff16610b90565b610c16565b600060046101000a81548163ffffffff021916908363ffffffff1602179055506103066103018260c001518860ff16610c26565b610cb0565b600080547fffffffffffffffffffffffffffffffff0000000000000000ffffffffffffffff166801000000000000000067ffffffffffffffff93841681029190911791829055610100820460ff169a62010000830461ffff169a50640100000000830463ffffffff169950910490911695509350505050565b60008061038f8360000151610b80565b905061039e8360200151610b80565b61ffff168161ffff161480156103c757506103bc8360400151610b80565b61ffff168161ffff16145b61047e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a4015b60405180910390fd5b92915050565b6000806104948360000151610cb0565b90506104a38360200151610cb0565b67ffffffffffffffff168167ffffffffffffffff161480156104e457506104cd8360400151610cb0565b67ffffffffffffffff168167ffffffffffffffff16145b801561050f57506104f88360800151610cb0565b67ffffffffffffffff168167ffffffffffffffff16145b801561053a57506105238360600151610cb0565b67ffffffffffffffff168167ffffffffffffffff16145b8015610565575061054e8360c00151610cb0565b67ffffffffffffffff168167ffffffffffffffff16145b80156103c757506105798360a00151610cb0565b67ffffffffffffffff168167ffffffffffffffff161461047e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a401610475565b6000806106518360000151610c16565b90506106608360200151610c16565b63ffffffff168163ffffffff1614801561069157506106828360400151610c16565b63ffffffff168163ffffffff16145b80156106b457506106a58360800151610c16565b63ffffffff168163ffffffff16145b80156103c757506106c88360600151610c16565b63ffffffff168163ffffffff161461047e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152604660248201527f64656372797074416e64436f6d70617265416c6c526573756c74733a2046616960448201527f6c656420746f206465637279707420616e6420636f6d7061726520616c6c207260648201527f6573756c74730000000000000000000000000000000000000000000000000000608482015260a401610475565b61079182610cc0565b835261079c81610cc0565b60208401526107ad60ff8316610d29565b60408401526107be60ff8216610d29565b60608401526107cf60ff8316610d93565b60808401526107e060ff8216610d93565b60a08401526107f160ff8316610dff565b60c084015261080260ff8216610dff565b60e0909301929092525050565b600061085960405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610864818585610788565b610875610247826000015185610e6f565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff92831617905560408201516108b89161029391908616610e85565b60005460ff1661ffff919091161480156108f257506108e16102c882608001518560ff16610e9b565b60005460ff1663ffffffff91909116145b8015610922575061090d6103018260c001518560ff16610eb1565b60005460ff1667ffffffffffffffff91909116145b610988576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600e60248201527f73687254657374206661696c65640000000000000000000000000000000000006044820152606401610475565b505060005460ff1692915050565b60006064631135f71a6109ac6001806002610ec3565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905260ff851660448201526064015b6020604051808303816000875af1158015610a34573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a589190611222565b9392505050565b60006064630cfed56160015b60f81b846040518363ffffffff1660e01b8152600401610ab99291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af1158015610ad8573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061047e9190611222565b60006064631135f71a610b126002600181610ec3565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905261ffff85166044820152606401610a15565b60006064630cfed5616002610a6b565b60006064631135f71a610ba66003806002610ec3565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905263ffffffff85166044820152606401610a15565b60006064630cfed5616003610a6b565b60006064631135f71a610c3c6004806002610ec3565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905267ffffffffffffffff85166044820152606401610a15565b60006064630cfed5616004610a6b565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b6090604401610ab9565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401610ab9565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401610ab9565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401610ab9565b600060646339bd1d8d6109ac6001806002610ec3565b600060646339bd1d8d610b126002600181610ec3565b600060646339bd1d8d610ba66003806002610ec3565b600060646339bd1d8d610c3c60048060025b6000816002811115610ed757610ed761123b565b60ff166008846004811115610eee57610eee61123b565b61ffff16901b61ffff166010866004811115610f0c57610f0c61123b565b62ffffff16901b171760e81b949350505050565b803560ff81168114610f3157600080fd5b919050565b60008060408385031215610f4957600080fd5b610f5283610f20565b9150610f6060208401610f20565b90509250929050565b604051610100810167ffffffffffffffff81118282101715610fb4577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405290565b600060608284031215610fcc57600080fd5b6040516060810181811067ffffffffffffffff82111715611016577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b80604052508235815260208301356020820152604083013560408201528091505092915050565b600060e0828403121561104f57600080fd5b60405160e0810181811067ffffffffffffffff82111715611099577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250823581526020830135602082015260408301356040820152606083013560608201526080830135608082015260a083013560a082015260c083013560c08201528091505092915050565b600060a082840312156110fa57600080fd5b60405160a0810181811067ffffffffffffffff82111715611144577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b806040525082358152602083013560208201526040830135604082015260608301356060820152608083013560808201528091505092915050565b600080600083850361014081121561119657600080fd5b610100808212156111a657600080fd5b6111ae610f69565b9150853582526020860135602083015260408601356040830152606086013560608301526080860135608083015260a086013560a083015260c086013560c083015260e086013560e0830152819450611208818701610f20565b935050506112196101208501610f20565b90509250925092565b60006020828403121561123457600080fd5b5051919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fdfea2646970667358221220788e3cce9b136e416d79286b2cd5720cbe2f466106ff84734c5e9ba3b65a02f964736f6c63430008130033";

type ShiftTestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: ShiftTestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class ShiftTestsContract__factory extends ContractFactory {
  constructor(...args: ShiftTestsContractConstructorParams) {
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
      ShiftTestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): ShiftTestsContract__factory {
    return super.connect(runner) as ShiftTestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): ShiftTestsContractInterface {
    return new Interface(_abi) as ShiftTestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): ShiftTestsContract {
    return new Contract(address, _abi, runner) as unknown as ShiftTestsContract;
  }
}
