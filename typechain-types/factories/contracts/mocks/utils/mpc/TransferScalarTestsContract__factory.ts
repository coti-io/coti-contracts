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
  TransferScalarTestsContract,
  TransferScalarTestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/TransferScalarTestsContract";

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
        internalType: "struct TransferScalarTestsContract.AllGTCastingValues",
        name: "allGTCastingValues",
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
        name: "amount",
        type: "uint8",
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
        internalType: "struct TransferScalarTestsContract.AllGTCastingValues",
        name: "allGTCastingValues",
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
        name: "amount",
        type: "uint8",
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
        internalType: "struct TransferScalarTestsContract.AllGTCastingValues",
        name: "allGTCastingValues",
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
        name: "amount",
        type: "uint8",
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
    name: "transferScalarTest",
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
  "0x608060405234801561001057600080fd5b506116ae806100206000396000f3fe608060405234801561001057600080fd5b50600436106100675760003560e01c806352fdcece1161005057806352fdcece146100c1578063df6d2101146100d4578063ea8fe3d5146100e757600080fd5b806319902cb11461006c5780634717f97c14610081575b600080fd5b61007f61007a3660046114b2565b6100fa565b005b60005460ff80821691610100810482169162010000909104165b6040805160ff948516815293909216602084015215159082015260600160405180910390f35b61007f6100cf3660046114b2565b61065b565b61009b6100e23660046115bf565b610823565b61007f6100f53660046114b2565b610a40565b60008060006101158860c001518960e001518660ff16610d88565b92509250925061012483610e51565b67ffffffffffffffff168760ff16148015610153575061014382610e51565b67ffffffffffffffff168660ff16145b801561016a575061016381610ef4565b1515851515145b6101c55760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084015b60405180910390fd5b6101db88600001518960e001518660ff16610f85565b919450925090506101eb83610e51565b67ffffffffffffffff168760ff1614801561021a575061020a82610e51565b67ffffffffffffffff168660ff16145b8015610231575061022a81610ef4565b1515851515145b6102875760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b61029d8860c0015189602001518660ff16610fa1565b919450925090506102ad83610e51565b67ffffffffffffffff168760ff161480156102dc57506102cc82610e51565b67ffffffffffffffff168660ff16145b80156102f357506102ec81610ef4565b1515851515145b6103495760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b61035f88604001518960e001518660ff16610fbd565b9194509250905061036f83610e51565b67ffffffffffffffff168760ff1614801561039e575061038e82610e51565b67ffffffffffffffff168660ff16145b80156103b557506103ae81610ef4565b1515851515145b61040b5760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b6104218860c0015189606001518660ff16610fda565b9194509250905061043183610e51565b67ffffffffffffffff168760ff16148015610460575061045082610e51565b67ffffffffffffffff168660ff16145b8015610477575061047081610ef4565b1515851515145b6104cd5760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b6104e388608001518960e001518660ff16610ff7565b919450925090506104f383610e51565b67ffffffffffffffff168760ff16148015610522575061051282610e51565b67ffffffffffffffff168660ff16145b8015610539575061053281610ef4565b1515851515145b61058f5760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b6105a58860c001518960a001518660ff16611014565b919450925090506105b583610e51565b67ffffffffffffffff168760ff161480156105e457506105d482610e51565b67ffffffffffffffff168660ff16145b80156105fb57506105f481610ef4565b1515851515145b6106515760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b5050505050505050565b6000806000610676886040015189606001518660ff16611031565b925092509250610685836110a3565b61ffff168760ff161480156106a8575061069e826110a3565b61ffff168660ff16145b80156106bf57506106b881610ef4565b1515851515145b6107155760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b61072b886000015189606001518660ff166110b3565b9194509250905061073b836110a3565b61ffff168760ff1614801561075e5750610754826110a3565b61ffff168660ff16145b8015610775575061076e81610ef4565b1515851515145b6107cb5760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b6107e1886040015189602001518660ff166110cf565b919450925090506107f1836110a3565b61ffff168760ff161480156105e4575061080a826110a3565b61ffff168660ff161480156105fb57506105f481610ef4565b600080600061087060405180610100016040528060008152602001600081526020016000815260200160008152602001600081526020016000815260200160008152602001600081525090565b610879876110eb565b8152610884866110eb565b602082015261089560ff8816611154565b60408201526108a660ff8716611154565b60608201526108b760ff88166111be565b60808201526108c860ff87166111be565b60a08201526108d960ff881661122a565b60c08201526108ea60ff871661122a565b60e08201528051602082015160009182918291610907918a61129a565b9250925092506109168361130a565b600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff929092169190911790556109518261130a565b600060016101000a81548160ff021916908360ff16021790555061097481610ef4565b60008054911515620100009081027fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ffff84168117928390556109cf93889360ff928316918316919091179261010082048316929104168c61065b565b6000546109f490859060ff80821691610100810482169162010000909104168c610a40565b600054610a1990859060ff80821691610100810482169162010000909104168c6100fa565b505060005460ff8082169a610100830482169a506201000090920416975095505050505050565b6000806000610a5b88608001518960a001518660ff1661131a565b925092509250610a6a8361138e565b63ffffffff168760ff16148015610a915750610a858261138e565b63ffffffff168660ff16145b8015610aa85750610aa181610ef4565b1515851515145b610afe5760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b610b1488600001518960a001518660ff1661139e565b91945092509050610b248361138e565b63ffffffff168760ff16148015610b4b5750610b3f8261138e565b63ffffffff168660ff16145b8015610b625750610b5b81610ef4565b1515851515145b610bb85760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b610bce886080015189602001518660ff166113ba565b91945092509050610bde8361138e565b63ffffffff168760ff16148015610c055750610bf98261138e565b63ffffffff168660ff16145b8015610c1c5750610c1581610ef4565b1515851515145b610c725760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b610c8888604001518960a001518660ff166113d6565b91945092509050610c988361138e565b63ffffffff168760ff16148015610cbf5750610cb38261138e565b63ffffffff168660ff16145b8015610cd65750610ccf81610ef4565b1515851515145b610d2c5760405162461bcd60e51b815260206004820152602160248201527f7472616e73666572546573743a20636865636b207363616c6172206661696c656044820152601960fa1b60648201526084016101bc565b610d42886080015189606001518660ff166113f3565b91945092509050610d528361138e565b63ffffffff168760ff161480156105e45750610d6d8261138e565b63ffffffff168660ff161480156105fb57506105f481610ef4565b6000808080808060646356c72d28610da460048080600161140c565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b81168252919091166004820152602481018c9052604481018b905267ffffffffffffffff8a1660648201526084015b6060604051808303816000875af1158015610e1b573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610e3f9190611602565b919b909a509098509650505050505050565b60006064630cfed56160045b60f81b846040518363ffffffff1660e01b8152600401610eab9291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af1158015610eca573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610eee919061165f565b92915050565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015610f58573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610f7c919061165f565b15159392505050565b6000808080808060646356c72d28610da460016004808261140c565b6000808080808060646356c72d28610da460046001818161140c565b6000808080808060646356c72d28610da46002600480600161140c565b6000808080808060646356c72d28610da46004600281600161140c565b6000808080808060646356c72d28610da46003600480600161140c565b6000808080808060646356c72d28610da46004600381600161140c565b6000808080808060646356c72d2861104d60028080600161140c565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b81168252919091166004820152602481018c9052604481018b905261ffff8a166064820152608401610dfc565b60006064630cfed5616002610e5d565b6000808080808060646356c72d2861104d60016002808261140c565b6000808080808060646356c72d2861104d60026001818161140c565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0100000000000000000000000000000000000000000000000000000000000000600482015260ff8216602482015260009060649063d9b60b6090604401610eab565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0200000000000000000000000000000000000000000000000000000000000000600482015261ffff8216602482015260009060649063d9b60b6090604401610eab565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0300000000000000000000000000000000000000000000000000000000000000600482015263ffffffff8216602482015260009060649063d9b60b6090604401610eab565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401610eab565b6000808080808060646356c72d286112b5600180808061140c565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b81168252919091166004820152602481018c9052604481018b905260ff8a166064820152608401610dfc565b60006064630cfed5616001610e5d565b6000808080808060646356c72d2861133660038080600161140c565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b81168252919091166004820152602481018c9052604481018b905263ffffffff8a166064820152608401610dfc565b60006064630cfed5616003610e5d565b6000808080808060646356c72d2861133660016003808261140c565b6000808080808060646356c72d2861133660036001818161140c565b6000808080808060646356c72d286113366002600380600161140c565b6000808080808060646356c72d28611336600360028160015b600081600281111561142057611420611630565b60ff16600884600481111561143757611437611630565b61ffff16901b61ffff16601086600481111561145557611455611630565b62ffffff16901b62ffffff16601888600481111561147557611475611630565b63ffffffff16901b17171760e01b95945050505050565b803560ff8116811461149d57600080fd5b919050565b8035801515811461149d57600080fd5b60008060008060008587036101808112156114cc57600080fd5b610100808212156114dc57600080fd5b604051915080820182811067ffffffffffffffff82111715611527577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b8060405250873582526020880135602083015260408801356040830152606088013560608301526080880135608083015260a088013560a083015260c088013560c083015260e088013560e083015281965061158481890161148c565b95505050611595610120870161148c565b92506115a461014087016114a2565b91506115b3610160870161148c565b90509295509295909350565b6000806000606084860312156115d457600080fd5b6115dd8461148c565b92506115eb6020850161148c565b91506115f96040850161148c565b90509250925092565b60008060006060848603121561161757600080fd5b8351925060208401519150604084015190509250925092565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60006020828403121561167157600080fd5b505191905056fea26469706673582212207d6da12162dd0dbd7639da0405ba74b4b47af37b31a65c617ccdeef4c3dc791064736f6c63430008130033";

type TransferScalarTestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: TransferScalarTestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class TransferScalarTestsContract__factory extends ContractFactory {
  constructor(...args: TransferScalarTestsContractConstructorParams) {
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
      TransferScalarTestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): TransferScalarTestsContract__factory {
    return super.connect(runner) as TransferScalarTestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TransferScalarTestsContractInterface {
    return new Interface(_abi) as TransferScalarTestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): TransferScalarTestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as TransferScalarTestsContract;
  }
}
