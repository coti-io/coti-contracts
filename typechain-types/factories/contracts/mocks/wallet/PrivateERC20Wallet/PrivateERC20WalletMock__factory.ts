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
  PrivateERC20WalletMock,
  PrivateERC20WalletMockInterface,
} from "../../../../../contracts/mocks/wallet/PrivateERC20Wallet/PrivateERC20WalletMock";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "token",
        type: "address",
      },
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint64",
        name: "value",
        type: "uint64",
      },
    ],
    name: "approve",
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
        internalType: "address",
        name: "token",
        type: "address",
      },
      {
        internalType: "address",
        name: "accountEncryptionAddress",
        type: "address",
      },
    ],
    name: "setAccountEncryptionAddress",
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
        internalType: "address",
        name: "token",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint64",
        name: "value",
        type: "uint64",
      },
    ],
    name: "transfer",
    outputs: [
      {
        internalType: "gtBool",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "token",
        type: "address",
      },
      {
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint64",
        name: "value",
        type: "uint64",
      },
    ],
    name: "transferFrom",
    outputs: [
      {
        internalType: "gtBool",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b506108a3806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c80632a308b3a146100515780633ead9adb146100815780634a009211146100b1578063ce4ec16a146100e1575b600080fd5b61006b60048036038101906100669190610497565b610111565b604051610078919061052f565b60405180910390f35b61009b6004803603810190610096919061054a565b6101a2565b6040516100a8919061052f565b60405180910390f35b6100cb60048036038101906100c691906105b1565b610236565b6040516100d8919061060c565b60405180910390f35b6100fb60048036038101906100f69190610497565b6102bc565b604051610108919061060c565b60405180910390f35b60008373ffffffffffffffffffffffffffffffffffffffff1663a9059cbb846101398561034d565b6040518363ffffffff1660e01b8152600401610156929190610645565b6020604051808303816000875af1158015610175573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610199919061069a565b90509392505050565b60008473ffffffffffffffffffffffffffffffffffffffff166323b872dd85856101cb8661034d565b6040518463ffffffff1660e01b81526004016101e9939291906106c7565b6020604051808303816000875af1158015610208573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061022c919061069a565b9050949350505050565b60008273ffffffffffffffffffffffffffffffffffffffff16638269bcc3836040518263ffffffff1660e01b815260040161027191906106fe565b6020604051808303816000875af1158015610290573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102b49190610745565b905092915050565b60008373ffffffffffffffffffffffffffffffffffffffff1663095ea7b3846102e48561034d565b6040518363ffffffff1660e01b8152600401610301929190610645565b6020604051808303816000875af1158015610320573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906103449190610745565b90509392505050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b6060048081111561037f5761037e610772565b5b60f81b8467ffffffffffffffff166040518363ffffffff1660e01b81526004016103aa9291906107eb565b6020604051808303816000875af11580156103c9573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906103ed9190610840565b9050919050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610424826103f9565b9050919050565b61043481610419565b811461043f57600080fd5b50565b6000813590506104518161042b565b92915050565b600067ffffffffffffffff82169050919050565b61047481610457565b811461047f57600080fd5b50565b6000813590506104918161046b565b92915050565b6000806000606084860312156104b0576104af6103f4565b5b60006104be86828701610442565b93505060206104cf86828701610442565b92505060406104e086828701610482565b9150509250925092565b6000819050919050565b6000819050919050565b600061051961051461050f846104ea565b6104f4565b6104ea565b9050919050565b610529816104fe565b82525050565b60006020820190506105446000830184610520565b92915050565b60008060008060808587031215610564576105636103f4565b5b600061057287828801610442565b945050602061058387828801610442565b935050604061059487828801610442565b92505060606105a587828801610482565b91505092959194509250565b600080604083850312156105c8576105c76103f4565b5b60006105d685828601610442565b92505060206105e785828601610442565b9150509250929050565b60008115159050919050565b610606816105f1565b82525050565b600060208201905061062160008301846105fd565b92915050565b61063081610419565b82525050565b61063f816104fe565b82525050565b600060408201905061065a6000830185610627565b6106676020830184610636565b9392505050565b610677816104ea565b811461068257600080fd5b50565b6000815190506106948161066e565b92915050565b6000602082840312156106b0576106af6103f4565b5b60006106be84828501610685565b91505092915050565b60006060820190506106dc6000830186610627565b6106e96020830185610627565b6106f66040830184610636565b949350505050565b60006020820190506107136000830184610627565b92915050565b610722816105f1565b811461072d57600080fd5b50565b60008151905061073f81610719565b92915050565b60006020828403121561075b5761075a6103f4565b5b600061076984828501610730565b91505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60007fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b6107d6816107a1565b82525050565b6107e5816104ea565b82525050565b600060408201905061080060008301856107cd565b61080d60208301846107dc565b9392505050565b61081d816104ea565b811461082857600080fd5b50565b60008151905061083a81610814565b92915050565b600060208284031215610856576108556103f4565b5b60006108648482850161082b565b9150509291505056fea264697066735822122019a19cd29aecdfb0afc31afc9577617252449274a501ff1e2d08d7cf3ca1f7cf64736f6c63430008140033";

type PrivateERC20WalletMockConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: PrivateERC20WalletMockConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class PrivateERC20WalletMock__factory extends ContractFactory {
  constructor(...args: PrivateERC20WalletMockConstructorParams) {
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
      PrivateERC20WalletMock & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): PrivateERC20WalletMock__factory {
    return super.connect(runner) as PrivateERC20WalletMock__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): PrivateERC20WalletMockInterface {
    return new Interface(_abi) as PrivateERC20WalletMockInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): PrivateERC20WalletMock {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as PrivateERC20WalletMock;
  }
}
