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
import type { NonPayableOverrides } from "../../../common";
import type {
  AccountOnboard,
  AccountOnboardInterface,
} from "../../../contracts/onboard/AccountOnboard";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "_from",
        type: "address",
      },
      {
        indexed: false,
        internalType: "bytes",
        name: "userKey",
        type: "bytes",
      },
    ],
    name: "AccountOnboarded",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "publicKey",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "signedEK",
        type: "bytes",
      },
    ],
    name: "onboardAccount",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b506106e0806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063afaea1bd14610030575b600080fd5b61004a60048036038101906100459190610329565b61004c565b005b600061005a858585856100b1565b90503373ffffffffffffffffffffffffffffffffffffffff167fb67504ecfeef0230a06f661ea388c2947b4125a35e918ebff5889e3553c29c04826040516100a2919061043a565b60405180910390a25050505050565b6060600085859050848490506100c79190610495565b67ffffffffffffffff8111156100e0576100df6104c9565b5b6040519080825280601f01601f1916602001820160405280156101125781602001600182028036833780820191505090505b50905060005b8484905081101561019557848482818110610136576101356104f8565b5b9050013560f81c60f81b828281518110610153576101526104f8565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a905350808061018d90610527565b915050610118565b5060005b86869050811015610224578686828181106101b7576101b66104f8565b5b9050013560f81c60f81b8282878790506101d19190610495565b815181106101e2576101e16104f8565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a905350808061021c90610527565b915050610199565b50606473ffffffffffffffffffffffffffffffffffffffff1663a85f0ca2826040518263ffffffff1660e01b815260040161025f919061043a565b600060405180830381865afa15801561027c573d6000803e3d6000fd5b505050506040513d6000823e3d601f19601f820116820180604052508101906102a59190610661565b915050949350505050565b6000604051905090565b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b60008083601f8401126102e9576102e86102c4565b5b8235905067ffffffffffffffff811115610306576103056102c9565b5b602083019150836001820283011115610322576103216102ce565b5b9250929050565b60008060008060408587031215610343576103426102ba565b5b600085013567ffffffffffffffff811115610361576103606102bf565b5b61036d878288016102d3565b9450945050602085013567ffffffffffffffff8111156103905761038f6102bf565b5b61039c878288016102d3565b925092505092959194509250565b600081519050919050565b600082825260208201905092915050565b60005b838110156103e45780820151818401526020810190506103c9565b60008484015250505050565b6000601f19601f8301169050919050565b600061040c826103aa565b61041681856103b5565b93506104268185602086016103c6565b61042f816103f0565b840191505092915050565b600060208201905081810360008301526104548184610401565b905092915050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006104a08261045c565b91506104ab8361045c565b92508282019050808211156104c3576104c2610466565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60006105328261045c565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361056457610563610466565b5b600182019050919050565b600080fd5b61057d826103f0565b810181811067ffffffffffffffff8211171561059c5761059b6104c9565b5b80604052505050565b60006105af6102b0565b90506105bb8282610574565b919050565b600067ffffffffffffffff8211156105db576105da6104c9565b5b6105e4826103f0565b9050602081019050919050565b60006106046105ff846105c0565b6105a5565b9050828152602081018484840111156106205761061f61056f565b5b61062b8482856103c6565b509392505050565b600082601f830112610648576106476102c4565b5b81516106588482602086016105f1565b91505092915050565b600060208284031215610677576106766102ba565b5b600082015167ffffffffffffffff811115610695576106946102bf565b5b6106a184828501610633565b9150509291505056fea2646970667358221220276a39f520680a4239ab659c07f82cf6855bbaa67f9ea867f90f1db78ff2186864736f6c63430008140033";

type AccountOnboardConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: AccountOnboardConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class AccountOnboard__factory extends ContractFactory {
  constructor(...args: AccountOnboardConstructorParams) {
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
      AccountOnboard & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): AccountOnboard__factory {
    return super.connect(runner) as AccountOnboard__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): AccountOnboardInterface {
    return new Interface(_abi) as AccountOnboardInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): AccountOnboard {
    return new Contract(address, _abi, runner) as unknown as AccountOnboard;
  }
}
