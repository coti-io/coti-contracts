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
import type { NonPayableOverrides } from "../../../../common";
import type {
  MpcCore,
  MpcCoreInterface,
} from "../../../../contracts/utils/mpc/MpcCore";

const _abi = [
  {
    inputs: [],
    name: "RSA_SIZE",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

const _bytecode =
  "0x6088610038600b82828239805160001a607314602b57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe730000000000000000000000000000000000000000301460806040526004361060335760003560e01c806331b943d5146038575b600080fd5b604061010081565b60405190815260200160405180910390f3fea2646970667358221220cf9b5c92cfd34eeb41890ad3bcec6ec15a59ccd6e8216e77664f7cfff771d88764736f6c63430008130033";

type MpcCoreConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: MpcCoreConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class MpcCore__factory extends ContractFactory {
  constructor(...args: MpcCoreConstructorParams) {
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
      MpcCore & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): MpcCore__factory {
    return super.connect(runner) as MpcCore__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): MpcCoreInterface {
    return new Interface(_abi) as MpcCoreInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): MpcCore {
    return new Contract(address, _abi, runner) as unknown as MpcCore;
  }
}
