/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumberish,
  BytesLike,
  FunctionFragment,
  Result,
  Interface,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedListener,
  TypedContractMethod,
} from "../../../../../common";

export interface TransferWithAllowanceTestsContractInterface extends Interface {
  getFunction(
    nameOrSignature: "getResults" | "transferWithAllowanceTest"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "getResults",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "transferWithAllowanceTest",
    values: [BigNumberish, BigNumberish, BigNumberish, BigNumberish]
  ): string;

  decodeFunctionResult(functionFragment: "getResults", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "transferWithAllowanceTest",
    data: BytesLike
  ): Result;
}

export interface TransferWithAllowanceTestsContract extends BaseContract {
  connect(runner?: ContractRunner | null): TransferWithAllowanceTestsContract;
  waitForDeployment(): Promise<this>;

  interface: TransferWithAllowanceTestsContractInterface;

  queryFilter<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;
  queryFilter<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;

  on<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  on<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  once<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  once<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  listeners<TCEvent extends TypedContractEvent>(
    event: TCEvent
  ): Promise<Array<TypedListener<TCEvent>>>;
  listeners(eventName?: string): Promise<Array<Listener>>;
  removeAllListeners<TCEvent extends TypedContractEvent>(
    event?: TCEvent
  ): Promise<this>;

  getResults: TypedContractMethod<
    [],
    [[bigint, bigint, boolean, bigint]],
    "view"
  >;

  transferWithAllowanceTest: TypedContractMethod<
    [
      a: BigNumberish,
      b: BigNumberish,
      amount: BigNumberish,
      allowance: BigNumberish
    ],
    [[bigint, bigint, boolean, bigint]],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "getResults"
  ): TypedContractMethod<[], [[bigint, bigint, boolean, bigint]], "view">;
  getFunction(
    nameOrSignature: "transferWithAllowanceTest"
  ): TypedContractMethod<
    [
      a: BigNumberish,
      b: BigNumberish,
      amount: BigNumberish,
      allowance: BigNumberish
    ],
    [[bigint, bigint, boolean, bigint]],
    "nonpayable"
  >;

  filters: {};
}
