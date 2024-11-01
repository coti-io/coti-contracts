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
} from "../../../../common";

export declare namespace TransferTestsContract {
  export type AllGTCastingValuesStruct = {
    a8_s: BigNumberish;
    b8_s: BigNumberish;
    a16_s: BigNumberish;
    b16_s: BigNumberish;
    a32_s: BigNumberish;
    b32_s: BigNumberish;
    a64_s: BigNumberish;
    b64_s: BigNumberish;
  };

  export type AllGTCastingValuesStructOutput = [
    a8_s: bigint,
    b8_s: bigint,
    a16_s: bigint,
    b16_s: bigint,
    a32_s: bigint,
    b32_s: bigint,
    a64_s: bigint,
    b64_s: bigint
  ] & {
    a8_s: bigint;
    b8_s: bigint;
    a16_s: bigint;
    b16_s: bigint;
    a32_s: bigint;
    b32_s: bigint;
    a64_s: bigint;
    b64_s: bigint;
  };

  export type AllAmountValuesStruct = {
    amount8_s: BigNumberish;
    amount16_s: BigNumberish;
    amount32_s: BigNumberish;
    amount64_s: BigNumberish;
    amount: BigNumberish;
  };

  export type AllAmountValuesStructOutput = [
    amount8_s: bigint,
    amount16_s: bigint,
    amount32_s: bigint,
    amount64_s: bigint,
    amount: bigint
  ] & {
    amount8_s: bigint;
    amount16_s: bigint;
    amount32_s: bigint;
    amount64_s: bigint;
    amount: bigint;
  };
}

export interface TransferTestsContractInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "computeAndChekTransfer16"
      | "computeAndChekTransfer32"
      | "computeAndChekTransfer64"
      | "getResults"
      | "transferTest"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "computeAndChekTransfer16",
    values: [
      TransferTestsContract.AllGTCastingValuesStruct,
      TransferTestsContract.AllAmountValuesStruct,
      BigNumberish,
      BigNumberish,
      boolean
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "computeAndChekTransfer32",
    values: [
      TransferTestsContract.AllGTCastingValuesStruct,
      TransferTestsContract.AllAmountValuesStruct,
      BigNumberish,
      BigNumberish,
      boolean
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "computeAndChekTransfer64",
    values: [
      TransferTestsContract.AllGTCastingValuesStruct,
      TransferTestsContract.AllAmountValuesStruct,
      BigNumberish,
      BigNumberish,
      boolean
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "getResults",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "transferTest",
    values: [BigNumberish, BigNumberish, BigNumberish]
  ): string;

  decodeFunctionResult(
    functionFragment: "computeAndChekTransfer16",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "computeAndChekTransfer32",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "computeAndChekTransfer64",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "getResults", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "transferTest",
    data: BytesLike
  ): Result;
}

export interface TransferTestsContract extends BaseContract {
  connect(runner?: ContractRunner | null): TransferTestsContract;
  waitForDeployment(): Promise<this>;

  interface: TransferTestsContractInterface;

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

  computeAndChekTransfer16: TypedContractMethod<
    [
      allGTCastingValues: TransferTestsContract.AllGTCastingValuesStruct,
      allAmountValues: TransferTestsContract.AllAmountValuesStruct,
      new_a: BigNumberish,
      new_b: BigNumberish,
      res: boolean
    ],
    [void],
    "nonpayable"
  >;

  computeAndChekTransfer32: TypedContractMethod<
    [
      allGTCastingValues: TransferTestsContract.AllGTCastingValuesStruct,
      allAmountValues: TransferTestsContract.AllAmountValuesStruct,
      new_a: BigNumberish,
      new_b: BigNumberish,
      res: boolean
    ],
    [void],
    "nonpayable"
  >;

  computeAndChekTransfer64: TypedContractMethod<
    [
      allGTCastingValues: TransferTestsContract.AllGTCastingValuesStruct,
      allAmountValues: TransferTestsContract.AllAmountValuesStruct,
      new_a: BigNumberish,
      new_b: BigNumberish,
      res: boolean
    ],
    [void],
    "nonpayable"
  >;

  getResults: TypedContractMethod<[], [[bigint, bigint, boolean]], "view">;

  transferTest: TypedContractMethod<
    [a: BigNumberish, b: BigNumberish, amount: BigNumberish],
    [[bigint, bigint, boolean]],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "computeAndChekTransfer16"
  ): TypedContractMethod<
    [
      allGTCastingValues: TransferTestsContract.AllGTCastingValuesStruct,
      allAmountValues: TransferTestsContract.AllAmountValuesStruct,
      new_a: BigNumberish,
      new_b: BigNumberish,
      res: boolean
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "computeAndChekTransfer32"
  ): TypedContractMethod<
    [
      allGTCastingValues: TransferTestsContract.AllGTCastingValuesStruct,
      allAmountValues: TransferTestsContract.AllAmountValuesStruct,
      new_a: BigNumberish,
      new_b: BigNumberish,
      res: boolean
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "computeAndChekTransfer64"
  ): TypedContractMethod<
    [
      allGTCastingValues: TransferTestsContract.AllGTCastingValuesStruct,
      allAmountValues: TransferTestsContract.AllAmountValuesStruct,
      new_a: BigNumberish,
      new_b: BigNumberish,
      res: boolean
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "getResults"
  ): TypedContractMethod<[], [[bigint, bigint, boolean]], "view">;
  getFunction(
    nameOrSignature: "transferTest"
  ): TypedContractMethod<
    [a: BigNumberish, b: BigNumberish, amount: BigNumberish],
    [[bigint, bigint, boolean]],
    "nonpayable"
  >;

  filters: {};
}
