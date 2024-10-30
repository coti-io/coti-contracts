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

export declare namespace MinMaxTestsContract {
  export type Check16Struct = {
    res16_16: BigNumberish;
    res8_16: BigNumberish;
    res16_8: BigNumberish;
  };

  export type Check16StructOutput = [
    res16_16: bigint,
    res8_16: bigint,
    res16_8: bigint
  ] & { res16_16: bigint; res8_16: bigint; res16_8: bigint };

  export type Check32Struct = {
    res32_32: BigNumberish;
    res8_32: BigNumberish;
    res32_8: BigNumberish;
    res16_32: BigNumberish;
    res32_16: BigNumberish;
  };

  export type Check32StructOutput = [
    res32_32: bigint,
    res8_32: bigint,
    res32_8: bigint,
    res16_32: bigint,
    res32_16: bigint
  ] & {
    res32_32: bigint;
    res8_32: bigint;
    res32_8: bigint;
    res16_32: bigint;
    res32_16: bigint;
  };

  export type Check64Struct = {
    res64_64: BigNumberish;
    res8_64: BigNumberish;
    res64_8: BigNumberish;
    res16_64: BigNumberish;
    res64_16: BigNumberish;
    res32_64: BigNumberish;
    res64_32: BigNumberish;
  };

  export type Check64StructOutput = [
    res64_64: bigint,
    res8_64: bigint,
    res64_8: bigint,
    res16_64: bigint,
    res64_16: bigint,
    res32_64: bigint,
    res64_32: bigint
  ] & {
    res64_64: bigint;
    res8_64: bigint;
    res64_8: bigint;
    res16_64: bigint;
    res64_16: bigint;
    res32_64: bigint;
    res64_32: bigint;
  };

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
}

export interface MinMaxTestsContractInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "decryptAndCompareResults16"
      | "decryptAndCompareResults32"
      | "decryptAndCompareResults64"
      | "getMaxResult"
      | "getMinResult"
      | "maxTest"
      | "minTest"
      | "setPublicValues"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "decryptAndCompareResults16",
    values: [MinMaxTestsContract.Check16Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "decryptAndCompareResults32",
    values: [MinMaxTestsContract.Check32Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "decryptAndCompareResults64",
    values: [MinMaxTestsContract.Check64Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "getMaxResult",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "getMinResult",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "maxTest",
    values: [BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "minTest",
    values: [BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "setPublicValues",
    values: [
      MinMaxTestsContract.AllGTCastingValuesStruct,
      BigNumberish,
      BigNumberish
    ]
  ): string;

  decodeFunctionResult(
    functionFragment: "decryptAndCompareResults16",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "decryptAndCompareResults32",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "decryptAndCompareResults64",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getMaxResult",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getMinResult",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "maxTest", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "minTest", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "setPublicValues",
    data: BytesLike
  ): Result;
}

export interface MinMaxTestsContract extends BaseContract {
  connect(runner?: ContractRunner | null): MinMaxTestsContract;
  waitForDeployment(): Promise<this>;

  interface: MinMaxTestsContractInterface;

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

  decryptAndCompareResults16: TypedContractMethod<
    [check16: MinMaxTestsContract.Check16Struct],
    [bigint],
    "nonpayable"
  >;

  decryptAndCompareResults32: TypedContractMethod<
    [check32: MinMaxTestsContract.Check32Struct],
    [bigint],
    "nonpayable"
  >;

  decryptAndCompareResults64: TypedContractMethod<
    [check64: MinMaxTestsContract.Check64Struct],
    [bigint],
    "nonpayable"
  >;

  getMaxResult: TypedContractMethod<[], [bigint], "view">;

  getMinResult: TypedContractMethod<[], [bigint], "view">;

  maxTest: TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  minTest: TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  setPublicValues: TypedContractMethod<
    [
      castingValues: MinMaxTestsContract.AllGTCastingValuesStruct,
      a: BigNumberish,
      b: BigNumberish
    ],
    [void],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "decryptAndCompareResults16"
  ): TypedContractMethod<
    [check16: MinMaxTestsContract.Check16Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "decryptAndCompareResults32"
  ): TypedContractMethod<
    [check32: MinMaxTestsContract.Check32Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "decryptAndCompareResults64"
  ): TypedContractMethod<
    [check64: MinMaxTestsContract.Check64Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "getMaxResult"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "getMinResult"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "maxTest"
  ): TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "minTest"
  ): TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "setPublicValues"
  ): TypedContractMethod<
    [
      castingValues: MinMaxTestsContract.AllGTCastingValuesStruct,
      a: BigNumberish,
      b: BigNumberish
    ],
    [void],
    "nonpayable"
  >;

  filters: {};
}
