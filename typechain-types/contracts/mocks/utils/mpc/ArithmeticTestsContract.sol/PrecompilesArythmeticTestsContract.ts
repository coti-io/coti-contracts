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

export declare namespace PrecompilesArythmeticTestsContract {
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

export interface PrecompilesArythmeticTestsContractInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "addTest"
      | "decryptAndCompareResults16"
      | "decryptAndCompareResults32"
      | "decryptAndCompareResults64"
      | "getAddResult"
      | "getMulResult"
      | "getSubResult"
      | "mulTest"
      | "setPublicValues"
      | "subTest"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "addTest",
    values: [BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "decryptAndCompareResults16",
    values: [PrecompilesArythmeticTestsContract.Check16Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "decryptAndCompareResults32",
    values: [PrecompilesArythmeticTestsContract.Check32Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "decryptAndCompareResults64",
    values: [PrecompilesArythmeticTestsContract.Check64Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "getAddResult",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "getMulResult",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "getSubResult",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "mulTest",
    values: [BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "setPublicValues",
    values: [
      PrecompilesArythmeticTestsContract.AllGTCastingValuesStruct,
      BigNumberish,
      BigNumberish
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "subTest",
    values: [BigNumberish, BigNumberish]
  ): string;

  decodeFunctionResult(functionFragment: "addTest", data: BytesLike): Result;
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
    functionFragment: "getAddResult",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getMulResult",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getSubResult",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "mulTest", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "setPublicValues",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "subTest", data: BytesLike): Result;
}

export interface PrecompilesArythmeticTestsContract extends BaseContract {
  connect(runner?: ContractRunner | null): PrecompilesArythmeticTestsContract;
  waitForDeployment(): Promise<this>;

  interface: PrecompilesArythmeticTestsContractInterface;

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

  addTest: TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  decryptAndCompareResults16: TypedContractMethod<
    [check16: PrecompilesArythmeticTestsContract.Check16Struct],
    [bigint],
    "nonpayable"
  >;

  decryptAndCompareResults32: TypedContractMethod<
    [check32: PrecompilesArythmeticTestsContract.Check32Struct],
    [bigint],
    "nonpayable"
  >;

  decryptAndCompareResults64: TypedContractMethod<
    [check64: PrecompilesArythmeticTestsContract.Check64Struct],
    [bigint],
    "nonpayable"
  >;

  getAddResult: TypedContractMethod<[], [bigint], "view">;

  getMulResult: TypedContractMethod<[], [bigint], "view">;

  getSubResult: TypedContractMethod<[], [bigint], "view">;

  mulTest: TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  setPublicValues: TypedContractMethod<
    [
      castingValues: PrecompilesArythmeticTestsContract.AllGTCastingValuesStruct,
      a: BigNumberish,
      b: BigNumberish
    ],
    [void],
    "nonpayable"
  >;

  subTest: TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "addTest"
  ): TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "decryptAndCompareResults16"
  ): TypedContractMethod<
    [check16: PrecompilesArythmeticTestsContract.Check16Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "decryptAndCompareResults32"
  ): TypedContractMethod<
    [check32: PrecompilesArythmeticTestsContract.Check32Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "decryptAndCompareResults64"
  ): TypedContractMethod<
    [check64: PrecompilesArythmeticTestsContract.Check64Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "getAddResult"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "getMulResult"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "getSubResult"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "mulTest"
  ): TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "setPublicValues"
  ): TypedContractMethod<
    [
      castingValues: PrecompilesArythmeticTestsContract.AllGTCastingValuesStruct,
      a: BigNumberish,
      b: BigNumberish
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "subTest"
  ): TypedContractMethod<
    [a: BigNumberish, b: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  filters: {};
}
