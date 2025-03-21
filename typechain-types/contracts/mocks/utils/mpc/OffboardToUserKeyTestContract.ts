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
  AddressLike,
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

export interface OffboardToUserKeyTestContractInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "getCTs"
      | "getCt"
      | "getOnboardOffboardResult"
      | "getUserKeyShares"
      | "getUserKeyTest"
      | "getX"
      | "offboardCombinedTest"
      | "offboardOnboardTest"
      | "offboardToUserTest"
      | "userKeyTest"
  ): FunctionFragment;

  encodeFunctionData(functionFragment: "getCTs", values?: undefined): string;
  encodeFunctionData(functionFragment: "getCt", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "getOnboardOffboardResult",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "getUserKeyShares",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "getUserKeyTest",
    values: [BytesLike, BytesLike, AddressLike]
  ): string;
  encodeFunctionData(functionFragment: "getX", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "offboardCombinedTest",
    values: [BigNumberish, AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "offboardOnboardTest",
    values: [BigNumberish, BigNumberish, BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "offboardToUserTest",
    values: [BigNumberish, AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "userKeyTest",
    values: [BytesLike, BytesLike]
  ): string;

  decodeFunctionResult(functionFragment: "getCTs", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "getCt", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "getOnboardOffboardResult",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getUserKeyShares",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getUserKeyTest",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "getX", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "offboardCombinedTest",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "offboardOnboardTest",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "offboardToUserTest",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "userKeyTest",
    data: BytesLike
  ): Result;
}

export interface OffboardToUserKeyTestContract extends BaseContract {
  connect(runner?: ContractRunner | null): OffboardToUserKeyTestContract;
  waitForDeployment(): Promise<this>;

  interface: OffboardToUserKeyTestContractInterface;

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

  getCTs: TypedContractMethod<
    [],
    [[bigint, bigint, bigint, bigint, bigint]],
    "view"
  >;

  getCt: TypedContractMethod<[], [bigint], "view">;

  getOnboardOffboardResult: TypedContractMethod<[], [bigint], "view">;

  getUserKeyShares: TypedContractMethod<[], [[string, string]], "view">;

  getUserKeyTest: TypedContractMethod<
    [signedEK: BytesLike, signature: BytesLike, addr: AddressLike],
    [bigint],
    "nonpayable"
  >;

  getX: TypedContractMethod<[], [bigint], "view">;

  offboardCombinedTest: TypedContractMethod<
    [a: BigNumberish, addr: AddressLike],
    [void],
    "nonpayable"
  >;

  offboardOnboardTest: TypedContractMethod<
    [a8: BigNumberish, a16: BigNumberish, a32: BigNumberish, a64: BigNumberish],
    [void],
    "nonpayable"
  >;

  offboardToUserTest: TypedContractMethod<
    [a: BigNumberish, addr: AddressLike],
    [void],
    "nonpayable"
  >;

  userKeyTest: TypedContractMethod<
    [signedEK: BytesLike, signature: BytesLike],
    [[string, string]],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "getCTs"
  ): TypedContractMethod<
    [],
    [[bigint, bigint, bigint, bigint, bigint]],
    "view"
  >;
  getFunction(
    nameOrSignature: "getCt"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "getOnboardOffboardResult"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "getUserKeyShares"
  ): TypedContractMethod<[], [[string, string]], "view">;
  getFunction(
    nameOrSignature: "getUserKeyTest"
  ): TypedContractMethod<
    [signedEK: BytesLike, signature: BytesLike, addr: AddressLike],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "getX"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "offboardCombinedTest"
  ): TypedContractMethod<
    [a: BigNumberish, addr: AddressLike],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "offboardOnboardTest"
  ): TypedContractMethod<
    [a8: BigNumberish, a16: BigNumberish, a32: BigNumberish, a64: BigNumberish],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "offboardToUserTest"
  ): TypedContractMethod<
    [a: BigNumberish, addr: AddressLike],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "userKeyTest"
  ): TypedContractMethod<
    [signedEK: BytesLike, signature: BytesLike],
    [[string, string]],
    "nonpayable"
  >;

  filters: {};
}
