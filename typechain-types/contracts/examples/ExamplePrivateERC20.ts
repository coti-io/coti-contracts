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
  EventFragment,
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedLogDescription,
  TypedListener,
  TypedContractMethod,
} from "../../common";

export type ItUint64Struct = { ciphertext: BigNumberish; signature: BytesLike };

export type ItUint64StructOutput = [ciphertext: bigint, signature: string] & {
  ciphertext: bigint;
  signature: string;
};

export interface ExamplePrivateERC20Interface extends Interface {
  getFunction(
    nameOrSignature:
      | "accountEncryptionAddress"
      | "allowance(address,bool)"
      | "allowance(address,address)"
      | "approve(address,uint256)"
      | "approve(address,(uint256,bytes))"
      | "balanceOf(address)"
      | "balanceOf()"
      | "decimals"
      | "name"
      | "reencryptAllowance"
      | "setAccountEncryptionAddress"
      | "symbol"
      | "totalSupply"
      | "transfer(address,(uint256,bytes))"
      | "transfer(address,uint256)"
      | "transferFrom(address,address,(uint256,bytes))"
      | "transferFrom(address,address,uint256)"
  ): FunctionFragment;

  getEvent(nameOrSignatureOrTopic: "Approval" | "Transfer"): EventFragment;

  encodeFunctionData(
    functionFragment: "accountEncryptionAddress",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "allowance(address,bool)",
    values: [AddressLike, boolean]
  ): string;
  encodeFunctionData(
    functionFragment: "allowance(address,address)",
    values: [AddressLike, AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "approve(address,uint256)",
    values: [AddressLike, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "approve(address,(uint256,bytes))",
    values: [AddressLike, ItUint64Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "balanceOf(address)",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "balanceOf()",
    values?: undefined
  ): string;
  encodeFunctionData(functionFragment: "decimals", values?: undefined): string;
  encodeFunctionData(functionFragment: "name", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "reencryptAllowance",
    values: [AddressLike, boolean]
  ): string;
  encodeFunctionData(
    functionFragment: "setAccountEncryptionAddress",
    values: [AddressLike]
  ): string;
  encodeFunctionData(functionFragment: "symbol", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "totalSupply",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "transfer(address,(uint256,bytes))",
    values: [AddressLike, ItUint64Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "transfer(address,uint256)",
    values: [AddressLike, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "transferFrom(address,address,(uint256,bytes))",
    values: [AddressLike, AddressLike, ItUint64Struct]
  ): string;
  encodeFunctionData(
    functionFragment: "transferFrom(address,address,uint256)",
    values: [AddressLike, AddressLike, BigNumberish]
  ): string;

  decodeFunctionResult(
    functionFragment: "accountEncryptionAddress",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowance(address,bool)",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowance(address,address)",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "approve(address,uint256)",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "approve(address,(uint256,bytes))",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "balanceOf(address)",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "balanceOf()",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "decimals", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "name", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "reencryptAllowance",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "setAccountEncryptionAddress",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "symbol", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "totalSupply",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "transfer(address,(uint256,bytes))",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "transfer(address,uint256)",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "transferFrom(address,address,(uint256,bytes))",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "transferFrom(address,address,uint256)",
    data: BytesLike
  ): Result;
}

export namespace ApprovalEvent {
  export type InputTuple = [
    owner: AddressLike,
    spender: AddressLike,
    ownerValue: BigNumberish,
    spenderValue: BigNumberish
  ];
  export type OutputTuple = [
    owner: string,
    spender: string,
    ownerValue: bigint,
    spenderValue: bigint
  ];
  export interface OutputObject {
    owner: string;
    spender: string;
    ownerValue: bigint;
    spenderValue: bigint;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace TransferEvent {
  export type InputTuple = [
    from: AddressLike,
    to: AddressLike,
    senderValue: BigNumberish,
    receiverValue: BigNumberish
  ];
  export type OutputTuple = [
    from: string,
    to: string,
    senderValue: bigint,
    receiverValue: bigint
  ];
  export interface OutputObject {
    from: string;
    to: string;
    senderValue: bigint;
    receiverValue: bigint;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export interface ExamplePrivateERC20 extends BaseContract {
  connect(runner?: ContractRunner | null): ExamplePrivateERC20;
  waitForDeployment(): Promise<this>;

  interface: ExamplePrivateERC20Interface;

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

  accountEncryptionAddress: TypedContractMethod<
    [account: AddressLike],
    [string],
    "view"
  >;

  "allowance(address,bool)": TypedContractMethod<
    [account: AddressLike, isSpender: boolean],
    [bigint],
    "nonpayable"
  >;

  "allowance(address,address)": TypedContractMethod<
    [owner: AddressLike, spender: AddressLike],
    [bigint],
    "view"
  >;

  "approve(address,uint256)": TypedContractMethod<
    [spender: AddressLike, value: BigNumberish],
    [boolean],
    "nonpayable"
  >;

  "approve(address,(uint256,bytes))": TypedContractMethod<
    [spender: AddressLike, value: ItUint64Struct],
    [boolean],
    "nonpayable"
  >;

  "balanceOf(address)": TypedContractMethod<
    [account: AddressLike],
    [bigint],
    "view"
  >;

  "balanceOf()": TypedContractMethod<[], [bigint], "nonpayable">;

  decimals: TypedContractMethod<[], [bigint], "view">;

  name: TypedContractMethod<[], [string], "view">;

  reencryptAllowance: TypedContractMethod<
    [account: AddressLike, isSpender: boolean],
    [boolean],
    "nonpayable"
  >;

  setAccountEncryptionAddress: TypedContractMethod<
    [offBoardAddress: AddressLike],
    [boolean],
    "nonpayable"
  >;

  symbol: TypedContractMethod<[], [string], "view">;

  totalSupply: TypedContractMethod<[], [bigint], "view">;

  "transfer(address,(uint256,bytes))": TypedContractMethod<
    [to: AddressLike, value: ItUint64Struct],
    [bigint],
    "nonpayable"
  >;

  "transfer(address,uint256)": TypedContractMethod<
    [to: AddressLike, value: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  "transferFrom(address,address,(uint256,bytes))": TypedContractMethod<
    [from: AddressLike, to: AddressLike, value: ItUint64Struct],
    [bigint],
    "nonpayable"
  >;

  "transferFrom(address,address,uint256)": TypedContractMethod<
    [from: AddressLike, to: AddressLike, value: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "accountEncryptionAddress"
  ): TypedContractMethod<[account: AddressLike], [string], "view">;
  getFunction(
    nameOrSignature: "allowance(address,bool)"
  ): TypedContractMethod<
    [account: AddressLike, isSpender: boolean],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "allowance(address,address)"
  ): TypedContractMethod<
    [owner: AddressLike, spender: AddressLike],
    [bigint],
    "view"
  >;
  getFunction(
    nameOrSignature: "approve(address,uint256)"
  ): TypedContractMethod<
    [spender: AddressLike, value: BigNumberish],
    [boolean],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "approve(address,(uint256,bytes))"
  ): TypedContractMethod<
    [spender: AddressLike, value: ItUint64Struct],
    [boolean],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "balanceOf(address)"
  ): TypedContractMethod<[account: AddressLike], [bigint], "view">;
  getFunction(
    nameOrSignature: "balanceOf()"
  ): TypedContractMethod<[], [bigint], "nonpayable">;
  getFunction(
    nameOrSignature: "decimals"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "name"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "reencryptAllowance"
  ): TypedContractMethod<
    [account: AddressLike, isSpender: boolean],
    [boolean],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "setAccountEncryptionAddress"
  ): TypedContractMethod<
    [offBoardAddress: AddressLike],
    [boolean],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "symbol"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "totalSupply"
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "transfer(address,(uint256,bytes))"
  ): TypedContractMethod<
    [to: AddressLike, value: ItUint64Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "transfer(address,uint256)"
  ): TypedContractMethod<
    [to: AddressLike, value: BigNumberish],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "transferFrom(address,address,(uint256,bytes))"
  ): TypedContractMethod<
    [from: AddressLike, to: AddressLike, value: ItUint64Struct],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "transferFrom(address,address,uint256)"
  ): TypedContractMethod<
    [from: AddressLike, to: AddressLike, value: BigNumberish],
    [bigint],
    "nonpayable"
  >;

  getEvent(
    key: "Approval"
  ): TypedContractEvent<
    ApprovalEvent.InputTuple,
    ApprovalEvent.OutputTuple,
    ApprovalEvent.OutputObject
  >;
  getEvent(
    key: "Transfer"
  ): TypedContractEvent<
    TransferEvent.InputTuple,
    TransferEvent.OutputTuple,
    TransferEvent.OutputObject
  >;

  filters: {
    "Approval(address,address,uint256,uint256)": TypedContractEvent<
      ApprovalEvent.InputTuple,
      ApprovalEvent.OutputTuple,
      ApprovalEvent.OutputObject
    >;
    Approval: TypedContractEvent<
      ApprovalEvent.InputTuple,
      ApprovalEvent.OutputTuple,
      ApprovalEvent.OutputObject
    >;

    "Transfer(address,address,uint256,uint256)": TypedContractEvent<
      TransferEvent.InputTuple,
      TransferEvent.OutputTuple,
      TransferEvent.OutputObject
    >;
    Transfer: TypedContractEvent<
      TransferEvent.InputTuple,
      TransferEvent.OutputTuple,
      TransferEvent.OutputObject
    >;
  };
}
