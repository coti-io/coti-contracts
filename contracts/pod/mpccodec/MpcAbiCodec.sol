// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../../utils/mpc/MpcCore.sol";

import "../IInbox.sol";

/// @title MpcAbiCodec
/// @notice dApp-facing builders for {IInbox.MpcMethodCall} payloads (source chains).
/// @dev Inbox must not use this for execution encode — see coti-pod-inbox-contracts {MpcAbiReEncode}.
library MpcAbiCodec {
    enum MpcDataType {
        UINT256,
        ADDRESS, // include other system types for coded
        BYTES32,
        STRING,
        BYTES,
        UINT256_ARRAY,
        ADDRESS_ARRAY,
        BYTES32_ARRAY,
        STRING_ARRAY,
        BYTES_ARRAY,
        IT_BOOL,
        IT_UINT8,
        IT_UINT16,
        IT_UINT32,
        IT_UINT64,
        IT_UINT128,
        IT_UINT256,
        IT_STRING
    }

    struct MpcMethodCallContext {
        IInbox.MpcMethodCall mpcMethodCall;
        bytes[] data;
        uint256 dataSize;
        uint256 argIndex;
    }

    /// @notice Create a method call context with selector and argument count.
    function create(bytes4 selector, uint256 argCount) internal pure returns (MpcMethodCallContext memory) {
        return MpcMethodCallContext({
            mpcMethodCall: IInbox.MpcMethodCall({
                selector: selector,
                data: new bytes(0),
                datatypes: new bytes8[](argCount),
                datalens: new bytes32[](argCount)
            }),
            data: new bytes[](argCount),
            dataSize: 0,
            argIndex: 0
        });
    }

    function addArgument(MpcMethodCallContext memory methodCall, uint256 arg)
        internal pure returns (MpcMethodCallContext memory)
    {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.UINT256);
    }

    function addArgument(MpcMethodCallContext memory methodCall, address arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.ADDRESS);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itUint64 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT64);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itBool memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_BOOL);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itUint8 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT8);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itUint16 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT16);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itUint32 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT32);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itUint128 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT128);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itUint256 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT256);
    }

    function addArgument(MpcMethodCallContext memory methodCall, itString memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_STRING);
    }

    function addArgument(MpcMethodCallContext memory methodCall, bytes32 arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES32);
    }

    function addArgument(MpcMethodCallContext memory methodCall, string memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.STRING);
    }

    function addArgument(MpcMethodCallContext memory methodCall, bytes memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES);
    }

    function addArgument(MpcMethodCallContext memory methodCall, uint256[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.UINT256_ARRAY);
    }

    function addArgument(MpcMethodCallContext memory methodCall, address[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.ADDRESS_ARRAY);
    }

    function addArgument(MpcMethodCallContext memory methodCall, bytes32[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES32_ARRAY);
    }

    function addArgument(MpcMethodCallContext memory methodCall, string[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.STRING_ARRAY);
    }

    function addArgument(MpcMethodCallContext memory methodCall, bytes[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES_ARRAY);
    }

    function build(MpcMethodCallContext memory methodCall) internal pure returns (IInbox.MpcMethodCall memory) {
        bytes memory resized = new bytes(methodCall.dataSize);
        uint cursor = 0;
        for (uint i = 0; i < methodCall.argIndex; i++) {
            bytes memory chunk = methodCall.data[i];
            methodCall.mpcMethodCall.datalens[i] = bytes32(chunk.length);
            for (uint j = 0; j < chunk.length; j++) {
                resized[cursor + j] = chunk[j];
            }
            cursor += chunk.length;
        }

        methodCall.mpcMethodCall.data = resized;
        return methodCall.mpcMethodCall;
    }

    function _appendArgument(
        MpcMethodCallContext memory methodCallContext,
        bytes memory encodedArg,
        MpcDataType dataType
    ) internal pure returns (MpcMethodCallContext memory) {
        require(methodCallContext.argIndex < methodCallContext.mpcMethodCall.datatypes.length, "MpcAbiCodec: too many args");

        methodCallContext.mpcMethodCall.datatypes[methodCallContext.argIndex] = bytes8(uint64(uint8(dataType)));
        methodCallContext.data[methodCallContext.argIndex] = encodedArg;
        methodCallContext.dataSize += encodedArg.length;
        methodCallContext.argIndex += 1;
        return methodCallContext;
    }
}
