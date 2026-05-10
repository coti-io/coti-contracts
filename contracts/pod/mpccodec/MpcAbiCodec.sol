// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "@coti-io/coti-contracts/contracts/utils/mpc/MpcCore.sol";

import "../IInbox.sol";

/// @title MpcAbiCodec
/// @notice Library to build and re-encode {IInbox.MpcMethodCall} payloads for MPC and ABI dispatch.
/// @dev Maps it-* wire types to gt-* calldata expected by COTI-side executors.
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

    event ValidateCiphertextStart(uint8 dataType, uint256 argLen, bytes32 argHash);
    event ValidateCiphertextSuccess(uint8 dataType);

    struct MpcMethodCallContext {
        IInbox.MpcMethodCall mpcMethodCall;
        bytes[] data;
        uint256 dataSize;
        uint256 argIndex;
    }

    /// @notice Create a method call context with selector and argument count.
    /// @param selector The method selector to call on the target contract.
    /// @param argCount The number of arguments expected in the call.
    /// @return context The initialized method call context.
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

    /**
     * @notice Add an argument to the method call context
     * @param methodCall The method call
     * @param arg the argument to add
     * @return The updated method call
     */
    function addArgument(MpcMethodCallContext memory methodCall, uint256 arg)
        internal pure returns (MpcMethodCallContext memory)
    {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.UINT256);
    }

    /// @notice Add an address argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The address argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, address arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.ADDRESS);
    }

    /// @notice Add an itUint64 argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itUint64 argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itUint64 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT64);
    }

    /// @notice Add an itBool argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itBool argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itBool memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_BOOL);
    }

    /// @notice Add an itUint8 argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itUint8 argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itUint8 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT8);
    }

    /// @notice Add an itUint16 argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itUint16 argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itUint16 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT16);
    }

    /// @notice Add an itUint32 argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itUint32 argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itUint32 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT32);
    }

    /// @notice Add an itUint128 argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itUint128 argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itUint128 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT128);
    }

    /// @notice Add an itUint256 argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itUint256 argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itUint256 memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_UINT256);
    }

    /// @notice Add an itString argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The itString argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, itString memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.IT_STRING);
    }

    /// @notice Add a bytes32 argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The bytes32 argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, bytes32 arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES32);
    }

    /// @notice Add a string argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The string argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, string memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.STRING);
    }

    /// @notice Add a bytes argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The bytes argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, bytes memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES);
    }

    /// @notice Add a uint256 array argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The uint256[] argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, uint256[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.UINT256_ARRAY);
    }

    /// @notice Add an address array argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The address[] argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, address[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.ADDRESS_ARRAY);
    }

    /// @notice Add a bytes32 array argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The bytes32[] argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, bytes32[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES32_ARRAY);
    }

    /// @notice Add a string array argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The string[] argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, string[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.STRING_ARRAY);
    }

    /// @notice Add a bytes array argument to the method call context.
    /// @param methodCall The method call context.
    /// @param arg The bytes[] argument to add.
    /// @return The updated method call context.
    function addArgument(MpcMethodCallContext memory methodCall, bytes[] memory arg)
    internal pure returns (MpcMethodCallContext memory) {
        return _appendArgument(methodCall, abi.encode(arg), MpcDataType.BYTES_ARRAY);
    }

    /**
     * @notice Build the method call from the context by resizing the data
     * @param methodCall The method call context
     * @return The method call
     */
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

    /// @notice Re-encode a method call, validating it-* types to gt-* and rebuilding calldata.
    /// @param data The method call to re-encode.
    /// @return calldataBytes The ABI-encoded calldata with selector prepended.
    function reEncodeWithGt(IInbox.MpcMethodCall memory data) internal returns (bytes memory) {
        uint argCount = data.datatypes.length;
        require(data.datalens.length == argCount, "MpcAbiCodec: invalid datalens");
        bytes memory encodedArgs = data.data;

        bytes[] memory processed = new bytes[](argCount);
        bool[] memory isDynamic = new bool[](argCount);
        uint[] memory staticWords = new uint[](argCount);
        uint totalTailSize = 0;

        uint cursor = 0;
        for (uint i = 0; i < argCount; i++) {
            uint argLen = uint(uint256(data.datalens[i]));
            require(cursor + argLen <= encodedArgs.length, "MpcAbiCodec: arg out of bounds");

            bytes memory argData = _slice(encodedArgs, cursor, argLen);
            cursor += argLen;

            MpcDataType dataType = _decodeType(data.datatypes[i]);
            (bytes memory encodedArg, bool dynamicType, uint words) = _normalizeArg(argData, dataType);
            processed[i] = encodedArg;
            isDynamic[i] = dynamicType;
            staticWords[i] = words;
            if (dynamicType) {
                require(encodedArg.length >= 32, "MpcAbiCodec: invalid dynamic arg");
                totalTailSize += (encodedArg.length - 32);
            } else {
                require(encodedArg.length == words * 32, "MpcAbiCodec: invalid static arg");
            }
        }
        require(cursor == encodedArgs.length, "MpcAbiCodec: trailing data");

        uint headSize = 0;
        for (uint i = 0; i < argCount; i++) {
            headSize += isDynamic[i] ? 32 : (staticWords[i] * 32);
        }
        bytes memory recoded = new bytes(4 + headSize + totalTailSize);
        bytes4 selector = data.selector;
        assembly {
            mstore(add(recoded, 32), selector)
        }

        uint tailCursor = 0;
        uint headCursor = 0;
        for (uint i = 0; i < argCount; i++) {
            if (isDynamic[i]) {
                uint offset = headSize + tailCursor;
                _writeWord(recoded, 4 + headCursor, offset);
                bytes memory tailData = processed[i];
                uint tailLen = tailData.length - 32;
                _copyBytes(recoded, 4 + headSize + tailCursor, tailData, 32, tailLen);
                tailCursor += tailLen;
                headCursor += 32;
            } else {
                bytes memory staticData = processed[i];
                _copyBytes(recoded, 4 + headCursor, staticData, 0, staticData.length);
                headCursor += staticData.length;
            }
        }

        return recoded;
    }

    /// @dev Append an encoded argument and update type metadata and data size.
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

    /// @dev Read a 32-byte word from a bytes array at the given offset.
    function _readUint256(bytes memory data, uint offset) internal pure returns (uint256 value) {
        assembly {
            value := mload(add(add(data, 32), offset))
        }
    }

    /// @dev Write a 32-byte word into a bytes array at the given offset.
    function _writeWord(bytes memory data, uint offset, uint256 value) internal pure {
        assembly {
            mstore(add(add(data, 32), offset), value)
        }
    }

    /// @dev Copy a slice of bytes into a new array.
    function _slice(bytes memory data, uint offset, uint length) internal pure returns (bytes memory result) {
        result = new bytes(length);
        for (uint i = 0; i < length; i++) {
            result[i] = data[offset + i];
        }
    }

    /// @dev Decode an on-chain data type identifier into the enum.
    function _decodeType(bytes8 dataType) internal pure returns (MpcDataType) {
        return MpcDataType(uint8(uint64(dataType)));
    }

    /// @dev Normalize an argument to ABI encoding and validate MPC ciphertexts.
    function _normalizeArg(bytes memory argData, MpcDataType dataType)
    internal returns (bytes memory encodedArg, bool dynamicType, uint staticWordCount) {
        if (dataType == MpcDataType.UINT256) {
            return (argData, false, 1);
        }

        if (dataType == MpcDataType.ADDRESS) {
            return (argData, false, 1);
        }

        if (dataType == MpcDataType.BYTES32) {
            return (argData, false, 1);
        }

        if (dataType == MpcDataType.IT_UINT64) {
            itUint64 memory itValue = abi.decode(argData, (itUint64));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtUint64 gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            return (abi.encode(gtUint64.unwrap(gtValue)), false, 1);
        }

        if (dataType == MpcDataType.IT_BOOL) {
            itBool memory itValue = abi.decode(argData, (itBool));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtBool gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            return (abi.encode(gtBool.unwrap(gtValue)), false, 1);
        }

        if (dataType == MpcDataType.IT_UINT8) {
            itUint8 memory itValue = abi.decode(argData, (itUint8));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtUint8 gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            return (abi.encode(gtUint8.unwrap(gtValue)), false, 1);
        }

        if (dataType == MpcDataType.IT_UINT16) {
            itUint16 memory itValue = abi.decode(argData, (itUint16));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtUint16 gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            return (abi.encode(gtUint16.unwrap(gtValue)), false, 1);
        }

        if (dataType == MpcDataType.IT_UINT32) {
            itUint32 memory itValue = abi.decode(argData, (itUint32));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtUint32 gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            return (abi.encode(gtUint32.unwrap(gtValue)), false, 1);
        }

        if (dataType == MpcDataType.IT_UINT128) {
            itUint128 memory itValue = abi.decode(argData, (itUint128));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtUint128 memory gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            bytes memory encoded = abi.encode(gtValue);
            return (encoded, false, encoded.length / 32);
        }

        if (dataType == MpcDataType.IT_UINT256) {
            itUint256 memory itValue = abi.decode(argData, (itUint256));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtUint256 memory gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            bytes memory encoded = abi.encode(gtValue);
            return (encoded, false, encoded.length / 32);
        }

        if (dataType == MpcDataType.IT_STRING) {
            itString memory itValue = abi.decode(argData, (itString));
            emit ValidateCiphertextStart(uint8(dataType), argData.length, keccak256(argData));
            gtString memory gtValue = MpcCore.validateCiphertext(itValue);
            emit ValidateCiphertextSuccess(uint8(dataType));
            return (abi.encode(gtValue), true, 0);
        }

        if (
            dataType == MpcDataType.STRING ||
            dataType == MpcDataType.BYTES ||
            dataType == MpcDataType.UINT256_ARRAY ||
            dataType == MpcDataType.ADDRESS_ARRAY ||
            dataType == MpcDataType.BYTES32_ARRAY ||
            dataType == MpcDataType.STRING_ARRAY ||
            dataType == MpcDataType.BYTES_ARRAY
        ) {
            return (argData, true, 0);
        }

        revert("MpcAbiCodec: unknown type");
    }

    /// @dev Copy bytes from source to destination with word-aligned optimization.
    function _copyBytes(
        bytes memory dest,
        uint destOffset,
        bytes memory src,
        uint srcOffset,
        uint length
    ) internal pure {
        if (length == 0) {
            return;
        }
        assembly {
            let destPtr := add(add(dest, 32), destOffset)
            let srcPtr := add(add(src, 32), srcOffset)

            let remaining := length
            for { } gt(remaining, 31) { } {
                mstore(destPtr, mload(srcPtr))
                destPtr := add(destPtr, 32)
                srcPtr := add(srcPtr, 32)
                remaining := sub(remaining, 32)
            }

            if gt(remaining, 0) {
                let mask := sub(shl(mul(remaining, 8), 1), 1)
                let srcWord := and(mload(srcPtr), mask)
                let destWord := and(mload(destPtr), not(mask))
                mstore(destPtr, or(destWord, srcWord))
            }
        }
    }
}