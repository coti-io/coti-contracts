// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

// =========== Basic MPC Types ===========

type gtBool is uint256;
type gtInt8 is uint256;
type gtUint8 is uint256;
type gtInt16 is uint256;
type gtUint16 is uint256;
type gtInt32 is uint256;
type gtUint32 is uint256;
type gtInt64 is uint256;
type gtUint64 is uint256;
type gtInt128 is uint256;
type gtUint128 is uint256;
type gtInt256 is uint256;
type gtUint256 is uint256;

// =========== Ciphertext Types ===========

type ctBool is uint256;
type ctInt8 is uint256;
type ctUint8 is uint256;
type ctInt16 is uint256;
type ctUint16 is uint256;
type ctInt32 is uint256;
type ctUint32 is uint256;
type ctInt64 is uint256;
type ctUint64 is uint256;
type ctInt128 is uint256;
type ctUint128 is uint256;
struct ctInt256 {
    ctInt128 ciphertextHigh;
    ctInt128 ciphertextLow;
}
struct ctUint256 {
    ctUint128 ciphertextHigh;
    ctUint128 ciphertextLow;
}

// =========== String Types ===========

struct gtString {
    gtUint64[] value;
}

struct ctString {
    ctUint64[] value;
}

// =========== Input Types ===========

struct itBool {
    ctBool ciphertext;
    bytes signature;
}

struct itInt8 {
    ctInt8 ciphertext;
    bytes signature;
}

struct itUint8 {
    ctUint8 ciphertext;
    bytes signature;
}

struct itInt16 {
    ctInt16 ciphertext;
    bytes signature;
}

struct itUint16 {
    ctUint16 ciphertext;
    bytes signature;
}

struct itInt32 {
    ctInt32 ciphertext;
    bytes signature;
}

struct itUint32 {
    ctUint32 ciphertext;
    bytes signature;
}

struct itInt64 {
    ctInt64 ciphertext;
    bytes signature;
}

struct itUint64 {
    ctUint64 ciphertext;
    bytes signature;
}

struct itUint128 {
    ctUint128 ciphertext;
    bytes signature;
}

struct itInt128 {
    ctInt128 ciphertext;
    bytes signature;
}

struct itUint256 {
    ctUint256 ciphertext;
    bytes signature;
}

struct itInt256 {
    ctInt256 ciphertext;
    bytes signature;
}

struct itString {
    ctString ciphertext;
    bytes[] signature;
}

// =========== User Types ===========

struct utBool {
    ctBool ciphertext;
    ctBool userCiphertext;
}

struct utInt8 {
    ctInt8 ciphertext;
    ctInt8 userCiphertext;
}

struct utUint8 {
    ctUint8 ciphertext;
    ctUint8 userCiphertext;
}

struct utInt16 {
    ctInt16 ciphertext;
    ctInt16 userCiphertext;
}

struct utUint16 {
    ctUint16 ciphertext;
    ctUint16 userCiphertext;
}

struct utInt32 {
    ctInt32 ciphertext;
    ctInt32 userCiphertext;
}

struct utUint32 {
    ctUint32 ciphertext;
    ctUint32 userCiphertext;
}

struct utInt64 {
    ctInt64 ciphertext;
    ctInt64 userCiphertext;
}

struct utUint64 {
    ctUint64 ciphertext;
    ctUint64 userCiphertext;
}

struct utUint128 {
    ctUint128 ciphertext;
    ctUint128 userCiphertext;
}

struct utUint256 {
    ctUint256 ciphertext;
    ctUint256 userCiphertext;
}

struct utInt128 {
    ctInt128 ciphertext;
    ctInt128 userCiphertext;
}

struct utInt256 {
    ctInt256 ciphertext;
    ctInt256 userCiphertext;
}

struct utString {
    ctString ciphertext;
    ctString userCiphertext;
}

// =========== Common Enums ===========

enum MPC_TYPE {
    SBOOL_T,
    SUINT8_T,
    SUINT16_T,
    SUINT32_T,
    SUINT64_T,
    SUINT128_T,
    SUINT256_T
}

enum ARGS {
    BOTH_SECRET,
    LHS_PUBLIC,
    RHS_PUBLIC
}

// =========== Common Utility Functions ===========

function combineEnumsToBytes2(
    MPC_TYPE mpcType,
    ARGS argsType
) pure returns (bytes2) {
    return bytes2((uint16(mpcType) << 8) | uint8(argsType));
}

function combineEnumsToBytes3(
    MPC_TYPE mpcType1,
    MPC_TYPE mpcType2,
    ARGS argsType
) pure returns (bytes3) {
    return
        bytes3(
            (uint24(mpcType1) << 16) | (uint16(mpcType2) << 8) | uint8(argsType)
        );
}

function combineEnumsToBytes4(
    MPC_TYPE mpcType1,
    MPC_TYPE mpcType2,
    MPC_TYPE mpcType3,
    ARGS argsType
) pure returns (bytes4) {
    return
        bytes4(
            (uint32(mpcType1) << 24) |
                (uint24(mpcType2) << 16) |
                (uint16(mpcType3) << 8) |
                uint8(argsType)
        );
}

function combineEnumsToBytes5(
    MPC_TYPE mpcType1,
    MPC_TYPE mpcType2,
    MPC_TYPE mpcType3,
    MPC_TYPE mpcType4,
    ARGS argsType
) pure returns (bytes5) {
    return
        bytes5(
            (uint40(mpcType1) << 32) |
                (uint32(mpcType2) << 24) |
                (uint24(mpcType3) << 16) |
                (uint16(mpcType4) << 8) |
                uint8(argsType)
        );
}
