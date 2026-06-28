// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/// @title IPodExecutorOps
/// @notice COTI-side MPC executor interfaces: 64-, 128-, and 256-bit operations with distinct selectors for {PodLib} dispatch.

/// @notice 64-bit executor ops (distinct names for unambiguous `.selector` use in {PodLib64}).
interface IPodExecutor64 {
    function add64(gtUint64 a, gtUint64 b, address cOwner) external;
    function sub64(gtUint64 a, gtUint64 b, address cOwner) external;
    /// @notice Checked multiplication. Reverts when the true product does not fit in uint64.
    function mul64(gtUint64 a, gtUint64 b, address cOwner) external;
    /// @notice Wrapping multiplication modulo 2^64. Use only when modulo arithmetic is an explicit invariant.
    function mulWrapping64(gtUint64 a, gtUint64 b, address cOwner) external;
    function div64(gtUint64 a, gtUint64 b, address cOwner) external;
    function rem64(gtUint64 a, gtUint64 b, address cOwner) external;
    function and64(gtUint64 a, gtUint64 b, address cOwner) external;
    function or64(gtUint64 a, gtUint64 b, address cOwner) external;
    function xor64(gtUint64 a, gtUint64 b, address cOwner) external;
    function min64(gtUint64 a, gtUint64 b, address cOwner) external;
    function max64(gtUint64 a, gtUint64 b, address cOwner) external;
    function eq64(gtUint64 a, gtUint64 b, address cOwner) external;
    function ne64(gtUint64 a, gtUint64 b, address cOwner) external;
    function ge64(gtUint64 a, gtUint64 b, address cOwner) external;
    function gt64(gtUint64 a, gtUint64 b, address cOwner) external;
    function le64(gtUint64 a, gtUint64 b, address cOwner) external;
    function lt64(gtUint64 a, gtUint64 b, address cOwner) external;
    function mux64(gtBool bit, gtUint64 a, gtUint64 b, address cOwner) external;
    function shl64(gtUint64 a, uint8 s, address cOwner) external;
    function shr64(gtUint64 a, uint8 s, address cOwner) external;

    /// @notice Plaintext random; inbox payload is `abi.encode(uint256)` (not `ctUint64`).
    function rand64(address cOwner) external;

    /// @notice Plaintext random; inbox payload is `abi.encode(uint256)` (not `ctUint64`).
    function randBoundedBits64(uint8 numBits, address cOwner) external;
}

/// @notice 128-bit executor ops.
interface IPodExecutor128 {
    function add128(gtUint128 a, gtUint128 b, address cOwner) external;
    function sub128(gtUint128 a, gtUint128 b, address cOwner) external;
    /// @notice Checked multiplication. Reverts when the true product does not fit in uint128.
    function mul128(gtUint128 a, gtUint128 b, address cOwner) external;
    /// @notice Wrapping multiplication modulo 2^128. Use only when modulo arithmetic is an explicit invariant.
    function mulWrapping128(gtUint128 a, gtUint128 b, address cOwner) external;
    function and128(gtUint128 a, gtUint128 b, address cOwner) external;
    function or128(gtUint128 a, gtUint128 b, address cOwner) external;
    function xor128(gtUint128 a, gtUint128 b, address cOwner) external;
    function min128(gtUint128 a, gtUint128 b, address cOwner) external;
    function max128(gtUint128 a, gtUint128 b, address cOwner) external;
    function eq128(gtUint128 a, gtUint128 b, address cOwner) external;
    function ne128(gtUint128 a, gtUint128 b, address cOwner) external;
    function ge128(gtUint128 a, gtUint128 b, address cOwner) external;
    function gt128(gtUint128 a, gtUint128 b, address cOwner) external;
    function le128(gtUint128 a, gtUint128 b, address cOwner) external;
    function lt128(gtUint128 a, gtUint128 b, address cOwner) external;
    function mux128(gtBool bit, gtUint128 a, gtUint128 b, address cOwner) external;
    function shl128(gtUint128 a, uint8 s, address cOwner) external;
    function shr128(gtUint128 a, uint8 s, address cOwner) external;

    /// @notice Plaintext random; inbox payload is `abi.encode(uint256)` (not `ctUint128`).
    function rand128(address cOwner) external;

    /// @notice Plaintext random; inbox payload is `abi.encode(uint256)` (not `ctUint128`).
    function randBoundedBits128(uint8 numBits, address cOwner) external;
}

/// @notice 256-bit executor ops.
interface IPodExecutor256 {
    function add256(gtUint256 a, gtUint256 b, address cOwner) external;
    function sub256(gtUint256 a, gtUint256 b, address cOwner) external;
    /// @notice Checked multiplication. Reverts when the true product does not fit in uint256.
    function mul256(gtUint256 a, gtUint256 b, address cOwner) external;
    /// @notice Wrapping multiplication modulo 2^256. Use only when modulo arithmetic is an explicit invariant.
    function mulWrapping256(gtUint256 a, gtUint256 b, address cOwner) external;
    function and256(gtUint256 a, gtUint256 b, address cOwner) external;
    function or256(gtUint256 a, gtUint256 b, address cOwner) external;
    function xor256(gtUint256 a, gtUint256 b, address cOwner) external;
    function min256(gtUint256 a, gtUint256 b, address cOwner) external;
    function max256(gtUint256 a, gtUint256 b, address cOwner) external;
    function eq256(gtUint256 a, gtUint256 b, address cOwner) external;
    function ne256(gtUint256 a, gtUint256 b, address cOwner) external;
    function ge256(gtUint256 a, gtUint256 b, address cOwner) external;
    function gt256(gtUint256 a, gtUint256 b, address cOwner) external;
    function le256(gtUint256 a, gtUint256 b, address cOwner) external;
    function lt256(gtUint256 a, gtUint256 b, address cOwner) external;
    function mux256(gtBool bit, gtUint256 a, gtUint256 b, address cOwner) external;
    function shl256(gtUint256 a, uint8 s, address cOwner) external;
    function shr256(gtUint256 a, uint8 s, address cOwner) external;

    /// @notice Plaintext random; inbox payload is `abi.encode(uint256)` (not `ctUint256`).
    function rand256(address cOwner) external;

    /// @notice Plaintext random; inbox payload is `abi.encode(uint256)` (not `ctUint256`).
    function randBoundedBits256(uint8 numBits, address cOwner) external;
}
