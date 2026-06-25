// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../../utils/mpc/MpcCore.sol";

import "../IInbox.sol";
import "../mpccodec/MpcAbiCodec.sol";
import "./coti-side/IPodExecutorOps.sol";
import "./PodLibBase.sol";

/// @title PodLib128
/// @notice 128-bit POD MPC helpers (`itUint128` / `ctUint128`).
abstract contract PodLib128 is PodLibBase {
    using MpcAbiCodec for MpcAbiCodec.MpcMethodCallContext;

    function add128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.add128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function sub128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.sub128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function mul128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.mul128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    /// @notice Wrapping multiply modulo 2^128. Use only when downstream logic is defined over uint128 modular arithmetic.
    function mulWrapping128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.mulWrapping128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function and128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.and128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function or128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.or128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function xor128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.xor128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function min128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.min128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function max128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.max128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function eq128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.eq128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function ne128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.ne128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function ge128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.ge128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function gt128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.gt128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function le128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.le128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function lt128(
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree128(IPodExecutor128.lt128.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function mux128(
        itBool memory bit,
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcMux128(bit, a, b, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _buildMpcMux128(
        itBool memory bit,
        itUint128 memory a,
        itUint128 memory b,
        address cOwner
    ) private pure returns (IInbox.MpcMethodCall memory) {
        return MpcAbiCodec.create(IPodExecutor128.mux128.selector, 4)
            .addArgument(bit)
            .addArgument(a)
            .addArgument(b)
            .addArgument(cOwner)
            .build();
    }

    function shl128(
        itUint128 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendShift128(
            IPodExecutor128.shl128.selector, a, s, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    function shr128(
        itUint128 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendShift128(
            IPodExecutor128.shr128.selector, a, s, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    /// @dev Callback `data` is `abi.encode(uint256)` plaintext (executor decrypts MPC rand on COTI).
    function rand128(
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcRand128(cOwner), callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    /// @dev Callback `data` is `abi.encode(uint256)` plaintext.
    function randBoundedBits128(
        uint8 numBits,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcRandBoundedBits128(numBits, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _buildMpcRand128(address cOwner) private pure returns (IInbox.MpcMethodCall memory) {
        return MpcAbiCodec.create(IPodExecutor128.rand128.selector, 1).addArgument(cOwner).build();
    }

    function _buildMpcRandBoundedBits128(uint8 numBits, address cOwner)
        private
        pure
        returns (IInbox.MpcMethodCall memory)
    {
        return MpcAbiCodec.create(IPodExecutor128.randBoundedBits128.selector, 2)
            .addArgument(uint256(uint8(numBits)))
            .addArgument(cOwner)
            .build();
    }

    function _buildMpcThree128(bytes4 selector, itUint128 memory a, itUint128 memory b, address cOwner)
        private
        pure
        returns (IInbox.MpcMethodCall memory)
    {
        return MpcAbiCodec.create(selector, 3).addArgument(a).addArgument(b).addArgument(cOwner).build();
    }

    function _buildMpcShift128(bytes4 selector, itUint128 memory a, uint8 s, address cOwner)
        private
        pure
        returns (IInbox.MpcMethodCall memory)
    {
        return MpcAbiCodec.create(selector, 3)
            .addArgument(a)
            .addArgument(uint256(uint8(s)))
            .addArgument(cOwner)
            .build();
    }

    function _sendThree128(
        bytes4 selector,
        itUint128 memory a,
        itUint128 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) private returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcThree128(selector, a, b, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _sendShift128(
        bytes4 selector,
        itUint128 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) private returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcShift128(selector, a, s, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }
}
