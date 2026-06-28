// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../../utils/mpc/MpcCore.sol";

import "../IInbox.sol";
import "../mpccodec/MpcAbiCodec.sol";
import "./coti-side/IPodExecutorOps.sol";
import "./PodLibBase.sol";

/// @title PodLib64
/// @notice 64-bit POD MPC helpers (`itUint64` / `ctUint64`) and comparisons to `ctBool`.
abstract contract PodLib64 is PodLibBase {
    using MpcAbiCodec for MpcAbiCodec.MpcMethodCallContext;

    function add64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.add64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function gt64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.gt64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function sub64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.sub64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function mul64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.mul64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    /// @notice Wrapping multiply modulo 2^64. Use only when downstream logic is defined over uint64 modular arithmetic.
    function mulWrapping64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.mulWrapping64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function div64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.div64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function rem64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.rem64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function and64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.and64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function or64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.or64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function xor64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.xor64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function min64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.min64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function max64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.max64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function eq64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.eq64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function ne64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.ne64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function ge64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.ge64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function le64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.le64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function lt64(
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree(IPodExecutor64.lt64.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function mux64(
        itBool memory bit,
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcMux64(bit, a, b, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _buildMpcMux64(
        itBool memory bit,
        itUint64 memory a,
        itUint64 memory b,
        address cOwner
    ) private pure returns (IInbox.MpcMethodCall memory) {
        return MpcAbiCodec.create(IPodExecutor64.mux64.selector, 4)
            .addArgument(bit)
            .addArgument(a)
            .addArgument(b)
            .addArgument(cOwner)
            .build();
    }

    function shl64(
        itUint64 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendShift(
            IPodExecutor64.shl64.selector, a, s, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    function shr64(
        itUint64 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendShift(
            IPodExecutor64.shr64.selector, a, s, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    /// @dev Callback `data` is `abi.encode(uint256)` plaintext (executor decrypts MPC rand on COTI).
    function rand64(
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcRand64(cOwner), callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    function _buildMpcRand64(address cOwner) private pure returns (IInbox.MpcMethodCall memory) {
        return MpcAbiCodec.create(IPodExecutor64.rand64.selector, 1).addArgument(cOwner).build();
    }

    /// @dev Callback `data` is `abi.encode(uint256)` plaintext.
    function randBoundedBits64(
        uint8 numBits,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcRandBoundedBits64(numBits, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _buildMpcRandBoundedBits64(uint8 numBits, address cOwner)
        private
        pure
        returns (IInbox.MpcMethodCall memory)
    {
        return MpcAbiCodec.create(IPodExecutor64.randBoundedBits64.selector, 2)
            .addArgument(uint256(uint8(numBits)))
            .addArgument(cOwner)
            .build();
    }

    function _buildMpcThree64(bytes4 selector, itUint64 memory a, itUint64 memory b, address cOwner)
        private
        pure
        returns (IInbox.MpcMethodCall memory)
    {
        return MpcAbiCodec.create(selector, 3).addArgument(a).addArgument(b).addArgument(cOwner).build();
    }

    function _buildMpcShift64(bytes4 selector, itUint64 memory a, uint8 s, address cOwner)
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

    function _sendThree(
        bytes4 selector,
        itUint64 memory a,
        itUint64 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) private returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcThree64(selector, a, b, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _sendShift(
        bytes4 selector,
        itUint64 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) private returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcShift64(selector, a, s, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }
}
