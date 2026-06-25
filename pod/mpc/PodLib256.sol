// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../../utils/mpc/MpcCore.sol";

import "../IInbox.sol";
import "../mpccodec/MpcAbiCodec.sol";
import "./coti-side/IPodExecutorOps.sol";
import "./PodLibBase.sol";

/// @title PodLib256
/// @notice 256-bit POD MPC helpers (`itUint256` / `ctUint256`).
abstract contract PodLib256 is PodLibBase {
    using MpcAbiCodec for MpcAbiCodec.MpcMethodCallContext;

    function add256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.add256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function sub256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.sub256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function mul256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.mul256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    /// @notice Wrapping multiply modulo 2^256. Use only when downstream logic is defined over uint256 modular arithmetic.
    function mulWrapping256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.mulWrapping256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function and256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.and256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function or256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.or256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function xor256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.xor256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function min256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.min256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function max256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.max256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function eq256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.eq256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function ne256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.ne256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function ge256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.ge256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function gt256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.gt256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function le256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.le256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function lt256(
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendThree256(IPodExecutor256.lt256.selector, a, b, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei);
    }

    function mux256(
        itBool memory bit,
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcMux256(bit, a, b, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _buildMpcMux256(
        itBool memory bit,
        itUint256 memory a,
        itUint256 memory b,
        address cOwner
    ) private pure returns (IInbox.MpcMethodCall memory) {
        return MpcAbiCodec.create(IPodExecutor256.mux256.selector, 4)
            .addArgument(bit)
            .addArgument(a)
            .addArgument(b)
            .addArgument(cOwner)
            .build();
    }

    function shl256(
        itUint256 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendShift256(
            IPodExecutor256.shl256.selector, a, s, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    function shr256(
        itUint256 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendShift256(
            IPodExecutor256.shr256.selector, a, s, cOwner, callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    /// @dev Callback `data` is `abi.encode(uint256)` plaintext (executor decrypts MPC rand on COTI).
    function rand256(
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcRand256(cOwner), callbackSelector, errorSelector, totalValueWei, callbackFeeLocalWei
        );
    }

    /// @dev Callback `data` is `abi.encode(uint256)` plaintext.
    function randBoundedBits256(
        uint8 numBits,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcRandBoundedBits256(numBits, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _buildMpcRand256(address cOwner) private pure returns (IInbox.MpcMethodCall memory) {
        return MpcAbiCodec.create(IPodExecutor256.rand256.selector, 1).addArgument(cOwner).build();
    }

    function _buildMpcRandBoundedBits256(uint8 numBits, address cOwner)
        private
        pure
        returns (IInbox.MpcMethodCall memory)
    {
        return MpcAbiCodec.create(IPodExecutor256.randBoundedBits256.selector, 2)
            .addArgument(uint256(uint8(numBits)))
            .addArgument(cOwner)
            .build();
    }

    function _buildMpcThree256(bytes4 selector, itUint256 memory a, itUint256 memory b, address cOwner)
        private
        pure
        returns (IInbox.MpcMethodCall memory)
    {
        return MpcAbiCodec.create(selector, 3).addArgument(a).addArgument(b).addArgument(cOwner).build();
    }

    function _buildMpcShift256(bytes4 selector, itUint256 memory a, uint8 s, address cOwner)
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

    function _sendThree256(
        bytes4 selector,
        itUint256 memory a,
        itUint256 memory b,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) private returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcThree256(selector, a, b, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }

    function _sendShift256(
        bytes4 selector,
        itUint256 memory a,
        uint8 s,
        address cOwner,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) private returns (bytes32) {
        return _forwardTwoWay(
            _buildMpcShift256(selector, a, s, cOwner),
            callbackSelector,
            errorSelector,
            totalValueWei,
            callbackFeeLocalWei
        );
    }
}
