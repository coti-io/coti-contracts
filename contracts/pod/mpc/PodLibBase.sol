// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../../utils/mpc/MpcCore.sol";

import "../IInbox.sol";
import "../mpccodec/MpcAbiCodec.sol";
import "./PodUser.sol";

/// @title PodLibBase
/// @notice Shared POD helpers: fee-aware two-way sends and default outbox error surfacing.
/// @dev Callers supply `totalValueWei` and `callbackFeeLocalWei`; the inbox splits into gas units. Not responsible for `tx.gasprice`.
abstract contract PodLibBase is PodUser {
    using MpcAbiCodec for MpcAbiCodec.MpcMethodCallContext;

    constructor(address initialOwner) PodUser(initialOwner) {}

    /// @dev Minimum callback slice in wei; inbox applies stricter policy from {InboxFeeManager}.
    uint256 internal constant MIN_CALLBACK_FEE_WEI = 1;

    /// @notice Accept native funds that can subsidize future inbox fees paid by inherited Pod helper methods.
    /// @dev `_sendTwoWayWithFee` checks contract balance, so callers may pre-fund a Pod app and later spend that balance.
    receive() external payable {}

    /// @param totalValueWei Total native payment forwarded to `sendTwoWayMessage` (e.g. `msg.value`).
    /// @param callbackFeeLocalWei Portion of that total reserved for the callback leg; caller-estimated.
    function _sendTwoWayWithFee(
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei,
        uint256 targetChainId_,
        address targetContract_,
        IInbox.MpcMethodCall memory mpcMethodCall,
        bytes4 callbackSelector_,
        bytes4 errorSelector_
    ) internal returns (bytes32) {
        require(callbackFeeLocalWei >= MIN_CALLBACK_FEE_WEI, "PodLib: callback fee min");
        require(callbackFeeLocalWei <= totalValueWei, "PodLib: callback exceeds total");
        require(address(this).balance >= totalValueWei, "PodLib: inbox fee");
        return IInbox(inbox).sendTwoWayMessage{value: totalValueWei}(
            targetChainId_,
            targetContract_,
            mpcMethodCall,
            callbackSelector_,
            errorSelector_,
            callbackFeeLocalWei
        );
    }

    /// @dev Splits stack between building `mpc` and forwarding; avoids "stack too deep" in codec helpers.
    function _forwardTwoWay(
        IInbox.MpcMethodCall memory mpc,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32) {
        return _sendTwoWayWithFee(
            totalValueWei,
            callbackFeeLocalWei,
            cotiChainId,
            mpcExecutorAddress,
            mpc,
            callbackSelector,
            errorSelector
        );
    }

    function onDefaultMpcError(bytes32 requestId) external onlyMpcExecutor {
        (uint256 code, string memory message) = inbox.getOutboxError(requestId);
        emit ErrorRemoteCall(requestId, code, message);
    }
}
