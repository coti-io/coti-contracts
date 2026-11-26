// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../IInbox.sol";

/// @dev Inbox stand-in that delivers one return leg to `target` with a chosen message context,
///      the way the real inbox does for `raise` and system-error callbacks.
contract ErrorLegInbox {
    uint256 private _remoteChainId;
    address private _remoteContract;
    bytes32 private _sourceRequestId;
    IInbox.InboxErrorType private _errorType;

    function deliver(
        address target,
        bytes calldata callData,
        uint256 remoteChainId,
        address remoteContract,
        bytes32 sourceRequestId,
        IInbox.InboxErrorType errorType
    ) external {
        _remoteChainId = remoteChainId;
        _remoteContract = remoteContract;
        _sourceRequestId = sourceRequestId;
        _errorType = errorType;

        (bool ok, bytes memory ret) = target.call(callData);

        delete _remoteChainId;
        delete _remoteContract;
        delete _sourceRequestId;
        delete _errorType;

        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    function inboxMsgSender() external view returns (uint256, address) {
        return (_remoteChainId, _remoteContract);
    }

    function inboxSourceRequestId() external view returns (bytes32) {
        return _sourceRequestId;
    }

    function inboxErrorType() external view returns (IInbox.InboxErrorType) {
        return _errorType;
    }
}
