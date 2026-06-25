// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "./IInbox.sol";

/// @title InboxUser
/// @notice Mixin that restricts selected functions to the configured {IInbox} and exposes `inbox`.
abstract contract InboxUser {
    /// @notice Cross-chain inbox used for messaging.
    IInbox public inbox;

    /// @notice Caller is not the configured inbox.
    error OnlyInbox(address caller);

    /// @notice Restrict a function to the configured inbox.
    /// @dev Reverts unless `msg.sender` is the configured inbox.
    modifier onlyInbox() {
        if (msg.sender != address(inbox)) {
            revert OnlyInbox(msg.sender);
        }
        _;
    }

    /// @notice Set the inbox contract (typically once from a constructor or initializer).
    /// @param _inbox Inbox address.
    function setInbox(address _inbox) internal {
        inbox = IInbox(_inbox);
    }
}
