// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "./InboxUser.sol";
import "./PodNetworkConstants.sol";

/// @title InboxUserCotiTestnet
/// @notice Mixin that configures {InboxUser} for COTI testnet inbox address.
abstract contract InboxUserCotiTestnet is InboxUser {
    constructor() {
        setInbox(PodNetworkConstants.COTI_TESTNET_INBOX);
    }
}
