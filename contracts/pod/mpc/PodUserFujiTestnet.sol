// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "./PodUser.sol";
import "../PodNetworkConstants.sol";

/// @title PodUserFujiTestnet
abstract contract PodUserFujiTestnet is PodUser {
    constructor() {
        setInbox(PodNetworkConstants.FUJI_TESTNET_INBOX);
        configureCoti(PodNetworkConstants.COTI_TESTNET_MPC_EXECUTOR, PodNetworkConstants.COTI_TESTNET_CHAIN_ID);
    }
}
