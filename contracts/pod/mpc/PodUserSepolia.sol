// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "./PodUser.sol";
import "../PodNetworkConstants.sol";

/// @title PodUserSepolia
abstract contract PodUserSepolia is PodUser {
    constructor() {
        setInbox(PodNetworkConstants.SEPOLIA_INBOX);
        configureCoti(PodNetworkConstants.COTI_TESTNET_MPC_EXECUTOR, PodNetworkConstants.COTI_TESTNET_CHAIN_ID);
    }
}
