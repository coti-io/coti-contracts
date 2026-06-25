// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "./PodUser.sol";
import "../PodNetworkConstants.sol";

/// @title PodUserFuji
/// @notice PoD base for Avalanche Fuji source-chain dApps paired with COTI testnet.
abstract contract PodUserFuji is PodUser {
    constructor() {
        setInbox(PodNetworkConstants.AVALANCHE_FUJI_INBOX);
        configureCoti(PodNetworkConstants.COTI_TESTNET_MPC_EXECUTOR, PodNetworkConstants.COTI_TESTNET_CHAIN_ID);
    }
}
