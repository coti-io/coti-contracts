// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/// @title PodNetworkConstants
/// @notice Deployment constants used by chain-specific PoD dapp helper contracts.
library PodNetworkConstants {
    address internal constant COTI_TESTNET_INBOX = 0xB4A53FE02401fDFA8DAc00450dA3FfF8D01502F8;
    address internal constant SEPOLIA_INBOX = 0xB4A53FE02401fDFA8DAc00450dA3FfF8D01502F8;
    address internal constant FUJI_TESTNET_INBOX = 0xB4A53FE02401fDFA8DAc00450dA3FfF8D01502F8;

    /// @notice COTI testnet chain id used for remote MPC execution.
    uint256 internal constant COTI_TESTNET_CHAIN_ID = 7082400;

    /// @notice COTI-side MPC executor paired with Sepolia PoD dapps.
    address internal constant COTI_TESTNET_MPC_EXECUTOR = 0xC76aaE4F3810fBBd5d96b92DEFeBE0034405Ad9c;
}
