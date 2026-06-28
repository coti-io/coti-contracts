// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/// @title PodNetworkConstants
/// @notice Deployment constants used by chain-specific PoD dapp helper contracts.
library PodNetworkConstants {
    /// @notice Deterministic inbox address shared by every chain (CreateX CREATE3 deploy).
    /// @dev Same value on Sepolia, COTI testnet, and Avalanche Fuji because the CREATE3 address
    /// depends only on the deployer EOA and salt (see scripts/createx.ts).
    address internal constant INBOX = 0xAb625bE229F603f6BBF964474AFf6d5487e364De;

    /// @notice Source-chain inbox used by PoD dapps on Sepolia.
    address internal constant SEPOLIA_INBOX = INBOX;

    /// @notice Avalanche Fuji chain id used as a source chain paired with COTI testnet.
    uint256 internal constant AVALANCHE_FUJI_CHAIN_ID = 43113;

    /// @notice Source-chain inbox used by PoD dapps on Avalanche Fuji.
    address internal constant AVALANCHE_FUJI_INBOX = INBOX;

    /// @notice COTI testnet chain id used for remote MPC execution.
    uint256 internal constant COTI_TESTNET_CHAIN_ID = 7082400;

    /// @notice COTI-side MPC executor paired with source-chain PoD dapps.
    /// @dev Redeploy and update this after the deterministic inbox redeploy on COTI.
    address internal constant COTI_TESTNET_MPC_EXECUTOR = 0xC76aaE4F3810fBBd5d96b92DEFeBE0034405Ad9c;

    /// @notice COTI testnet inbox used by COTI-side dapps.
    address internal constant COTI_TESTNET_INBOX = INBOX;
}
