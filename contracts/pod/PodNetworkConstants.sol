// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// @title PodNetworkConstants
/// @notice Deployment constants used by chain-specific PoD dapp helper contracts.
library PodNetworkConstants {
    /// @notice Deterministic inbox address shared by every chain (CreateX CREATE3 deploy).
    /// @dev Salt label `pod.inbox.v2.2` — keep in sync with
    /// `pod-ecosystem-integration/deployConfig.json` (`chains.*.inbox`).
    /// Same value on Sepolia, COTI testnet, and Avalanche Fuji (CREATE3 = deployer EOA + salt).
    address internal constant INBOX = 0x3b8B70819f27e0438cBcE7f31894f799da52648F;

    /// @notice Source-chain inbox used by PoD dapps on Sepolia.
    address internal constant SEPOLIA_INBOX = INBOX;

    /// @notice Avalanche Fuji chain id used as a source chain paired with COTI testnet.
    uint256 internal constant AVALANCHE_FUJI_CHAIN_ID = 43113;

    /// @notice Source-chain inbox used by PoD dapps on Avalanche Fuji.
    address internal constant AVALANCHE_FUJI_INBOX = INBOX;

    /// @notice COTI testnet chain id used for remote MPC execution.
    uint256 internal constant COTI_TESTNET_CHAIN_ID = 7082400;

    /// @notice COTI-side MPC executor paired with source-chain PoD dapps.
    /// @dev From deployConfig `chains.7082400.cotiExecutor` (pod.inbox.v2.2 era).
    address internal constant COTI_TESTNET_MPC_EXECUTOR = 0x6804961167C3C8Ef2bf6839DDcf51Ec1FBE800c3;

    /// @notice COTI testnet inbox used by COTI-side dapps.
    address internal constant COTI_TESTNET_INBOX = INBOX;
}
