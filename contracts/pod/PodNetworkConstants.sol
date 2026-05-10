// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/// @title PodNetworkConstants
/// @notice Deployment constants used by chain-specific PoD dapp helper contracts.
library PodNetworkConstants {
    /// @notice Source-chain inbox used by PoD dapps on Sepolia.
    address internal constant SEPOLIA_INBOX = 0xFa158f9e49C8bb77f971c3630EbCD23a8a88D14E;

    /// @notice COTI testnet chain id used for remote MPC execution.
    uint256 internal constant COTI_TESTNET_CHAIN_ID = 7082400;

    /// @notice COTI-side MPC executor paired with Sepolia PoD dapps.
    address internal constant COTI_TESTNET_MPC_EXECUTOR = 0xC76aaE4F3810fBBd5d96b92DEFeBE0034405Ad9c;

    /// @notice COTI testnet inbox used by COTI-side dapps.
    address internal constant COTI_TESTNET_INBOX = 0x0f9A5cD00450Db1217839C35D23D56F96d6331AE;
}
