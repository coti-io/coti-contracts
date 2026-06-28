// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Erc7984Constants
/// @notice Shared constants for ERC-7984 explorer compatibility.
library Erc7984Constants {
    /// @dev Interface id from EIP-7984; Blockscout uses this to classify confidential tokens.
    bytes4 internal constant INTERFACE_ID = 0x4958f2a4;
}
