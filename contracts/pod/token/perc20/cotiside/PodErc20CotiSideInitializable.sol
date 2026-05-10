// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PodErc20CotiSide.sol";

/// @title PodErc20CotiSideInitializable
/// @notice Minimal-clone friendly COTI-side pToken ledger.
contract PodErc20CotiSideInitializable is PodErc20CotiSide {
    /// @notice Lock the implementation instance with placeholder addresses.
    constructor() PodErc20CotiSide(address(1), address(1)) {}

    /// @notice Initialize a COTI-side pToken clone.
    /// @param inboxAddress COTI-side inbox allowed to call remote entry points.
    /// @param initialOwner Owner of the clone.
    function initialize(address inboxAddress, address initialOwner) external {
        _initializePodErc20CotiSide(inboxAddress, initialOwner);
    }
}
