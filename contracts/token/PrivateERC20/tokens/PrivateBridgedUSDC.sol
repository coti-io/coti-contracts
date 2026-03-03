// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateBridgedUSDC
 * @notice Privacy-preserving USDC.e token (p.USDC.e) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateBridgedUSDC is PrivateERC20 {
    constructor() PrivateERC20("Private Bridged USDC", "p.USDC.e") {}

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }
}
