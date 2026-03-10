// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateWrappedADA
 * @notice Privacy-preserving WADA token (p.WADA) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateWrappedADA is PrivateERC20 {
    constructor() PrivateERC20("Private Wrapped ADA", "p.wADA") {}

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }
}
