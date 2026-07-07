// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateNight
 * @notice Privacy-preserving NIGHT token (p.NIGHT) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateNight is PrivateERC20 {
    constructor() PrivateERC20("Private Night", "p.NIGHT") {}

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }
}
