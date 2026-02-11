// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateTetherUSD
 * @notice Privacy-preserving USDT token (p.USDT) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateTetherUSD is PrivateERC20 {
    constructor() PrivateERC20("Private Tether USD", "p.USDT") {}

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }
}
