// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateWrappedBTC
 * @notice Privacy-preserving WBTC token (p.WBTC) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateWrappedBTC is PrivateERC20 {
    constructor() PrivateERC20("Private Wrapped BTC", "p.WBTC") {}

    function decimals() public view virtual override returns (uint8) {
        return 8;
    }
}
