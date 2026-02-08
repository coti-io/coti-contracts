// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateWrappedEther
 * @notice Privacy-preserving WETH token (p.WETH) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateWrappedEther is PrivateERC20 {
    constructor() PrivateERC20("Private WETH", "p.WETH") {}


}
