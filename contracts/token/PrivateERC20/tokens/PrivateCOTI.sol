// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateCOTI
 * @notice Privacy-preserving COTI token (COTI.p) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateCOTI is PrivateERC20 {
    constructor() PrivateERC20("Private COTI", "p.COTI") {}
}
