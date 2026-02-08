// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../PrivateERC20.sol";

/**
 * @title PrivateCOTITreasuryGovernanceToken
 * @notice Privacy-preserving gCOTI token (p.gCOTI) using COTI's Multi-Party Computation (MPC)
 * @dev Extends PayableToken for role-based minting/burning and bridge operations
 */
contract PrivateCOTITreasuryGovernanceToken is PrivateERC20 {
    constructor() PrivateERC20("Private COTI Treasury Governance Token", "p.gCOTI") {}




}
