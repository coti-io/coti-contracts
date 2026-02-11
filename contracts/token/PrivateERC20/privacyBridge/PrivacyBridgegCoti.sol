// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../tokens/PrivateCOTITreasuryGovernanceToken.sol";

/**
 * @title PrivacyBridgegCoti
 * @notice Bridge contract for converting between gCOTI and privacy-preserving p.gCOTI tokens
 */
contract PrivacyBridgegCoti is PrivacyBridgeERC20 {
    PrivateCOTITreasuryGovernanceToken public privategCoti;

    constructor(address _gCoti, address _privategCoti) PrivacyBridgeERC20(_gCoti, _privategCoti) {
        privategCoti = PrivateCOTITreasuryGovernanceToken(_privategCoti);
    }
}
