// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../token/PrivateERC20/tokens/PrivateCOTITreasuryGovernanceToken.sol";

/**
 * @title PrivacyBridgegCoti
 * @notice Bridge contract for converting between gCOTI and privacy-preserving p.gCOTI tokens
 */
contract PrivacyBridgegCoti is PrivacyBridgeERC20 {
    

    constructor(address _gCoti, address _privategCoti, address _feeRecipient, address _rescueRecipient) PrivacyBridgeERC20(_gCoti, _privategCoti, "GCOTI", _feeRecipient, _rescueRecipient) {
        
    }
}
