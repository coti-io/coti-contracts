// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../token/PrivateERC20/tokens/PrivateBridgedUSDC.sol";

/**
 * @title PrivacyBridgeUSDCe
 * @notice Bridge contract for converting between USDC.e and privacy-preserving p.USDC.e tokens
 */
contract PrivacyBridgeUSDCe is PrivacyBridgeERC20 {

    constructor(address _usdc, address _privateUsdc) PrivacyBridgeERC20(_usdc, _privateUsdc) {
        
    }
}
