// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../tokens/PrivateBridgedUSDC.sol";

/**
 * @title PrivacyBridgeUSDCe
 * @notice Bridge contract for converting between USDC.e and privacy-preserving p.USDC.e tokens
 */
contract PrivacyBridgeUSDCe is PrivacyBridgeERC20 {
    PrivateBridgedUSDC public privateUsdc;

    constructor(address _usdc, address _privateUsdc) PrivacyBridgeERC20(_usdc, _privateUsdc) {
        privateUsdc = PrivateBridgedUSDC(_privateUsdc);
    }
}
