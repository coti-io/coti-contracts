// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../token/PrivateERC20/tokens/PrivateWrappedADA.sol";

/**
 * @title PrivacyBridgeWADA
 * @notice Bridge contract for converting between WADA and privacy-preserving p.WADA tokens
 */
contract PrivacyBridgeWADA is PrivacyBridgeERC20 {
    

    constructor(address _wada, address _privateWada) PrivacyBridgeERC20(_wada, _privateWada) {
        
    }
}
