// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../tokens/PrivateWrappedBTC.sol";

/**
 * @title PrivacyBridgeWBTC
 * @notice Bridge contract for converting between WBTC and privacy-preserving p.WBTC tokens
 */
contract PrivacyBridgeWBTC is PrivacyBridgeERC20 {
    PrivateWrappedBTC public privateBtc;

    constructor(address _wbtc, address _privateWbtc) PrivacyBridgeERC20(_wbtc, _privateWbtc) {
        privateBtc = PrivateWrappedBTC(_privateWbtc);
    }
}
