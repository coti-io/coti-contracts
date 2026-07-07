// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../token/PrivateERC20/tokens/PrivateNight.sol";

/**
 * @title PrivacyBridgeNight
 * @notice Bridge contract for converting between NIGHT and privacy-preserving p.NIGHT tokens
 */
contract PrivacyBridgeNight is PrivacyBridgeERC20 {


    constructor(
        address _night,
        address _privateNight,
        address _feeRecipient,
        address _rescueRecipient,
        address _priceOracle
    ) PrivacyBridgeERC20(_night, _privateNight, "NIGHT", _feeRecipient, _rescueRecipient, _priceOracle) {

    }
}
