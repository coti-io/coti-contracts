// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../privacyBridge/PrivacyBridgeERC20.sol";

/**
 * @dev Mock contract for testing PrivacyBridgeERC20
 */
contract PrivacyBridgeERC20Mock is PrivacyBridgeERC20 {
    constructor(
        address _token,
        address _privateToken,
        string memory _tokenSymbol,
        address _feeRecipient,
        address _rescueRecipient,
        address _priceOracle
    ) PrivacyBridgeERC20(_token, _privateToken, _tokenSymbol, _feeRecipient, _rescueRecipient, _priceOracle) {}
}
