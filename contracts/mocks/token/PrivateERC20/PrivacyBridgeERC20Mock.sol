// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/privacyBridge/PrivacyBridgeERC20.sol";

/**
 * @dev Mock contract for testing PrivacyBridgeERC20
 */
contract PrivacyBridgeERC20Mock is PrivacyBridgeERC20 {
    constructor(address _token, address _privateToken) 
        PrivacyBridgeERC20(_token, _privateToken) 
    {}
}
