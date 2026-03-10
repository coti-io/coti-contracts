// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../token/PrivateERC20/tokens/PrivateWrappedEther.sol";

/**
 * @title PrivacyBridgeWETH
 * @notice Bridge contract for converting between WETH and privacy-preserving p.WETH tokens
 */
contract PrivacyBridgeWETH is PrivacyBridgeERC20 {
    

    constructor(address _weth, address _privateWeth) PrivacyBridgeERC20(_weth, _privateWeth) {
        
    }
}
