// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../token/PrivateERC20/tokens/PrivateWrappedEther.sol";

/**
 * @title PrivacyBridgeWETH
 * @notice Bridge contract for converting between WETH and privacy-preserving p.WETH tokens
 */
contract PrivacyBridgeWETH is PrivacyBridgeERC20 {
    address public constant WETH = 0x8bca4e6bbE402DB4aD189A316137aD08206154FB;
    address public constant pWETH = 0xc79fC578D7Fe1677c72F88cAdD63D9199D56ebe0;

    constructor() PrivacyBridgeERC20(WETH, pWETH) {
        
    }
}
