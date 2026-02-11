// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../tokens/PrivateTetherUSD.sol";

/**
 * @title PrivacyBridgeUSDT
 * @notice Bridge contract for converting between USDT and privacy-preserving p.USDT tokens
 */
contract PrivacyBridgeUSDT is PrivacyBridgeERC20 {
    PrivateTetherUSD public privateUsdt;

    constructor(address _usdt, address _privateUsdt) PrivacyBridgeERC20(_usdt, _privateUsdt) {
        privateUsdt = PrivateTetherUSD(_privateUsdt);
    }
}
