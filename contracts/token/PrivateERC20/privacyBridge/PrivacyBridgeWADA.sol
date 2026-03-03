// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridgeERC20.sol";
import "../tokens/PrivateWrappedADA.sol";

/**
 * @title PrivacyBridgeWADA
 * @notice Bridge contract for converting between WADA and privacy-preserving p.WADA tokens
 */
contract PrivacyBridgeWADA is PrivacyBridgeERC20 {
    PrivateWrappedADA public privateWada;

    constructor(address _wada, address _privateWada) PrivacyBridgeERC20(_wada, _privateWada) {
        privateWada = PrivateWrappedADA(_privateWada);
    }
}
