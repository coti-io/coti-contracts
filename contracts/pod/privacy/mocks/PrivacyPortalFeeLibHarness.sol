// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../PrivacyPortalFeeLib.sol";

/// @dev Test harness exposing {PrivacyPortalFeeLib} pure helpers.
contract PrivacyPortalFeeLibHarness {
    function packFeeConfig(uint256 fixedFee, uint256 percentageBps, uint256 maxFee)
        external
        pure
        returns (bytes32)
    {
        return PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
    }

    function resolvePortalFee(
        bytes32 packedFeeConfig,
        uint256 amount,
        uint8 decimals,
        uint256 collateralUsdRate,
        uint256 nativeUsdRate
    ) external pure returns (uint256 fee, bool usedDynamicPricing) {
        return PrivacyPortalFeeLib.resolvePortalFee(
            packedFeeConfig, amount, decimals, collateralUsdRate, nativeUsdRate
        );
    }
}
