// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/math/Math.sol";

import "./IPrivacyPortalFactory.sol";

/// @title PrivacyPortalFeeLib
/// @notice Pure fee math and packed config helpers for Privacy Portal protocol fees.
library PrivacyPortalFeeLib {
    /// @notice Percentage divisor (same as Privacy Bridge).
    uint256 internal constant FEE_DIVISOR = 1_000_000;
    /// @notice Maximum percentage units (10%).
    uint256 internal constant MAX_FEE_UNITS = 100_000;
    /// @notice USD rate scale for native conversion.
    uint256 internal constant PRICE_SCALE = 1e18;

    /// @notice Packed field overflow.
    error FeeOverflow();
    /// @notice Invalid fee configuration.
    error InvalidFeeConfiguration();

    /// @notice Pack fee config into one storage slot: uint96 fixed | uint32 bps | uint128 max.
    function packFeeConfig(uint256 fixedFee, uint256 percentageBps, uint256 maxFee)
        internal
        pure
        returns (bytes32)
    {
        if (fixedFee > type(uint96).max || maxFee > type(uint128).max) {
            revert FeeOverflow();
        }
        if (maxFee == 0 || fixedFee > maxFee || percentageBps > MAX_FEE_UNITS) {
            revert InvalidFeeConfiguration();
        }
        return bytes32(
            uint256(uint96(fixedFee)) | (uint256(uint32(percentageBps)) << 96)
                | (uint256(uint128(maxFee)) << 128)
        );
    }

    /// @notice Unpack a fee config slot.
    function unpackFeeConfig(bytes32 packed)
        internal
        pure
        returns (uint96 fixedFee, uint32 percentageBps, uint128 maxFee)
    {
        fixedFee = uint96(uint256(packed));
        percentageBps = uint32(uint256(packed >> 96));
        maxFee = uint128(uint256(packed >> 128));
    }

    /// @notice Whether a portal override slot is set (non-zero).
    function isOverrideSet(bytes32 packed) internal pure returns (bool) {
        return packed != bytes32(0);
    }

    /// @notice Decode a packed fee config slot into plain uint256 fields for UI use.
    function decodeFeeConfig(bytes32 packed) internal pure returns (PortalFeeConfig memory config) {
        (uint96 fixedFee, uint32 percentageBps, uint128 maxFee) = unpackFeeConfig(packed);
        config = PortalFeeConfig({
            fixedFee: uint256(fixedFee),
            percentageBps: uint256(percentageBps),
            maxFee: uint256(maxFee)
        });
    }

    /// @notice Bridge-equivalent floor/cap formula.
    function calculateDynamicFee(uint256 percentageFeeNative, uint256 fixedFee, uint256 maxFee)
        internal
        pure
        returns (uint256)
    {
        uint256 fee = percentageFeeNative > fixedFee ? percentageFeeNative : fixedFee;
        return fee > maxFee ? maxFee : fee;
    }

    /// @notice Resolve portal fee from packed config and live USD rates.
    /// @dev Falls back to `fixedFee` (no dynamic pricing) when `percentageBps == 0` or either rate is zero.
    function resolvePortalFee(
        bytes32 packedFeeConfig,
        uint256 amount,
        uint8 decimals,
        uint256 collateralUsdRate,
        uint256 nativeUsdRate
    ) internal pure returns (uint256 fee, bool usedDynamicPricing) {
        (uint96 fixedFee, uint32 percentageBps, uint128 maxFee) = unpackFeeConfig(packedFeeConfig);

        if (percentageBps == 0 || collateralUsdRate == 0 || nativeUsdRate == 0) {
            return (fixedFee, false);
        }

        uint256 txValueUsd = Math.mulDiv(amount, collateralUsdRate, 10 ** uint256(decimals));
        uint256 percentageFeeUsd = Math.mulDiv(txValueUsd, percentageBps, FEE_DIVISOR);
        uint256 percentageFeeNative = Math.mulDiv(percentageFeeUsd, PRICE_SCALE, nativeUsdRate);
        fee = calculateDynamicFee(percentageFeeNative, fixedFee, maxFee);
        return (fee, true);
    }
}
