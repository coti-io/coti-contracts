// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPodPriceOracle.sol";

/// @notice Unpacked portal fee parameters (`fixedFee` and `maxFee` in native wei; `percentageBps` / 1_000_000).
struct PortalFeeConfig {
    uint256 fixedFee;
    uint256 percentageBps;
    uint256 maxFee;
}

/// @notice Pause flags exposed by the factory to portal clones.
interface IPrivacyPortalPauseController {
    /// @notice Whether new withdrawal requests should revert.
    function withdrawalsPaused() external view returns (bool);

    /// @notice Whether new deposits / wraps should revert.
    function depositsPaused() external view returns (bool);
}

/// @title IPrivacyPortalFactory
/// @notice Factory surface used by portal clones for pause control and fee configuration.
interface IPrivacyPortalFactory is IPrivacyPortalPauseController {
    /// @notice Recipient of swept portal protocol fees.
    function feeRecipient() external view returns (address);

    /// @notice Wrapped native token on this chain (WETH/WAVAX) used for portal fee gas pricing.
    function nativeToken() external view returns (address);

    /// @notice Optional USD oracle for dynamic portal fees; zero disables dynamic pricing.
    function priceOracle() external view returns (IPodPriceOracle);

    /// @notice Factory default packed deposit fee config.
    function defaultDepositFeePacked() external view returns (bytes32);

    /// @notice Factory default packed withdraw fee config.
    function defaultWithdrawFeePacked() external view returns (bytes32);

    /// @notice Estimate deposit portal fee for an underlying and amount.
    function estimateDepositPortalFee(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 fee, bool usedDynamicPricing);

    /// @notice Estimate withdraw portal fee for an underlying and amount.
    function estimateWithdrawPortalFee(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 fee, bool usedDynamicPricing);

    /// @notice Live-oracle deposit portal fee floor for tx validation.
    function getDepositPortalFeeFloor(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 floor, uint128 maxFee);

    /// @notice Live-oracle withdraw portal fee floor for tx validation.
    function getWithdrawPortalFeeFloor(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 floor, uint128 maxFee);

    /// @notice Factory default fee config for deposits (`isDeposit == true`) or withdrawals.
    function getFeeConfig(bool isDeposit) external view returns (PortalFeeConfig memory config);

    /// @notice Decode any packed fee config slot (e.g. from storage or events).
    function decodeFeeConfig(bytes32 packed) external pure returns (PortalFeeConfig memory config);
}
