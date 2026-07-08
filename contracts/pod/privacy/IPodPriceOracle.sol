// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPodPriceOracle
/// @notice Live USD price reads keyed by ERC-20 token address (18-decimal USD per whole token).
/// @dev Must stay in sync with coti-pod-inbox-contracts/contracts/fee/IPodPriceOracle.sol
///
/// Implemented by {PoDPriceOracle} (portal + inbox), {BandLiveOracle}, and {ChainlinkLiveOracle}.
/// Feed adapters never revert; return `0` when a feed is unset, stale, or failed.
/// Zero rates make {PrivacyPortalFeeLib.resolvePortalFee} skip dynamic pricing (fixed fee only).
interface IPodPriceOracle {
    /// @notice Live USD price for `token`.
    function getLivePrice(address token) external view returns (uint256 priceUsd);

    /// @notice Live USD prices for two tokens in one call (Band may bulk internally).
    function getLivePrices(address tokenA, address tokenB)
        external
        view
        returns (uint256 priceA, uint256 priceB);
}
