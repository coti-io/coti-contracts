// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ICotiPriceConsumer
 * @notice Minimal interface for the CotiPriceConsumer oracle used by the bridge
 */
interface ICotiPriceConsumer {
   
    /// @notice Returns the rate for an arbitrary base/USD pair scaled by 1e18.
    function getPrice(string calldata _base) external view returns (uint256);

    /// @notice Returns rate + metadata for any base/USD pair.
    function getPriceWithMeta(string calldata _base) external view returns (uint256 rate, uint256 lastUpdated, uint256 blockTimestamp);
}
