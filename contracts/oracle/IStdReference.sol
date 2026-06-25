// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IStdReference
 * @notice Band Protocol Standard Reference interface for querying price data.
 */
interface IStdReference {
    struct ReferenceData {
        uint256 rate;            // base/quote exchange rate, scaled by 1e18
        uint256 lastUpdatedBase; // UNIX epoch when the base price was last updated
        uint256 lastUpdatedQuote; // UNIX epoch when the quote price was last updated
    }

    /// @notice Returns the price data for a single base/quote pair.
    function getReferenceData(
        string memory _base,
        string memory _quote
    ) external view returns (ReferenceData memory);

    /// @notice Returns the price data for multiple base/quote pairs.
    function getReferenceDataBulk(
        string[] memory _bases,
        string[] memory _quotes
    ) external view returns (ReferenceData[] memory);
}
