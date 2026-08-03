// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IStdReference
/// @notice Minimal Band Protocol StdReference interface (no npm dependency).
/// @dev Canonical SoT for Band lookups used by PoD inbox fee adapters and COTI oracle helpers.
///      Implementations are trusted for rate correctness; callers validate staleness and non-zero rates.
interface IStdReference {
    /// @notice Band reference quote: `rate` is base/quote scaled by 1e18.
    struct ReferenceData {
        uint256 rate;
        uint256 lastUpdatedBase;
        uint256 lastUpdatedQuote;
    }

    /// @notice Single base/quote pair lookup.
    function getReferenceData(string memory base, string memory quote)
        external
        view
        returns (ReferenceData memory);

    /// @notice Parallel lookup for multiple pairs (same-length arrays).
    function getReferenceDataBulk(string[] memory bases, string[] memory quotes)
        external
        view
        returns (ReferenceData[] memory);
}
