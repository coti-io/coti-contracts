// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IStdReference.sol";

/**
 * @title CotiPriceConsumer
 * @notice Retrieves token/USD prices from the Band Protocol oracle.
 * @dev All prices returned by Band Protocol are scaled by 1e18.
 *      For example, a rate of 50000000000000000 means $0.05.
 */
contract CotiPriceConsumer {
    /// @notice Band Protocol StdReferenceProxy on COTI .
    IStdReference public immutable ref;

    /// @notice Maximum acceptable age (in seconds) for oracle data before it is considered stale.
    uint256 public maxStaleness;

    /// @notice Emitted when the staleness threshold is updated.
    event MaxStalenessUpdated(uint256 oldValue, uint256 newValue);

    /// @notice Thrown when the oracle data is older than the allowed staleness window.
    error StaleOracleData(uint256 lastUpdated, uint256 threshold);

    address public owner;

    /// @notice Minimum allowed staleness threshold (1 hour).
    uint256 public constant MIN_STALENESS = 1 hours;

    /// @notice Thrown when the staleness value is below the minimum.
    error StalenessTooLow(uint256 provided, uint256 minimum);

    modifier onlyOwner() {
        require(msg.sender == owner, "CotiPriceConsumer: caller is not the owner");
        _;
    }

    /**
     * @param _ref          Address of the Band Protocol StdReferenceProxy contract.
     * @param _maxStaleness Maximum acceptable data age in seconds (0 = no staleness check).
     */
    constructor(address _ref, uint256 _maxStaleness) {
        require(_ref != address(0), "CotiPriceConsumer: zero ref address");
        if (_maxStaleness < MIN_STALENESS) revert StalenessTooLow(_maxStaleness, MIN_STALENESS);
        ref = IStdReference(_ref);
        maxStaleness = _maxStaleness;
        owner = msg.sender;
    }

    /// @notice Returns the rate, last update timestamp, and current block timestamp for any base/USD pair.
    /// @return rate           The price scaled by 1e18
    /// @return lastUpdated    Block timestamp when the oracle data was last updated
    /// @return blockTimestamp The current block.timestamp
    function getPriceWithMeta(string calldata _base) external view returns (uint256 rate, uint256 lastUpdated, uint256 blockTimestamp) {
        IStdReference.ReferenceData memory data = _getPrice(_base);
        rate = data.rate;
        lastUpdated = data.lastUpdatedBase;
        blockTimestamp = block.timestamp;
    }


    // ──────────────────────────────────────────────────────────────────────
    //  Internal helper
    // ──────────────────────────────────────────────────────────────────────

    /**
     * @dev Queries the Band oracle for `_base`/USD and optionally enforces staleness.
     */
    function _getPrice(string memory _base) internal view returns (IStdReference.ReferenceData memory data) {
        data = ref.getReferenceData(_base, "USD");

        uint256 threshold = block.timestamp - maxStaleness;
        if (data.lastUpdatedBase < threshold) {
            revert StaleOracleData(data.lastUpdatedBase, threshold);
        }
    }


    // ──────────────────────────────────────────────────────────────────────
    //  Generic getter — query any symbol the oracle supports
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Returns the rate for an arbitrary base/USD pair scaled by 1e18.
    function getPrice(string calldata _base) external view returns (uint256) {
        return _getPrice(_base).rate;
    }


    /// @notice Returns the full ReferenceData for an arbitrary base/USD pair.
    function getPriceData(string calldata _base) external view returns (IStdReference.ReferenceData memory) {
        return _getPrice(_base);
    }

    /**
     * @notice Updates the maximum staleness threshold.
     * @param _maxStaleness New threshold in seconds (0 = disable check).
     */
    function setMaxStaleness(uint256 _maxStaleness) external onlyOwner {
        if (_maxStaleness < MIN_STALENESS) revert StalenessTooLow(_maxStaleness, MIN_STALENESS);
        emit MaxStalenessUpdated(maxStaleness, _maxStaleness);
        maxStaleness = _maxStaleness;
    }
}
