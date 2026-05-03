// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../oracle/IStdReference.sol";

/**
 * @title MockStdReference
 * @notice Mock Band Protocol StdReference for testing CotiPriceConsumer directly.
 * @dev Allows setting arbitrary prices and lastUpdated timestamps per symbol.
 */
contract MockStdReference is IStdReference {
    mapping(string => uint256) private _rates;
    mapping(string => uint256) private _lastUpdatedBase;
    bool private _shouldRevert;

    constructor() {
        // Default: COTI at $0.05
        _rates["COTI"] = 50000000000000000;
        _lastUpdatedBase["COTI"] = block.timestamp;
    }

    function setRate(string calldata symbol, uint256 rate) external {
        _rates[symbol] = rate;
    }

    function setLastUpdatedBase(string calldata symbol, uint256 ts) external {
        _lastUpdatedBase[symbol] = ts;
    }

    function setShouldRevert(bool val) external {
        _shouldRevert = val;
    }

    function getReferenceData(
        string memory _base,
        string memory /* _quote */
    ) external view override returns (ReferenceData memory) {
        if (_shouldRevert) revert("MockStdReference: forced revert");
        return ReferenceData({
            rate: _rates[_base],
            lastUpdatedBase: _lastUpdatedBase[_base] > 0 ? _lastUpdatedBase[_base] : block.timestamp,
            lastUpdatedQuote: block.timestamp
        });
    }

    function getReferenceDataBulk(
        string[] memory _bases,
        string[] memory _quotes
    ) external view override returns (ReferenceData[] memory results) {
        results = new ReferenceData[](_bases.length);
        for (uint256 i = 0; i < _bases.length; i++) {
            results[i] = this.getReferenceData(_bases[i], _quotes[i]);
        }
    }
}
