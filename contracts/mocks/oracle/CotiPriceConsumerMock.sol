// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../oracle/ICotiPriceConsumer.sol";

/// @dev Test double for {ICotiPriceConsumer}: fixed rates and a shared `lastUpdated` for all symbols.
contract CotiPriceConsumerMock is ICotiPriceConsumer {
    mapping(string => uint256) internal rates;
    uint256 public metaLastUpdated;

    function setRate(string calldata base, uint256 rate_) external {
        rates[base] = rate_;
        metaLastUpdated = block.timestamp;
    }

    function sync() external {
        metaLastUpdated = block.timestamp;
    }

    function getPrice(string calldata base) external view returns (uint256) {
        return rates[base];
    }

    function getPriceWithMeta(string calldata base)
        external
        view
        returns (uint256 rate, uint256 lastUpdated, uint256 blockTimestamp)
    {
        return (rates[base], metaLastUpdated, block.timestamp);
    }
}
