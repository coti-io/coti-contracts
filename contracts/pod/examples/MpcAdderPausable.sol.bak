// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";

import "./MpcAdder.sol";

/// @title MpcAdderPausable
/// @notice Same as {MpcAdder}, but `receiveC` reverts while paused (simulates callback failure until unpaused).
contract MpcAdderPausable is MpcAdder, Pausable {
    constructor(address _inbox) MpcAdder(_inbox) {}

    /// @inheritdoc MpcAdder
    function receiveC(bytes memory data) external override onlyInbox whenNotPaused {
        _receiveResult(data);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
