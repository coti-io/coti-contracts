// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Minimal WETH9 / WAVAX interface for wrap-on-deposit and unwrap-on-withdraw.
interface IWrappedNative {
    /// @notice Wrap native coin into the ERC-20 underlying (mints WETH/WAVAX to `msg.sender`).
    function deposit() external payable;

    /// @notice Unwrap `wad` to native coin (burns caller balance, sends native to `msg.sender`).
    function withdraw(uint256 wad) external;
}
