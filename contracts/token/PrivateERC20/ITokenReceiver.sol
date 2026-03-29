// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/**
 * @dev Interface for receiving Private ERC-20 tokens via `transferAndCall` with a **public** `uint256` amount.
 *
 * For `transferAndCall` with an **encrypted** `itUint256` amount, use {ITokenReceiverEncrypted} instead —
 * the amount must not be passed in plaintext in the callback.
 */
interface ITokenReceiver {
    function onTokenReceived(
        address from,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
}
