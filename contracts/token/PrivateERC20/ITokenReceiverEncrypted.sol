// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/**
 * @dev Callback for the **encrypted-amount** `transferAndCall(to, itUint256, data)` overload on {PrivateERC20}.
 *
 * The transferred amount is intentionally **not** passed in plaintext to the callback. Receivers that
 * handle private transfers must implement this interface. Do **not** use {ITokenReceiver} for that
 * overload — its `amount` parameter cannot carry the real value without breaking privacy.
 *
 * Integrators: derive any needed amount context from `data` you control, or from off-chain decryption
 * of {Transfer} events / balances — not from a callback `amount` field.
 */
interface ITokenReceiverEncrypted {
    function onPrivateTransferReceived(
        address from,
        bytes calldata data
    ) external returns (bool);
}
