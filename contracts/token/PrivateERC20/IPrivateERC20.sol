// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../utils/mpc/MpcCore.sol";

/**
 * @dev Interface of the COTI Private ERC-20 standard.
 */
interface IPrivateERC20 {
    struct Allowance {
        ctUint256 ciphertext;
        ctUint256 ownerCiphertext;
        ctUint256 spenderCiphertext;
    }

    /**
     * @dev Emitted when `senderValue/receiverValue` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `senderValue/receiverValue` may be zero.
     */
    event Transfer(
        address indexed from,
        address indexed to,
        ctUint256 senderValue,
        ctUint256 receiverValue
    );

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `ownerValue` and `spenderValue` are the new allowance encrypted with the respective users AES key.
     */
    event Approval(
        address indexed owner,
        address indexed spender,
        ctUint256 ownerValue,
        ctUint256 spenderValue
    );

    /**
     * @dev Returns the value of tokens in existence.
     *      For privacy, the base implementation always returns 0; aggregate supply is not exposed
     *      on-chain by default. Implementations may optionally add encrypted supply tracking and
     *      reencryption for a designated party (e.g. owner) if they accept the reduced privacy
     *      tradeoff for that metric.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account` encrypted with their AES key.
     */
    function balanceOf(
        address account
    ) external view returns (ctUint256 memory);

    /**
     * @dev Returns the value of tokens owned by the caller.
     */
    function balanceOf() external returns (gtUint256);

    /**
     * @dev Reencrypts the caller's balance using the AES key of `addr`.
     */
    function setAccountEncryptionAddress(address addr) external returns (bool);

    /**
     * @dev Returns whether clear public `uint256` operations are currently enabled
     *      for this token (mint, burn, transfer, transferFrom, approve, transferAndCall
     *      variants that take plain amounts).
     */
    function publicAmountsEnabled() external view returns (bool);

    /**
     * @dev Enables or disables operations that use clear public `uint256` amounts
     *      (mint, burn, transfer, transferFrom, approve, transferAndCall with uint256).
     *      Intended for token admins that want to disallow public value usage and
     *      enforce encrypted-only flows.
     */
    function setPublicAmountsEnabled(bool enabled) external;

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     * Callers must check or decrypt the return value; this variant does not revert on failure.
     *
     * Emits a {Transfer} event.
     */
    function transfer(
        address to,
        itUint256 calldata value
    ) external returns (gtBool);

    /**
     * @dev Moves a public `amount` of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

    /**
     * @dev Moves a garbled-text `value` amount of tokens from the caller's account to `to`.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     * Callers must check or decrypt the return value; this variant does not revert on failure.
     *
     * Emits a {Transfer} event.
     */
    function transferGT(address to, gtUint256 value) external returns (gtBool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(
        address owner,
        address spender
    ) external view returns (Allowance memory);

    /**
     * @dev Returns the remaining number of tokens that `account` will be
     * allowed to spend on behalf of the caller through {transferFrom} (or vice
     * versa depending on the value of `isSpender`). This is zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address account, bool isSpender) external returns (gtUint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(
        address spender,
        itUint256 calldata value
    ) external returns (bool);

    /**
     * @dev Sets a public `amount` as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Sets a garbled-text `value` as the allowance of `spender` over the
     * caller's tokens.
     *
     * Emits an {Approval} event.
     */
    function approveGT(address spender, gtUint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Reverts if the transfer fails. On success, returns an encrypted true.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        itUint256 calldata value
    ) external returns (gtBool);

    /**
     * @dev Moves a public `amount` of tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Reverts if the transfer fails. Returns true on success.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    /**
     * @dev Moves a garbled-text `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's allowance.
     *
     * Reverts if the transfer fails. On success, returns an encrypted true.
     *
     * Emits a {Transfer} event.
     */
    function transferFromGT(address from, address to, gtUint256 value) external returns (gtBool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`, and then calls `onTokenReceived` on `to`.
     * @param to The address of the recipient
     * @param amount The amount of tokens to be transferred
     * @param data Additional data with no specified format, sent in call to `to`
     * @return A boolean value indicating whether the operation succeeded
     */
    function transferAndCall(
        address to,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);

    /**
     * @dev Moves an input-text (encrypted) `amount` of tokens from the caller's account to `to`,
     *      and then calls `onTokenReceived(sender, 0, data)` on `to`. For privacy, the callback
     *      receives 0 as the amount argument; integrators must not rely on the amount parameter
     *      in the callback for this variant.
     * @param to The address of the recipient
     * @param amount Encrypted input-text amount to be transferred
     * @param data Additional data with no specified format, sent in call to `to`
     * @return An encrypted boolean value indicating whether the operation succeeded
     */
    function transferAndCall(
        address to,
        itUint256 calldata amount,
        bytes calldata data
    ) external returns (gtBool);

    /**
     * @dev Creates `amount` public tokens and assigns them to `to`, increasing the total supply.
     *
     * Returns a boolean value indicating whether the operation succeeded (decrypted from gtBool).
     */
    function mint(address to, uint256 amount) external returns (bool);

    /**
     * @dev Creates `amount` input-text (encrypted) tokens and assigns them to `to`, increasing the total supply.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     */
    function mint(address to, itUint256 calldata amount) external returns (gtBool);

    /**
     * @dev Creates `amount` garbled-text tokens and assigns them to `to` without re-wrapping.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     */
    function mintGt(address to, gtUint256 amount) external returns (gtBool);

    /**
     * @dev Destroys `amount` public tokens from the caller.
     *
     * Returns a boolean value indicating whether the operation succeeded (decrypted from gtBool).
     */
    function burn(uint256 amount) external returns (bool);

    /**
     * @dev Destroys `amount` input-text (encrypted) tokens from the caller.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     * Callers must check or decrypt the return value; this variant does not revert on failure.
     */
    function burn(itUint256 calldata amount) external returns (gtBool);

    /**
     * @dev Destroys `amount` garbled-text tokens from the caller without re-wrapping.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     * Callers must check or decrypt the return value; this variant does not revert on failure.
     */
    function burnGt(gtUint256 amount) external returns (gtBool);
}
