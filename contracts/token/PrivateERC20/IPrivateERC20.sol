// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../utils/mpc/MpcCore.sol";

/**
 * @dev Interface of the COTI Private ERC-20 standard.
 */
interface IPrivateERC20 {
    struct Allowance {
        ctUint64 ciphertext;
        ctUint64 ownerCiphertext;
        ctUint64 spenderCiphertext;
    }
    
    /**
     * @dev Emitted when `senderValue/receiverValue` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `senderValue/receiverValue` may be zero.
     */
    event Transfer(address indexed from, address indexed to, ctUint64 senderValue, ctUint64 receiverValue);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `ownerValue` and `spenderValue` are the new allowance encrypted with the respective users AES key.
     */
    event Approval(address indexed owner, address indexed spender, ctUint64 ownerValue, ctUint64 spenderValue);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account` encrypted with their AES key.
     */
    function balanceOf(address account) external view returns (ctUint64);

    /**
     * @dev Returns the value of tokens owned by the caller.
     */
    function balanceOf() external returns (gtUint64);

    /**
     * @dev Reencrypts the caller's balance using the AES key of `addr`.
     */
    function setAccountEncryptionAddress(address addr) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, itUint64 calldata value) external returns (gtBool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, gtUint64 value) external returns (gtBool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (Allowance memory);

    /**
     * @dev Returns the remaining number of tokens that `account` will be
     * allowed to spend on behalf of the caller through {transferFrom} (or vice
     * versa depending on the value of `isSpender`). This is zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address account, bool isSpender) external returns (gtUint64);

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
    function approve(address spender, itUint64 calldata value) external returns (bool);

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
    function approve(address spender, gtUint64 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, itUint64 calldata value) external returns (gtBool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns an encrypted boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, gtUint64 value) external returns (gtBool);
}