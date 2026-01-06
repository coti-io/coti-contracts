// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../utils/mpc/MpcCore.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @dev Interface of the PrivateERC20 standard as defined in the EIP.
 * Updated to include ERC-7984 improvements:
 * - Introspection (IERC165)
 * - Encrypted Total Supply (confidentialTotalSupply)
 * - ERC-1363 (transferAndCall)
 */
interface IPrivateERC20 is IERC165 {
    struct Allowance {
        ctUint64 ciphertext;
        ctUint64 ownerCiphertext;
        ctUint64 spenderCiphertext;
    }

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     */
    event Transfer(address indexed from, address indexed to, ctUint64 value, ctUint64 toValue);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, ctUint64 value, ctUint64 spenderValue);

    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);

    /**
     * @dev Returns the amount of tokens in existence (Public visibility).
     * Usually returns 0 for private tokens.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens in existence (Confidential visibility).
     * Returns a valid ciphertext of the total supply.
     */
    function confidentialTotalSupply() external view returns (ctUint64);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (ctUint64);

    /**
     * @dev Returns the amount of tokens owned by the caller.
     */
    function balanceOf() external returns (gtUint64);
    
    /**
     * @dev Returns the address used to equate the `account` balance.
     */
    function accountEncryptionAddress(address account) external view returns (address);

    /**
     * @dev Sets the address used to equate the caller balance.
     */
    function setAccountEncryptionAddress(address account) external returns (bool);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, itUint64 calldata amount) external returns (gtBool);
    
    function transfer(address to, gtUint64 amount) external returns (gtBool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, itUint64 calldata amount) external returns (gtBool);

    function transferFrom(address from, address to, gtUint64 amount) external returns (gtBool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (Allowance memory);

    function allowance(address account, bool isSpender) external returns (gtUint64);

    function reencryptAllowance(address account, bool isSpender) external returns (bool);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
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
    function approve(address spender, itUint64 calldata amount) external returns (bool);

    function approve(address spender, gtUint64 amount) external returns (bool);

    // =============================================================
    // ERC-1363 Extensions
    // =============================================================

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`
     * and then calls `onTransferReceived` on `to`.
     * @param to The address which you want to transfer to
     * @param amount The amount of tokens to be transferred
     * @param data Additional data with no specified format, sent in call to `to`
     * @return A boolean value indicating whether the operation succeeded unless throwing
     */
    function transferAndCall(address to, itUint64 calldata amount, bytes calldata data) external returns (gtBool);

    function transferAndCall(address to, uint64 amount, bytes calldata data) external returns (gtBool);
}
