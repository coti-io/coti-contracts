// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../../utils/mpc/MpcCore.sol";

/**
 * @title IPodErc20CotiSide
 * @notice Entry points the COTI inbox invokes for a paired {PodERC20}: balance/allowance ciphertext on-chain, MPC garbling in memory, and `respond`/`raise` wiring.
 * @dev Implementations must restrict callers to the inbox and to the configured remote `PodERC20`. `transferFrom` does not carry
 *      `msg.sender` as spender on this chain—allowance must be enforced before the cross-chain message is sent.
 */
interface IPodErc20CotiSide {
    /**
     * @notice Owner-only mint of plain `amount` into balance ciphertext storage for `to` (bridge / test setup).
     * @dev Does not automatically update PoD ciphertext; use {syncBalances} on `PodERC20` after minting if mirrors must match.
     *      Kept distinct from the inbox-called {mint} / {mintPublic} so `.selector` access stays unambiguous.
     */
    function ownerMint(address to, uint256 amount) external;

    /**
     * @notice Inbox-only mint with garbled `value`; responds with a {PodERC20.transferCallback}-shaped tuple so PoD updates `to`'s ciphertext.
     */
    function mint(address to, gtUint256 value) external;

    /**
     * @notice Inbox-only mint using a plain `amount`; COTI garbles via `MpcCore.setPublic256` and responds as in {mint}.
     */
    function mintPublic(address to, uint256 amount) external;

    /**
     * @notice For each account, `onBoard`s stored balance ciphertext, `offBoardToUser`s to that address, and `respond`s with `(addresses, amounts, nonce)`.
     * @dev **Gotcha:** empty `accounts` should be rejected by the implementation; otherwise PoD may receive useless callbacks.
     */
    function syncBalances(address[] calldata accounts) external;

    /**
     * @notice Moves `value` garbled tokens from `from` to `to` if balance suffices, then `respond`s with the PoD transfer tuple.
     * @dev **Gotcha:** locks on PoD are tracked separately; this function assumes the inbox message is well-formed.
     */
    function transfer(address from, address to, gtUint256 value) external;

    /**
     * @notice Plain-amount variant of {transfer}; COTI garbles via `MpcCore.setPublic256`.
     */
    function transferPublic(address from, address to, uint256 value) external;

    /**
     * @notice Legacy same MPC move as {transfer}; kept for compatibility with older PoD tokens.
     * @dev New allowance-based integrations should use {transferFromAsSpender}.
     */
    function transferFrom(address from, address to, gtUint256 value) external;

    /**
     * @notice Legacy plain-amount variant of {transferFrom}; kept for compatibility with older PoD tokens.
     */
    function transferFromPublic(address from, address to, uint256 value) external;

    /**
     * @notice Spender-aware transferFrom that consumes allowance on COTI before moving garbled `value`.
     */
    function transferFromAsSpender(address spender, address from, address to, gtUint256 value) external;

    /**
     * @notice Plain-amount variant of {transferFromAsSpender}.
     */
    function transferFromPublicAsSpender(address spender, address from, address to, uint256 value) external;

    /**
     * @notice Sets garbled allowance and `respond`s with owner- and spender-specific ciphertext of the same allowance amount.
     * @dev On invalid addresses the implementation should `raise` rather than revert if you need PoD `approveError` symmetry.
     */
    function approve(address owner, address spender, gtUint256 value) external;

    /**
     * @notice Plain-amount variant of {approve}; COTI garbles via `MpcCore.setPublic256`.
     */
    function approvePublic(address owner, address spender, uint256 value) external;

    /**
     * @notice Subtracts `value` from `from` and responds with a burn-shaped tuple (`to == 0`, zero ciphertexts for receiver side).
     */
    function burn(address from, gtUint256 value) external;

    /**
     * @notice Plain-amount variant of {burn}; COTI garbles via `MpcCore.setPublic256`.
     */
    function burnPublic(address from, uint256 value) external;
}
