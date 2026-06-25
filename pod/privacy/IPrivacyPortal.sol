// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title IPrivacyPortal
/// @notice Source-chain portal interface for locking public ERC20 collateral and minting/burning private pTokens.
/// @dev Public deposit/withdraw amounts are visible in calldata and events. Privacy-sensitive integrations should use encrypted pToken APIs where available after entering the private token system.
interface IPrivacyPortal {
    /// @notice Withdrawal lifecycle tracked by the portal.
    enum WithdrawalStatus {
        /// @notice No withdrawal exists for the id.
        None,
        /// @notice pToken transfer to the portal has been requested but not yet released.
        TransferPending,
        /// @notice Underlying collateral was released to the recipient.
        Released
    }

    /// @notice Withdrawal request state stored by withdrawal id.
    struct Withdrawal {
        /// @notice User whose pTokens are transferred into portal custody.
        address user;
        /// @notice Recipient of the public underlying ERC20.
        address recipient;
        /// @notice Public withdrawal amount.
        uint256 amount;
        /// @notice Native fee reserved for the pToken burn request after release.
        uint256 burnFee;
        /// @notice Native fee reserved for the burn callback leg.
        uint256 burnCallbackFee;
        /// @notice Async pToken transfer request that must succeed before release.
        bytes32 transferRequestId;
        /// @notice Async pToken burn request submitted after release, if submission succeeded.
        bytes32 burnRequestId;
        /// @notice Current withdrawal lifecycle status.
        WithdrawalStatus status;
    }

    /// @notice Initialize a clone portal.
    /// @param owner Owner for admin functions.
    /// @param underlyingToken Public ERC20 locked and released by this portal (WETH/WAVAX when native-wrapped).
    /// @param pToken PoD pToken minted and burned for the underlying token.
    /// @param decimals Token decimals exposed for UI compatibility.
    /// @param nativeWrappedUnderlying When true, use {depositNative} and unwrap withdrawals to native coin.
    function initialize(
        address owner,
        address underlyingToken,
        address pToken,
        uint8 decimals,
        bool nativeWrappedUnderlying
    ) external;

    /// @notice Whether this portal wraps native coin on deposit and unwraps on withdraw.
    function nativeWrappedUnderlying() external view returns (bool);

    /// @notice Lock public ERC20 and request a private pToken mint.
    /// @param recipient Address receiving private pTokens on successful async mint.
    /// @param amount Public amount to deposit; visible on-chain.
    /// @param mintCallbackFee Native fee slice for the mint callback.
    /// @return requestId Async pToken mint request id.
    function deposit(address recipient, uint256 amount, uint256 mintCallbackFee) external payable returns (bytes32 requestId);

    /// @notice Wrap native coin into the underlying WETH/WAVAX, then mint pTokens (single tx).
    /// @dev Requires {nativeWrappedUnderlying}. `msg.value` must equal `amount + mintFee` where `mintFee` is
    ///      forwarded to {IPodERC20.mint} (same as {deposit}'s `msg.value`).
    /// @param recipient Address receiving private pTokens on successful async mint.
    /// @param amount Native amount to wrap and lock (wei).
    /// @param mintCallbackFee Native fee slice for the mint callback.
    /// @return requestId Async pToken mint request id.
    function depositNative(
        address recipient,
        uint256 amount,
        uint256 mintCallbackFee
    ) external payable returns (bytes32 requestId);

    /// @notice Request withdrawal by permitting and transferring pTokens into portal custody, then releasing after async success.
    /// @dev `amount`, fees, recipient, and permit data are public. The pToken transfer must reach `RequestStatus.Success` before release.
    /// @param recipient Public underlying recipient.
    /// @param amount Public amount to withdraw.
    /// @param transferFee Native fee paid for the pToken transfer request.
    /// @param transferCallbackFee Native fee slice for the pToken transfer callback.
    /// @param burnFee Native fee paid for the pToken burn after release.
    /// @param burnCallbackFee Native fee slice for the burn callback.
    /// @param permitDeadline Permit expiry timestamp.
    /// @param v Permit signature v.
    /// @param r Permit signature r.
    /// @param s Permit signature s.
    /// @return withdrawalId Portal withdrawal id.
    /// @return transferRequestId Async pToken transfer request id.
    function requestWithdrawWithPermit(
        address recipient,
        uint256 amount,
        uint256 transferFee,
        uint256 transferCallbackFee,
        uint256 burnFee,
        uint256 burnCallbackFee,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable returns (bytes32 withdrawalId, bytes32 transferRequestId);

    /// @notice Callback entry point used by the pToken after a transfer-to-portal succeeds.
    /// @param withdrawalId Withdrawal id encoded into the pToken transfer callback data.
    function onPTokenTransferred(bytes32 withdrawalId) external;

    /// @notice Manually release a pending withdrawal after its pToken transfer request is marked successful.
    /// @param withdrawalId Withdrawal id to release.
    function triggerWithdrawalRelease(bytes32 withdrawalId) external;

    /// @notice Update or disable the external pause controller for deposits and withdrawals.
    /// @param pauseController New controller address, or zero to disable pause checks.
    function setPauseController(address pauseController) external;

    /// @notice Sweep accidental native-token balance held by the portal.
    /// @param recipient Recipient of swept native tokens.
    /// @param amount Amount to sweep.
    function sweepNative(address payable recipient, uint256 amount) external;
}
