// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPrivacyPortalFactory.sol";

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
        Released,
        /// @notice Async pToken transfer failed; withdrawal abandoned without releasing collateral.
        Failed
    }

    /// @notice Deposit escrow lifecycle for collateral locked pending async mint.
    enum DepositEscrowStatus {
        /// @notice No escrow exists for the mint request id.
        None,
        /// @notice Underlying is locked awaiting mint success or failure.
        Pending,
        /// @notice Mint request hit an Inbox system error; collateral is eligible for refund.
        Failed,
        /// @notice Underlying was returned to the depositor after a failed mint.
        Refunded
    }

    /// @notice Escrow of public collateral locked for an async pToken mint.
    struct DepositEscrow {
        /// @notice User who deposited the underlying (refund recipient).
        address user;
        /// @notice Intended pToken mint recipient.
        address recipient;
        /// @notice Locked underlying amount.
        uint256 amount;
        /// @notice Escrow lifecycle status.
        DepositEscrowStatus status;
    }

    /// @notice Withdrawal request state stored by withdrawal id.
    struct Withdrawal {
        /// @notice User whose pTokens are transferred into portal custody.
        address user;
        /// @notice Recipient of the public underlying ERC20.
        address recipient;
        /// @notice Public withdrawal amount.
        uint256 amount;
        /// @notice Async pToken transfer request that must succeed before release.
        bytes32 transferRequestId;
        /// @notice Current withdrawal lifecycle status.
        WithdrawalStatus status;
    }

    /// @notice Initialize a clone portal.
    /// @param underlyingToken Public ERC20 locked and released by this portal (WETH/WAVAX when native-wrapped).
    /// @param pToken PoD pToken minted and burned for the underlying token.
    /// @param decimals Token decimals exposed for UI compatibility.
    /// @param nativeWrappedUnderlying When true, {depositNative} accepts native coin (wraps in-contract); withdraw releases wrapped underlying ERC20.
    /// @param factory PrivacyPortalFactory (admin, fees, pause, blacklist, rescue, operators).
    function initialize(
        address underlyingToken,
        address pToken,
        uint8 decimals,
        bool nativeWrappedUnderlying,
        address factory
    ) external;

    /// @notice Factory that created / binds this portal.
    function factory() external view returns (address);

    /// @notice Whether this portal accepts native coin on deposit via {depositNative}.
    function nativeWrappedUnderlying() external view returns (bool);

    /// @notice Accumulated portal protocol fees awaiting sweep.
    function accumulatedPortalFees() external view returns (uint256);

    /// @notice pToken amount held in portal custody pending factory-admin batch burn.
    function pendingBurnAmount() external view returns (uint256);

    /// @notice Lock public ERC20 and request a private pToken mint.
    /// @param recipient Address receiving private pTokens on successful async mint.
    /// @param amount Public amount to deposit; visible on-chain.
    /// @param portalFee Portal protocol fee collected by this portal.
    /// @param mintCallbackFee Native fee slice for the mint callback.
    /// @return requestId Async pToken mint request id.
    function deposit(address recipient, uint256 amount, uint256 portalFee, uint256 mintCallbackFee)
        external
        payable
        returns (bytes32 requestId);

    /// @notice Wrap native coin into the underlying WETH/WAVAX, then mint pTokens (single tx).
    /// @dev Requires {nativeWrappedUnderlying}. `msg.value` must equal `amount + mintFee + portalFee`.
    /// @param recipient Address receiving private pTokens on successful async mint.
    /// @param amount Native amount to wrap and lock (wei).
    /// @param portalFee Portal protocol fee collected by this portal.
    /// @param mintCallbackFee Native fee slice for the mint callback.
    /// @return requestId Async pToken mint request id.
    function depositNative(
        address recipient,
        uint256 amount,
        uint256 portalFee,
        uint256 mintCallbackFee
    ) external payable returns (bytes32 requestId);

    /// @notice Request withdrawal by permitting and transferring pTokens into portal custody, then releasing after async success.
    /// @dev `msg.value` must equal `transferFee + portalFee`. pTokens are batch-burned separately by the portal owner.
    /// @param recipient Public underlying recipient (wrapped ERC20 for native portals).
    /// @param amount Public amount to withdraw.
    /// @param portalFee Portal protocol fee collected by this portal.
    /// @param transferFee Native fee paid for the pToken transfer request.
    /// @param transferCallbackFee Native fee slice for the pToken transfer callback.
    /// @param permitDeadline Permit expiry timestamp.
    /// @param v Permit signature v.
    /// @param r Permit signature r.
    /// @param s Permit signature s.
    /// @return withdrawalId Portal withdrawal id.
    /// @return transferRequestId Async pToken transfer request id.
    function requestWithdrawWithPermit(
        address recipient,
        uint256 amount,
        uint256 portalFee,
        uint256 transferFee,
        uint256 transferCallbackFee,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable returns (bytes32 withdrawalId, bytes32 transferRequestId);

    /// @notice Callback entry point used by the pToken after a transfer-to-portal succeeds.
    function onPTokenTransferred(bytes32 withdrawalId) external;

    /// @notice Manually release a pending withdrawal after its pToken transfer request is marked successful.
    function triggerWithdrawalRelease(bytes32 withdrawalId) external;

    /// @notice Refund underlying collateral after a mint Inbox system error
    ///         (`pToken.requests(requestId).status == SystemFailed`).
    /// @dev App `raise` / `Failed` is not refundable (mint should not raise). Portal protocol fee is kept.
    ///      Permissionless: anyone may call; underlying is always sent to the original depositor.
    /// @param requestId Mint request id returned by {deposit} / {depositNative} / {wrap}.
    function refundFailedDeposit(bytes32 requestId) external;

    /// @notice Mark a pending withdrawal as Failed after its pToken transfer request fails.
    /// @dev Does not release underlying; user retains pTokens. Portal protocol fee is kept.
    /// @param withdrawalId Portal withdrawal id from {requestWithdrawWithPermit}.
    function cancelFailedWithdrawal(bytes32 withdrawalId) external;

    /// @notice Escrow state for a deposit mint request id.
    function depositEscrows(bytes32 requestId)
        external
        view
        returns (address user, address recipient, uint256 amount, DepositEscrowStatus status);

    /// @notice Owner batch-burn for pTokens accumulated from completed withdrawals.
    function burnAccumulatedPTokens(uint256 amount, uint256 burnCallbackFee)
        external
        payable
        returns (bytes32 burnRequestId);

    /// @notice Set per-portal deposit fee override; zero packed config clears override.
    /// @dev Caller must hold factory {OPERATOR_ROLE}.
    function setDepositFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external;

    /// @notice Set per-portal withdraw fee override.
    function setWithdrawFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external;

    /// @notice Clear per-portal deposit fee override (inherit factory default).
    function clearDepositFeeOverride() external;

    /// @notice Clear per-portal withdraw fee override (inherit factory default).
    function clearWithdrawFeeOverride() external;

    /// @notice Maximum amount that can be deposited in a single transaction.
    function maxDepositAmount() external view returns (uint256);

    /// @notice Maximum amount that can be withdrawn in a single transaction.
    function maxWithdrawAmount() external view returns (uint256);

    /// @notice Minimum amount required for a deposit.
    function minDepositAmount() external view returns (uint256);

    /// @notice Minimum amount required for a withdrawal.
    function minWithdrawAmount() external view returns (uint256);

    /// @notice Update per-portal deposit and withdrawal amount limits.
    /// @dev Setting `maxDeposit` or `maxWithdraw` to zero disables that operation.
    function setLimits(
        uint256 minDeposit,
        uint256 maxDeposit,
        uint256 minWithdraw,
        uint256 maxWithdraw
    ) external;

    /// @notice Sweep accumulated portal protocol fees to the factory fee recipient.
    function withdrawPortalFees(uint256 amount) external;

    /// @notice Rescue native to the factory {rescueRecipient} while paused.
    function rescueNative(uint256 amount) external;

    /// @notice Rescue ERC20 to the factory {rescueRecipient} while paused (not the paired pToken).
    function rescueERC20(address token, uint256 amount) external;

    /// @notice Estimate deposit fees for UI quoting.
    function estimateDepositFees(uint256 amount)
        external
        view
        returns (
            uint256 portalFee,
            bool usedDynamicPricing,
            uint256 mintTotalFee,
            uint256 mintCallbackFee
        );

    /// @notice Estimate withdraw fees for UI quoting.
    function estimateWithdrawFees(uint256 amount)
        external
        view
        returns (
            uint256 portalFee,
            bool usedDynamicPricing,
            uint256 transferTotalFee,
            uint256 transferCallbackFee
        );

    /// @notice Estimate batch burn inbox fees for keeper UI.
    function estimateBatchBurnFees(uint256 amount)
        external
        view
        returns (uint256 burnTotalFee, uint256 burnCallbackFee);

    /// @notice Effective fee config for this portal (override when set, else factory default).
    /// @param isDeposit True for deposit/wrap fees; false for withdraw fees.
    function getFeeConfig(bool isDeposit) external view returns (PortalFeeConfig memory config);

    /// @notice Per-portal fee override for a direction, when configured.
    /// @return config Unpacked override parameters when `isSet` is true.
    /// @return isSet True when this portal overrides the factory default for that direction.
    function getFeeConfigOverride(bool isDeposit)
        external
        view
        returns (PortalFeeConfig memory config, bool isSet);
}
