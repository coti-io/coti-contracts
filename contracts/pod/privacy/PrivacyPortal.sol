// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import "../token/perc20/IPodERC20.sol";
import "../token/erc7984/IERC7984PortalWrapper.sol";
import "../utils/IWrappedNative.sol";
import "./IPrivacyPortal.sol";
import "./IPrivacyPortalFactory.sol";
import "./IPodPriceOracle.sol";
import "./PrivacyPortalFeeLib.sol";

/// @title PrivacyPortal
/// @notice Locks a public ERC20 and mints/burns its PoD private pToken counterpart.
/// @dev The portal never reads private balances. It only reacts to successful pToken callbacks and records public bridge obligations.
///      Split deploy-then-initialize is unsafe on clones; use {PrivacyPortalFactory.createPortal} or an equivalent atomic path.
///      Admin and operator privileges live on {factory} only — portals have no local Ownable.
contract PrivacyPortal is IPrivacyPortal, IERC7984PortalWrapper, Pausable, ReentrancyGuard, Initializable {
    using SafeERC20 for IERC20;
    using PrivacyPortalFeeLib for bytes32;

    /// @notice Public ERC20 collateral locked by this portal.
    IERC20 public underlyingToken;
    /// @notice Private pToken minted and burned against the underlying collateral.
    IPodERC20 public pToken;
    /// @notice Factory that created this portal (fees, pause, blacklist, rescue, operators).
    address public factory;
    /// @notice Token decimals mirrored from the underlying/pToken pair.
    uint8 public decimals;
    /// @notice When true, {depositNative} wraps native coin; withdrawals release wrapped underlying ERC20.
    bool public nativeWrappedUnderlying;

    /// @notice Soft deposit switch (factory operator); independent of pause / factory pause.
    bool public isDepositEnabled = true;
    /// @notice Per-portal blacklist (ORs with factory blacklist).
    mapping(address => bool) public blacklisted;

    /// @notice Optional per-portal deposit fee override; bytes32(0) inherits factory default.
    bytes32 internal depositFeeOverridePacked;
    /// @notice Optional per-portal withdraw fee override; bytes32(0) inherits factory default.
    bytes32 internal withdrawFeeOverridePacked;
    /// @notice Accumulated portal protocol fees awaiting sweep.
    uint256 public accumulatedPortalFees;
    /// @notice pToken amount held in portal custody pending owner batch burn.
    uint256 public pendingBurnAmount;
    /// @notice Monotonic nonce used to derive withdrawal ids.
    uint256 public withdrawalNonce;

    /// @notice Maximum amount that can be deposited in a single transaction.
    uint256 public maxDepositAmount;
    /// @notice Maximum amount that can be withdrawn in a single transaction.
    uint256 public maxWithdrawAmount;
    /// @notice Minimum amount required for a deposit.
    uint256 public minDepositAmount;
    /// @notice Minimum amount required for a withdrawal.
    uint256 public minWithdrawAmount;

    /// @notice Withdrawal state by withdrawal id.
    mapping(bytes32 => Withdrawal) public withdrawals;
    /// @notice Deposit escrow by mint request id.
    mapping(bytes32 => DepositEscrow) public depositEscrows;

    /// @notice Public ERC20 was locked and an async private pToken mint was requested.
    event DepositRequested(
        address indexed user,
        address indexed recipient,
        uint256 amount,
        bytes32 indexed mintRequestId
    );
    /// @notice Failed mint collateral was returned to the depositor.
    event DepositRefunded(address indexed user, bytes32 indexed mintRequestId, uint256 amount);
    /// @notice Public withdrawal was requested and a pToken transfer-to-portal request was submitted.
    event WithdrawalRequested(
        bytes32 indexed withdrawalId,
        address indexed user,
        address indexed recipient,
        uint256 amount,
        bytes32 transferRequestId
    );
    /// @notice Pending withdrawal was cancelled after a failed pToken transfer.
    event WithdrawalFailed(bytes32 indexed withdrawalId, bytes32 indexed transferRequestId);
    /// @notice Underlying collateral was released to the withdrawal recipient.
    event WithdrawalReleased(bytes32 indexed withdrawalId, address indexed recipient, uint256 amount);
    /// @notice Portal protocol fee collected on a user-facing entry point.
    /// @dev Prefer {OperationFeesPaid} for offline indexing of portal vs PoD fee legs.
    event PortalFeeCollected(address indexed payer, uint256 amount, bool isDeposit);
    /// @notice Full native-fee breakdown for a deposit or withdraw (offline fee accounting).
    /// @param payer User who paid `msg.value`.
    /// @param correlationId Mint `requestId` (deposit/wrap) or `withdrawalId` (withdraw).
    /// @param isDeposit True for deposit/wrap; false for withdraw.
    /// @param isNativeWrap True when the deposit wrapped native coin into the underlying.
    /// @param portalFee Protocol fee retained by this portal (native wei).
    /// @param podFee Native wei forwarded to the pToken/inbox for the async PoD leg.
    /// @param podCallbackFee Native wei reserved for the PoD callback slice within `podFee`.
    /// @param amount Principal amount in underlying token units (not a fee).
    event OperationFeesPaid(
        address indexed payer,
        bytes32 indexed correlationId,
        bool indexed isDeposit,
        bool isNativeWrap,
        uint256 portalFee,
        uint256 podFee,
        uint256 podCallbackFee,
        uint256 amount
    );
    /// @notice pTokens from a release were queued for batch burn.
    event PendingBurnIncreased(bytes32 indexed withdrawalId, uint256 amount, uint256 pendingBurnAmount);
    /// @notice Owner submitted a batch burn for accumulated pTokens.
    event BatchBurnSubmitted(address indexed caller, uint256 amount, bytes32 indexed burnRequestId);
    /// @notice Portal protocol fees swept to the factory fee recipient.
    event PortalFeesWithdrawn(address indexed recipient, uint256 amount);
    /// @notice Per-portal fee override updated.
    event PortalFeeOverrideUpdated(bool indexed isDeposit, bytes32 packedConfig);
    /// @notice Per-portal fee override cleared.
    event PortalFeeOverrideCleared(bool indexed isDeposit);
    /// @notice Factory binding set at initialize (immutable thereafter).
    event FactorySet(address indexed factory);
    /// @notice Per-portal deposit/withdraw limits changed.
    event LimitsUpdated(
        uint256 minDeposit,
        uint256 maxDeposit,
        uint256 minWithdraw,
        uint256 maxWithdraw
    );
    /// @notice Native token was rescued to the factory rescue recipient while paused.
    event NativeRescued(address indexed rescueRecipient, uint256 amount);
    /// @notice ERC20 was rescued to the factory rescue recipient while paused.
    event ERC20Rescued(address indexed token, address indexed rescueRecipient, uint256 amount);
    /// @notice Soft deposit-enabled flag changed.
    event DepositEnabledUpdated(bool enabled);
    /// @notice Address added to the portal blacklist.
    event Blacklisted(address indexed account, address indexed by);
    /// @notice Address removed from the portal blacklist.
    event UnBlacklisted(address indexed account, address indexed by);

    /// @notice A required address was zero.
    error InvalidAddress();
    /// @notice Amount argument was zero.
    error InvalidAmount();
    /// @notice `msg.value` did not match the expected fee.
    error IncorrectFee(uint256 expected, uint256 actual);
    /// @notice Caller was not the configured pToken.
    error OnlyPToken(address caller);
    /// @notice Withdrawal id is not known.
    error UnknownWithdrawal(bytes32 withdrawalId);
    /// @notice Withdrawal is not in the pending-transfer state.
    error WithdrawalNotPending(bytes32 withdrawalId, WithdrawalStatus status);
    /// @notice Requested batch burn exceeds pending burn amount.
    error PendingBurnTooLow(uint256 pending, uint256 requested);
    /// @notice Portal fee below configured floor.
    error InsufficientPortalFee(uint256 expectedFloor, uint256 actual);
    /// @notice Portal fee above configured max.
    error ExcessivePortalFee(uint256 maxFee, uint256 actual);
    /// @notice Insufficient accumulated portal fees to sweep.
    error InsufficientAccumulatedFees(uint256 accumulated, uint256 requested);
    /// @notice Pause controller reports withdrawals are paused.
    error WithdrawalsPaused();
    /// @notice Pause controller reports deposits are paused.
    error DepositsPaused();
    /// @notice pToken transfer request has not succeeded yet.
    error PTokenTransferNotSuccessful(bytes32 requestId, IPodERC20.RequestStatus status);
    /// @notice Deposit escrow is missing or not eligible for the requested action.
    error DepositEscrowInvalid(bytes32 requestId, DepositEscrowStatus status);
    /// @notice Mint request is not {IPodERC20.RequestStatus.SystemFailed}, so escrow cannot be refunded.
    error DepositMintNotFailed(bytes32 requestId, IPodERC20.RequestStatus status);
    /// @notice Transfer request is not Failed/SystemFailed, so withdrawal cannot be cancelled.
    error WithdrawTransferNotFailed(bytes32 requestId, IPodERC20.RequestStatus status);
    /// @notice Portal underlying is not configured for native wrap deposits.
    error NativeWrapDisabled();
    /// @notice Factory pause controller is not configured.
    error FactoryNotConfigured();
    /// @notice Caller is on the factory blacklist.
    error AddressBlacklisted(address account);
    /// @notice Deposit amount is below the configured minimum.
    error DepositBelowMinimum();
    /// @notice Deposit amount exceeds the configured maximum.
    error DepositExceedsMaximum();
    /// @notice Withdraw amount is below the configured minimum.
    error WithdrawBelowMinimum();
    /// @notice Withdraw amount exceeds the configured maximum.
    error WithdrawExceedsMaximum();
    /// @notice Invalid min/max limit configuration.
    error InvalidLimitConfiguration();
    /// @notice Soft deposit switch is off.
    error DepositDisabled();
    /// @notice Caller is not a factory {OPERATOR_ROLE} holder.
    error OnlyFactoryOperator(address caller);
    /// @notice Caller is not a factory {DEFAULT_ADMIN_ROLE} holder.
    error OnlyFactoryAdmin(address caller);
    /// @notice Cannot rescue the paired pToken.
    error CannotRescuePToken();
    /// @notice Native transfer failed.
    error EthTransferFailed();

    /// @notice Lock implementation so it cannot be initialized.
    constructor() {
        _disableInitializers();
    }

    /// @notice Accept native funds for portal fees or accidental recovery.
    receive() external payable {}

    function initialize(
        address underlyingToken_,
        address pToken_,
        uint8 decimals_,
        bool nativeWrappedUnderlying_,
        address factory_
    ) external initializer override {
        if (underlyingToken_ == address(0) || pToken_ == address(0) || factory_ == address(0)) {
            revert InvalidAddress();
        }
        underlyingToken = IERC20(underlyingToken_);
        pToken = IPodERC20(pToken_);
        decimals = decimals_;
        nativeWrappedUnderlying = nativeWrappedUnderlying_;
        isDepositEnabled = true;
        maxDepositAmount = type(uint256).max;
        maxWithdrawAmount = type(uint256).max;
        minDepositAmount = 1;
        minWithdrawAmount = 1;
        factory = factory_;
        emit FactorySet(factory_);
    }

    /// @notice Factory-admin hard-pause for this portal instance (enables rescue). Checked before factory pause.
    function pause() external onlyFactoryAdmin {
        _pause();
    }

    /// @notice Factory-admin unpause for this portal instance.
    function unpause() external onlyFactoryAdmin {
        _unpause();
    }

    /// @notice Soft deposit enable/disable (factory operator); does not enable rescue.
    function setIsDepositEnabled(bool enabled) external onlyFactoryOperator {
        isDepositEnabled = enabled;
        emit DepositEnabledUpdated(enabled);
    }

    /// @notice Add an address to this portal's blacklist.
    function addToBlacklist(address account) external onlyFactoryAdmin {
        if (account == address(0)) {
            revert InvalidAddress();
        }
        blacklisted[account] = true;
        emit Blacklisted(account, msg.sender);
    }

    /// @notice Remove an address from this portal's blacklist.
    function removeFromBlacklist(address account) external onlyFactoryAdmin {
        if (account == address(0)) {
            revert InvalidAddress();
        }
        blacklisted[account] = false;
        emit UnBlacklisted(account, msg.sender);
    }

    /// @notice Update per-portal deposit and withdrawal amount limits.
    /// @dev Setting `maxDeposit` or `maxWithdraw` to zero disables that operation.
    function setLimits(
        uint256 minDeposit,
        uint256 maxDeposit,
        uint256 minWithdraw,
        uint256 maxWithdraw
    ) external onlyFactoryAdmin {
        if (minDeposit > maxDeposit) {
            revert InvalidLimitConfiguration();
        }
        if (minWithdraw > maxWithdraw) {
            revert InvalidLimitConfiguration();
        }
        minDepositAmount = minDeposit;
        maxDepositAmount = maxDeposit;
        minWithdrawAmount = minWithdraw;
        maxWithdrawAmount = maxWithdraw;
        emit LimitsUpdated(minDeposit, maxDeposit, minWithdraw, maxWithdraw);
    }

    /// @inheritdoc IPrivacyPortal
    function setDepositFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external onlyFactoryOperator {
        bytes32 packed = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
        depositFeeOverridePacked = packed;
        emit PortalFeeOverrideUpdated(true, packed);
    }

    /// @inheritdoc IPrivacyPortal
    function setWithdrawFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external onlyFactoryOperator {
        bytes32 packed = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
        withdrawFeeOverridePacked = packed;
        emit PortalFeeOverrideUpdated(false, packed);
    }

    /// @inheritdoc IPrivacyPortal
    function clearDepositFeeOverride() external onlyFactoryOperator {
        depositFeeOverridePacked = bytes32(0);
        emit PortalFeeOverrideCleared(true);
    }

    /// @inheritdoc IPrivacyPortal
    function clearWithdrawFeeOverride() external onlyFactoryOperator {
        withdrawFeeOverridePacked = bytes32(0);
        emit PortalFeeOverrideCleared(false);
    }

    /// @inheritdoc IPrivacyPortal
    function deposit(
        address recipient,
        uint256 amount,
        uint256 portalFee,
        uint256 mintCallbackFee
    ) external payable override nonReentrant returns (bytes32 requestId) {
        return _deposit(recipient, amount, portalFee, mintCallbackFee);
    }

    function _deposit(address recipient, uint256 amount, uint256 portalFee, uint256 mintCallbackFee)
        private
        returns (bytes32 requestId)
    {
        _checkDepositsNotPaused();
        _checkNotBlacklisted();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        _checkDepositLimits(amount);

        _validateAndCollectPortalFee(portalFee, amount, true);
        if (msg.value <= portalFee) {
            revert IncorrectFee(portalFee + 1, msg.value);
        }
        uint256 mintFee = msg.value - portalFee;

        underlyingToken.safeTransferFrom(msg.sender, address(this), amount);
        requestId = pToken.mint{value: mintFee}(recipient, amount, mintCallbackFee);
        depositEscrows[requestId] = DepositEscrow({
            user: msg.sender,
            recipient: recipient,
            amount: amount,
            status: DepositEscrowStatus.Pending
        });
        emit DepositRequested(msg.sender, recipient, amount, requestId);
        emit WrapRequested(msg.sender, recipient, amount, requestId);
        emit OperationFeesPaid(
            msg.sender, requestId, true, false, portalFee, mintFee, mintCallbackFee, amount
        );
    }

    /// @inheritdoc IPrivacyPortal
    function depositNative(
        address recipient,
        uint256 amount,
        uint256 portalFee,
        uint256 mintCallbackFee
    ) external payable override nonReentrant returns (bytes32 requestId) {
        if (!nativeWrappedUnderlying) {
            revert NativeWrapDisabled();
        }
        _checkDepositsNotPaused();
        _checkNotBlacklisted();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        _checkDepositLimits(amount);

        _validateAndCollectPortalFee(portalFee, amount, true);
        if (msg.value <= amount + portalFee) {
            revert IncorrectFee(amount + portalFee + 1, msg.value);
        }
        uint256 mintFee = msg.value - amount - portalFee;

        IWrappedNative(address(underlyingToken)).deposit{value: amount}();
        requestId = pToken.mint{value: mintFee}(recipient, amount, mintCallbackFee);
        depositEscrows[requestId] = DepositEscrow({
            user: msg.sender,
            recipient: recipient,
            amount: amount,
            status: DepositEscrowStatus.Pending
        });
        emit DepositRequested(msg.sender, recipient, amount, requestId);
        emit WrapRequested(msg.sender, recipient, amount, requestId);
        emit OperationFeesPaid(
            msg.sender, requestId, true, true, portalFee, mintFee, mintCallbackFee, amount
        );
    }

    /// @inheritdoc IERC7984PortalWrapper
    function underlying() external view returns (address) {
        return address(underlyingToken);
    }

    /// @inheritdoc IERC7984PortalWrapper
    function rate() external pure returns (uint256) {
        return 1;
    }

    /// @inheritdoc IERC7984PortalWrapper
    function wrap(address to, uint256 amount, uint256 mintCallbackFee)
        external
        payable
        nonReentrant
        returns (bytes32 requestId)
    {
        (uint256 portalFloor,) = _portalFeeFloor(amount, true);
        return _deposit(to, amount, portalFloor, mintCallbackFee);
    }

    /// @inheritdoc IPrivacyPortal
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
    ) external payable override nonReentrant returns (bytes32 withdrawalId, bytes32 transferRequestId) {
        _checkWithdrawalsNotPaused();
        _checkNotBlacklisted();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        _checkWithdrawLimits(amount);

        _validateAndCollectPortalFee(portalFee, amount, false);
        if (msg.value < portalFee) {
            revert IncorrectFee(portalFee, msg.value);
        }
        uint256 transferTotalFee = msg.value - portalFee;
        if (transferFee != transferTotalFee) {
            revert IncorrectFee(transferTotalFee, transferFee);
        }

        withdrawalId = keccak256(abi.encodePacked(address(this), msg.sender, recipient, amount, withdrawalNonce++));
        bytes memory callbackData = abi.encodeWithSelector(this.onPTokenTransferred.selector, withdrawalId);

        IPodERC20.PublicPermit memory permit =
            IPodERC20.PublicPermit({deadline: permitDeadline, v: v, r: r, s: s});
        transferRequestId = pToken.transferFromAndCallWithPermit{value: transferTotalFee}(
            msg.sender,
            address(this),
            amount,
            permit,
            callbackData,
            transferCallbackFee
        );

        withdrawals[withdrawalId] = Withdrawal({
            user: msg.sender,
            recipient: recipient,
            amount: amount,
            transferRequestId: transferRequestId,
            status: WithdrawalStatus.TransferPending
        });

        emit WithdrawalRequested(withdrawalId, msg.sender, recipient, amount, transferRequestId);
        emit UnwrapRequested(
            recipient,
            withdrawalId,
            keccak256(abi.encode(withdrawalId, transferRequestId))
        );
        emit OperationFeesPaid(
            msg.sender,
            withdrawalId,
            false,
            false,
            portalFee,
            transferTotalFee,
            transferCallbackFee,
            amount
        );
    }

    /// @inheritdoc IPrivacyPortal
    function onPTokenTransferred(bytes32 withdrawalId) external override nonReentrant {
        if (msg.sender != address(pToken)) {
            revert OnlyPToken(msg.sender);
        }
        _releaseWithdrawal(withdrawalId);
    }

    /// @inheritdoc IPrivacyPortal
    function refundFailedDeposit(bytes32 requestId) external override nonReentrant {
        DepositEscrow storage escrow = depositEscrows[requestId];
        DepositEscrowStatus status = escrow.status;
        if (status != DepositEscrowStatus.Pending && status != DepositEscrowStatus.Failed) {
            revert DepositEscrowInvalid(requestId, status);
        }
        IPodERC20.RequestStatus mintStatus = pToken.requests(requestId).status;
        // Mint should not `raise`; only Inbox system errors are refundable.
        // Permissionless: anyone may trigger; underlying always returns to {escrow.user}.
        if (mintStatus != IPodERC20.RequestStatus.SystemFailed) {
            revert DepositMintNotFailed(requestId, mintStatus);
        }

        uint256 amount = escrow.amount;
        escrow.status = DepositEscrowStatus.Refunded;
        escrow.amount = 0;
        underlyingToken.safeTransfer(escrow.user, amount);
        emit DepositRefunded(escrow.user, requestId, amount);
    }

    /// @inheritdoc IPrivacyPortal
    function cancelFailedWithdrawal(bytes32 withdrawalId) external override nonReentrant {
        Withdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.user == address(0)) {
            revert UnknownWithdrawal(withdrawalId);
        }
        if (withdrawal.status != WithdrawalStatus.TransferPending) {
            revert WithdrawalNotPending(withdrawalId, withdrawal.status);
        }
        IPodERC20.RequestStatus requestStatus = pToken.requests(withdrawal.transferRequestId).status;
        if (
            requestStatus != IPodERC20.RequestStatus.Failed
                && requestStatus != IPodERC20.RequestStatus.SystemFailed
        ) {
            revert WithdrawTransferNotFailed(withdrawal.transferRequestId, requestStatus);
        }

        withdrawal.status = WithdrawalStatus.Failed;
        emit WithdrawalFailed(withdrawalId, withdrawal.transferRequestId);
    }

    /// @inheritdoc IPrivacyPortal
    function triggerWithdrawalRelease(bytes32 withdrawalId) external override nonReentrant {
        _releaseWithdrawal(withdrawalId);
    }

    /// @inheritdoc IPrivacyPortal
    function burnAccumulatedPTokens(uint256 amount, uint256 burnCallbackFee)
        external
        payable
        onlyFactoryAdmin
        nonReentrant
        returns (bytes32 burnRequestId)
    {
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (amount > pendingBurnAmount) {
            revert PendingBurnTooLow(pendingBurnAmount, amount);
        }
        if (msg.value == 0) {
            revert InvalidAmount();
        }

        pendingBurnAmount -= amount;
        burnRequestId = pToken.burn{value: msg.value}(amount, burnCallbackFee);
        emit BatchBurnSubmitted(msg.sender, amount, burnRequestId);
    }

    /// @inheritdoc IPrivacyPortal
    function withdrawPortalFees(uint256 amount) external onlyFactoryAdmin nonReentrant {
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (amount > accumulatedPortalFees) {
            revert InsufficientAccumulatedFees(accumulatedPortalFees, amount);
        }

        IPrivacyPortalFactory portalFactory = _factory();
        address recipient = portalFactory.feeRecipient();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }

        accumulatedPortalFees -= amount;
        (bool ok,) = payable(recipient).call{value: amount}("");
        require(ok, "PrivacyPortal: fee sweep failed");
        emit PortalFeesWithdrawn(recipient, amount);
    }

    /// @notice Rescue native balance to the factory rescue recipient while paused (catastrophe path).
    function rescueNative(uint256 amount) external onlyFactoryAdmin nonReentrant whenPaused {
        if (amount == 0) {
            revert InvalidAmount();
        }
        address recipient = _factory().rescueRecipient();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        (bool ok,) = payable(recipient).call{value: amount}("");
        if (!ok) {
            revert EthTransferFailed();
        }
        // Keep fee accounting consistent if rescue dips into fee balance.
        uint256 bal = address(this).balance;
        if (accumulatedPortalFees > bal) {
            accumulatedPortalFees = bal;
        }
        emit NativeRescued(recipient, amount);
    }

    /// @notice Rescue ERC20 balance to the factory rescue recipient while paused. Cannot rescue the paired pToken.
    function rescueERC20(address token, uint256 amount) external onlyFactoryAdmin nonReentrant whenPaused {
        if (token == address(0) || amount == 0) {
            revert InvalidAmount();
        }
        if (token == address(pToken)) {
            revert CannotRescuePToken();
        }
        address recipient = _factory().rescueRecipient();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        IERC20(token).safeTransfer(recipient, amount);
        emit ERC20Rescued(token, recipient, amount);
    }

    /// @inheritdoc IPrivacyPortal
    function estimateDepositFees(uint256 amount)
        external
        view
        returns (
            uint256 portalFee,
            bool usedDynamicPricing,
            uint256 mintTotalFee,
            uint256 mintCallbackFee
        )
    {
        (portalFee, usedDynamicPricing) = _estimatePortalFee(amount, true);
        (mintTotalFee, , mintCallbackFee) = pToken.estimateFee();
    }

    /// @inheritdoc IPrivacyPortal
    function estimateWithdrawFees(uint256 amount)
        external
        view
        returns (
            uint256 portalFee,
            bool usedDynamicPricing,
            uint256 transferTotalFee,
            uint256 transferCallbackFee
        )
    {
        (portalFee, usedDynamicPricing) = _estimatePortalFee(amount, false);
        (transferTotalFee, , transferCallbackFee) = pToken.estimateFee();
    }

    /// @inheritdoc IPrivacyPortal
    function estimateBatchBurnFees(uint256)
        external
        view
        returns (uint256 burnTotalFee, uint256 burnCallbackFee)
    {
        (burnTotalFee, , burnCallbackFee) = pToken.estimateFee();
    }

    /// @notice Effective packed deposit fee config (override or factory default).
    function getEffectiveDepositFeeConfig() external view returns (bytes32) {
        return _effectiveFeePacked(true);
    }

    /// @notice Effective packed withdraw fee config (override or factory default).
    function getEffectiveWithdrawFeeConfig() external view returns (bytes32) {
        return _effectiveFeePacked(false);
    }

    /// @inheritdoc IPrivacyPortal
    function getFeeConfig(bool isDeposit) external view returns (PortalFeeConfig memory config) {
        return PrivacyPortalFeeLib.decodeFeeConfig(_effectiveFeePacked(isDeposit));
    }

    /// @inheritdoc IPrivacyPortal
    function getFeeConfigOverride(bool isDeposit)
        external
        view
        returns (PortalFeeConfig memory config, bool isSet)
    {
        bytes32 packed = isDeposit ? depositFeeOverridePacked : withdrawFeeOverridePacked;
        isSet = PrivacyPortalFeeLib.isOverrideSet(packed);
        if (!isSet) {
            return (config, false);
        }
        return (PrivacyPortalFeeLib.decodeFeeConfig(packed), true);
    }

    /// @notice Release an eligible withdrawal exactly once; pTokens remain in custody for batch burn.
    function _releaseWithdrawal(bytes32 withdrawalId) private {
        Withdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.user == address(0)) {
            revert UnknownWithdrawal(withdrawalId);
        }
        if (withdrawal.status != WithdrawalStatus.TransferPending) {
            revert WithdrawalNotPending(withdrawalId, withdrawal.status);
        }
        IPodERC20.RequestStatus requestStatus = pToken.requests(withdrawal.transferRequestId).status;
        if (requestStatus != IPodERC20.RequestStatus.Success) {
            revert PTokenTransferNotSuccessful(withdrawal.transferRequestId, requestStatus);
        }

        withdrawal.status = WithdrawalStatus.Released;
        underlyingToken.safeTransfer(withdrawal.recipient, withdrawal.amount);
        pendingBurnAmount += withdrawal.amount;

        emit WithdrawalReleased(withdrawalId, withdrawal.recipient, withdrawal.amount);
        emit PendingBurnIncreased(withdrawalId, withdrawal.amount, pendingBurnAmount);
        emit UnwrapFinalized(
            withdrawal.recipient,
            withdrawalId,
            withdrawalId,
            uint64(withdrawal.amount)
        );
    }

    function _validateAndCollectPortalFee(uint256 portalFee, uint256 amount, bool isDeposit) private {
        (uint256 floor, uint128 maxFee) = _portalFeeFloor(amount, isDeposit);
        if (portalFee < floor) {
            revert InsufficientPortalFee(floor, portalFee);
        }
        if (portalFee > maxFee) {
            revert ExcessivePortalFee(maxFee, portalFee);
        }
        accumulatedPortalFees += portalFee;
        emit PortalFeeCollected(msg.sender, portalFee, isDeposit);
    }

    function _portalFeeFloor(uint256 amount, bool isDeposit)
        private
        view
        returns (uint256 floor, uint128 maxFee)
    {
        bytes32 packed = _effectiveFeePacked(isDeposit);
        IPrivacyPortalFactory portalFactory = _factory();
        (uint96 fixedFee, uint32 bps, uint128 max) = PrivacyPortalFeeLib.unpackFeeConfig(packed);
        maxFee = max;
        if (address(portalFactory.priceOracle()) == address(0) || bps == 0) {
            return (fixedFee, maxFee);
        }
        IPodPriceOracle oracle = portalFactory.priceOracle();
        (uint256 nativeUsd, uint256 collateralUsd) = oracle.getLivePrices(
            portalFactory.nativeToken(),
            address(underlyingToken)
        );
        (floor,) = PrivacyPortalFeeLib.resolvePortalFee(
            packed,
            amount,
            decimals,
            collateralUsd,
            nativeUsd
        );
    }

    function _estimatePortalFee(uint256 amount, bool isDeposit)
        private
        view
        returns (uint256 fee, bool usedDynamicPricing)
    {
        IPrivacyPortalFactory portalFactory = _factory();
        if (isDeposit) {
            if (PrivacyPortalFeeLib.isOverrideSet(depositFeeOverridePacked)) {
                return _estimateWithOverride(depositFeeOverridePacked, amount, portalFactory);
            }
            return portalFactory.estimateDepositPortalFee(address(underlyingToken), amount, decimals);
        }
        if (PrivacyPortalFeeLib.isOverrideSet(withdrawFeeOverridePacked)) {
            return _estimateWithOverride(withdrawFeeOverridePacked, amount, portalFactory);
        }
        return portalFactory.estimateWithdrawPortalFee(address(underlyingToken), amount, decimals);
    }

    function _estimateWithOverride(bytes32 packed, uint256 amount, IPrivacyPortalFactory portalFactory)
        private
        view
        returns (uint256 fee, bool usedDynamicPricing)
    {
        if (address(portalFactory.priceOracle()) == address(0)) {
            (uint96 fixedFee,,) = PrivacyPortalFeeLib.unpackFeeConfig(packed);
            return (fixedFee, false);
        }
        IPodPriceOracle oracle = portalFactory.priceOracle();
        (uint256 nativeUsd, uint256 collateralUsd) = oracle.getLivePrices(
            portalFactory.nativeToken(),
            address(underlyingToken)
        );
        return PrivacyPortalFeeLib.resolvePortalFee(
            packed,
            amount,
            decimals,
            collateralUsd,
            nativeUsd
        );
    }

    function _effectiveFeePacked(bool isDeposit) private view returns (bytes32) {
        bytes32 overridePacked = isDeposit ? depositFeeOverridePacked : withdrawFeeOverridePacked;
        if (PrivacyPortalFeeLib.isOverrideSet(overridePacked)) {
            return overridePacked;
        }
        IPrivacyPortalFactory portalFactory = _factory();
        return isDeposit ? portalFactory.defaultDepositFeePacked() : portalFactory.defaultWithdrawFeePacked();
    }

    function _factory() private view returns (IPrivacyPortalFactory) {
        address factory_ = factory;
        if (factory_ == address(0)) {
            revert FactoryNotConfigured();
        }
        return IPrivacyPortalFactory(factory_);
    }

    modifier onlyFactoryOperator() {
        if (!_factory().isOperator(msg.sender)) {
            revert OnlyFactoryOperator(msg.sender);
        }
        _;
    }

    modifier onlyFactoryAdmin() {
        if (!_factory().isAdmin(msg.sender)) {
            revert OnlyFactoryAdmin(msg.sender);
        }
        _;
    }

    function _checkWithdrawalsNotPaused() private view {
        // Local instance pause first, then factory-wide pause.
        if (paused() || _factory().withdrawalsPaused()) {
            revert WithdrawalsPaused();
        }
    }

    function _checkDepositsNotPaused() private view {
        if (paused() || _factory().depositsPaused()) {
            revert DepositsPaused();
        }
        if (!isDepositEnabled) {
            revert DepositDisabled();
        }
    }

    function _checkNotBlacklisted() private view {
        if (blacklisted[msg.sender] || _factory().blacklisted(msg.sender)) {
            revert AddressBlacklisted(msg.sender);
        }
    }

    function _checkDepositLimits(uint256 amount) private view {
        if (amount < minDepositAmount) {
            revert DepositBelowMinimum();
        }
        if (amount > maxDepositAmount) {
            revert DepositExceedsMaximum();
        }
    }

    function _checkWithdrawLimits(uint256 amount) private view {
        if (amount < minWithdrawAmount) {
            revert WithdrawBelowMinimum();
        }
        if (amount > maxWithdrawAmount) {
            revert WithdrawExceedsMaximum();
        }
    }
}
