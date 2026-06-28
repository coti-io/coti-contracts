// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "../token/perc20/IPodERC20.sol";
import "../token/erc7984/IERC7984PortalWrapper.sol";
import "../utils/IWrappedNative.sol";
import "./IPrivacyPortal.sol";

/// @notice Optional external policy hook for pausing portal operations.
interface IPrivacyPortalPauseController {
    /// @notice Whether new withdrawal requests should revert.
    function withdrawalsPaused() external view returns (bool);

    /// @notice Whether new deposits / wraps should revert.
    function depositsPaused() external view returns (bool);
}

/// @title PrivacyPortal
/// @notice Locks a public ERC20 and mints/burns its PoD private pToken counterpart.
/// @dev The portal never reads private balances. It only reacts to successful pToken callbacks and records public bridge obligations.
contract PrivacyPortal is IPrivacyPortal, IERC7984PortalWrapper, Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Public ERC20 collateral locked by this portal.
    IERC20 public underlyingToken;
    /// @notice Private pToken minted and burned against the underlying collateral.
    IPodERC20 public pToken;
    /// @notice Optional pause controller for deposits and withdrawals; zero disables pause checks.
    address public pauseController;
    /// @notice Token decimals mirrored from the underlying/pToken pair.
    uint8 public decimals;
    /// @notice When true, {depositNative} wraps native coin and withdrawals unwrap to native.
    bool public nativeWrappedUnderlying;

    /// @notice Monotonic nonce used to derive withdrawal ids.
    uint256 public withdrawalNonce;
    /// @notice Total pToken amount held by the portal that still needs owner-submitted burn cleanup.
    uint256 public burnDebtAmount;

    /// @notice Withdrawal state by withdrawal id.
    mapping(bytes32 => Withdrawal) public withdrawals;

    /// @notice Public ERC20 was locked and an async private pToken mint was requested.
    event DepositRequested(
        address indexed user,
        address indexed recipient,
        uint256 amount,
        bytes32 indexed mintRequestId
    );
    /// @notice Public withdrawal was requested and a pToken transfer-to-portal request was submitted.
    event WithdrawalRequested(
        bytes32 indexed withdrawalId,
        address indexed user,
        address indexed recipient,
        uint256 amount,
        bytes32 transferRequestId
    );
    /// @notice Underlying collateral was released to the withdrawal recipient.
    event WithdrawalReleased(bytes32 indexed withdrawalId, address indexed recipient, uint256 amount);
    /// @notice A burn request was submitted for pTokens in portal custody after release.
    event BurnSubmitted(bytes32 indexed withdrawalId, uint256 amount, bytes32 indexed burnRequestId);
    /// @notice Burn submission failed after release, leaving debt for owner cleanup.
    event BurnDebtRecorded(bytes32 indexed withdrawalId, uint256 amount, bytes reason);
    /// @notice Owner submitted a cleanup burn for accumulated pToken debt.
    event BurnDebtSubmitted(address indexed caller, uint256 amount, bytes32 indexed burnRequestId);
    /// @notice Pause controller was changed.
    event PauseControllerUpdated(address indexed pauseController);
    /// @notice Native token balance was swept by the owner.
    event NativeSwept(address indexed recipient, uint256 amount);

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
    /// @notice Requested burn cleanup exceeds accumulated debt.
    error BurnDebtTooLow(uint256 debt, uint256 requested);
    /// @notice Clone was already initialized.
    error PortalAlreadyInitialized();
    /// @notice Pause controller reports withdrawals are paused.
    error WithdrawalsPaused();
    /// @notice Pause controller reports deposits are paused.
    error DepositsPaused();
    /// @notice Configured pause controller did not return a valid pause flag.
    error PauseControllerFault();
    /// @notice pToken transfer request has not succeeded yet.
    error PTokenTransferNotSuccessful(bytes32 requestId, IPodERC20.RequestStatus status);
    /// @notice Portal underlying is not configured for native wrap/unwrap.
    error NativeWrapDisabled();
    /// @notice Native transfer to the withdrawal recipient failed.
    error NativeTransferFailed();

    /// @notice Lock implementation instance by assigning a non-zero owner placeholder.
    constructor() Ownable(address(1)) {}

    /// @notice Accept native funds used only for pToken burn-fee cleanup or accidental recovery.
    /// @dev User-facing deposit and withdrawal fees should be passed as `msg.value`; arbitrary native donations can be swept by the owner.
    receive() external payable {}

    function initialize(
        address owner_,
        address underlyingToken_,
        address pToken_,
        uint8 decimals_,
        bool nativeWrappedUnderlying_
    ) external override {
        if (address(underlyingToken) != address(0)) {
            revert PortalAlreadyInitialized();
        }
        if (owner_ == address(0)) {
            revert OwnableInvalidOwner(owner_);
        }
        if (underlyingToken_ == address(0) || pToken_ == address(0)) {
            revert InvalidAddress();
        }
        _transferOwnership(owner_);
        underlyingToken = IERC20(underlyingToken_);
        pToken = IPodERC20(pToken_);
        decimals = decimals_;
        nativeWrappedUnderlying = nativeWrappedUnderlying_;
        pauseController = msg.sender;
        emit PauseControllerUpdated(msg.sender);
    }

    /// @notice Update the external pause controller checked before deposits and withdrawal requests.
    /// @dev Set to `address(0)` to disable pause checks. When non-zero, the controller must implement
    ///      {IPrivacyPortalPauseController}; failed staticcalls revert (fail-closed).
    /// @param pauseController_ New controller address, or zero to disable.
    function setPauseController(address pauseController_) external onlyOwner {
        pauseController = pauseController_;
        emit PauseControllerUpdated(pauseController_);
    }

    /// @inheritdoc IPrivacyPortal
    function deposit(
        address recipient,
        uint256 amount,
        uint256 mintCallbackFee
    ) external payable override nonReentrant returns (bytes32 requestId) {
        return _deposit(recipient, amount, mintCallbackFee);
    }

    function _deposit(address recipient, uint256 amount, uint256 mintCallbackFee)
        private
        returns (bytes32 requestId)
    {
        _checkDepositsNotPaused();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }

        underlyingToken.safeTransferFrom(msg.sender, address(this), amount);
        requestId = pToken.mint{value: msg.value}(recipient, amount, mintCallbackFee);
        emit DepositRequested(msg.sender, recipient, amount, requestId);
        emit WrapRequested(msg.sender, recipient, amount, requestId);
    }

    /// @inheritdoc IPrivacyPortal
    function depositNative(
        address recipient,
        uint256 amount,
        uint256 mintCallbackFee
    ) external payable override nonReentrant returns (bytes32 requestId) {
        if (!nativeWrappedUnderlying) {
            revert NativeWrapDisabled();
        }
        _checkDepositsNotPaused();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (msg.value < amount) {
            revert IncorrectFee(amount, msg.value);
        }
        uint256 mintFee = msg.value - amount;

        IWrappedNative(address(underlyingToken)).deposit{value: amount}();
        requestId = pToken.mint{value: mintFee}(recipient, amount, mintCallbackFee);
        emit DepositRequested(msg.sender, recipient, amount, requestId);
        emit WrapRequested(msg.sender, recipient, amount, requestId);
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
        return _deposit(to, amount, mintCallbackFee);
    }

    /// @inheritdoc IPrivacyPortal
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
    ) external payable override nonReentrant returns (bytes32 withdrawalId, bytes32 transferRequestId) {
        _checkWithdrawalsNotPaused();
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        uint256 expectedFee = transferFee + burnFee;
        if (msg.value != expectedFee) {
            revert IncorrectFee(expectedFee, msg.value);
        }

        withdrawalId = keccak256(abi.encodePacked(address(this), msg.sender, recipient, amount, withdrawalNonce++));
        bytes memory callbackData = abi.encodeWithSelector(this.onPTokenTransferred.selector, withdrawalId);

        IPodERC20.PublicPermit memory permit =
            IPodERC20.PublicPermit({deadline: permitDeadline, v: v, r: r, s: s});
        transferRequestId = pToken.transferFromAndCallWithPermit{value: transferFee}(
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
            burnFee: burnFee,
            burnCallbackFee: burnCallbackFee,
            transferRequestId: transferRequestId,
            burnRequestId: bytes32(0),
            status: WithdrawalStatus.TransferPending
        });

        emit WithdrawalRequested(withdrawalId, msg.sender, recipient, amount, transferRequestId);
        emit UnwrapRequested(
            recipient,
            withdrawalId,
            keccak256(abi.encode(withdrawalId, transferRequestId))
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
    function triggerWithdrawalRelease(bytes32 withdrawalId) external override nonReentrant {
        _releaseWithdrawal(withdrawalId);
    }

    /// @notice Release an eligible withdrawal exactly once and submit the follow-up burn request.
    /// @dev Follows checks-effects-interactions by marking the withdrawal released before transferring underlying tokens.
    function _releaseWithdrawal(bytes32 withdrawalId) private {
        Withdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.user == address(0)) {
            revert UnknownWithdrawal(withdrawalId);
        }
        if (withdrawal.status != WithdrawalStatus.TransferPending) {
            revert WithdrawalNotPending(withdrawalId, withdrawal.status);
        }
        IPodERC20.RequestStatus requestStatus = pToken.requests(withdrawal.transferRequestId);
        if (requestStatus != IPodERC20.RequestStatus.Success) {
            revert PTokenTransferNotSuccessful(withdrawal.transferRequestId, requestStatus);
        }

        withdrawal.status = WithdrawalStatus.Released;
        if (nativeWrappedUnderlying) {
            IWrappedNative(address(underlyingToken)).withdraw(withdrawal.amount);
            (bool ok,) = payable(withdrawal.recipient).call{value: withdrawal.amount}("");
            if (!ok) {
                revert NativeTransferFailed();
            }
        } else {
            underlyingToken.safeTransfer(withdrawal.recipient, withdrawal.amount);
        }
        emit WithdrawalReleased(withdrawalId, withdrawal.recipient, withdrawal.amount);
        // Explorer correlation id for the confidential leg (not a ciphertext pointer; see pToken ConfidentialTransfer).
        emit UnwrapFinalized(
            withdrawal.recipient,
            withdrawalId,
            withdrawalId,
            uint64(withdrawal.amount)
        );

        _trySubmitBurn(withdrawalId, withdrawal);
    }

    /// @notice Keeper/admin cleanup for pTokens already in portal custody when a previous burn submission failed.
    function burnAccumulatedDebt(
        uint256 amount,
        uint256 burnFee,
        uint256 burnCallbackFee
    ) external payable onlyOwner nonReentrant returns (bytes32 burnRequestId) {
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (amount > burnDebtAmount) {
            revert BurnDebtTooLow(burnDebtAmount, amount);
        }
        if (msg.value != burnFee) {
            revert IncorrectFee(burnFee, msg.value);
        }

        burnRequestId = pToken.burn{value: burnFee}(amount, burnCallbackFee);
        burnDebtAmount -= amount;
        emit BurnDebtSubmitted(msg.sender, amount, burnRequestId);
    }

    /// @notice Sweep accidental native-token balance to `recipient`.
    /// @dev Does not touch locked ERC20 collateral. Keep enough balance for planned owner burn-debt retries before sweeping.
    /// @param recipient Native-token recipient.
    /// @param amount Amount to sweep.
    function sweepNative(address payable recipient, uint256 amount) external onlyOwner nonReentrant {
        if (recipient == address(0)) {
            revert InvalidAddress();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "PrivacyPortal: sweep failed");
        emit NativeSwept(recipient, amount);
    }

    /// @notice Best-effort burn submission for pTokens already moved into portal custody.
    /// @dev Release is final even if burn submission fails; failures increase {burnDebtAmount} for owner cleanup.
    function _trySubmitBurn(bytes32 withdrawalId, Withdrawal storage withdrawal) private {
        burnDebtAmount += withdrawal.amount;
        try pToken.burn{value: withdrawal.burnFee}(withdrawal.amount, withdrawal.burnCallbackFee) returns (
            bytes32 burnRequestId
        ) {
            burnDebtAmount -= withdrawal.amount;
            withdrawal.burnRequestId = burnRequestId;
            emit BurnSubmitted(withdrawalId, withdrawal.amount, burnRequestId);
        } catch (bytes memory reason) {
            emit BurnDebtRecorded(withdrawalId, withdrawal.amount, reason);
        }
    }

    /// @notice Query the optional pause controller and revert when it reports withdrawals paused.
    function _checkWithdrawalsNotPaused() private view {
        if (_pauseFlag(IPrivacyPortalPauseController.withdrawalsPaused.selector)) {
            revert WithdrawalsPaused();
        }
    }

    /// @notice Query the optional pause controller and revert when it reports deposits paused.
    function _checkDepositsNotPaused() private view {
        if (_pauseFlag(IPrivacyPortalPauseController.depositsPaused.selector)) {
            revert DepositsPaused();
        }
    }

    /// @dev Returns the pause flag from {pauseController}. Disabled when zero; fail-closed for contracts.
    function _pauseFlag(bytes4 selector) private view returns (bool) {
        address controller = pauseController;
        if (controller == address(0)) {
            return false;
        }
        if (controller.code.length == 0) {
            return false;
        }
        (bool success, bytes memory data) = controller.staticcall(abi.encodeWithSelector(selector));
        if (!success || data.length < 32) {
            revert PauseControllerFault();
        }
        return abi.decode(data, (bool));
    }
}
