// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "../oracle/ICotiPriceConsumer.sol";

/**
 * @title PrivacyBridge
 * @notice Base contract for Privacy Bridge contracts containing common logic
 * @dev Trust assumptions: (1) MPC precompile at expected address is correct and non-malicious.
 *      (2) Private token implementation is trusted and only authorized minters can mint.
 *      (3) Owner operations (limits, fees, pause, withdraw fees, rescue) are centralized; consider timelock/multisig for sensitive actions.
 *      (4) Any new derived bridge must override withdrawFees to perform the actual transfer; base implementation reverts.
 */
abstract contract PrivacyBridge is ReentrancyGuard, Pausable, Ownable, AccessControlEnumerable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    event OperatorAdded(address indexed account, address indexed by);
    event OperatorRemoved(address indexed account, address indexed by);
    event DepositEnabledUpdated(bool enabled, address indexed by);
    event NativeCotiFeeUpdated(uint256 fee, address indexed by);
    event DynamicFeeUpdated(string feeType, uint256 fixedFee, uint256 percentageBps, uint256 maxFee);
    event PriceOracleUpdated(address indexed oldOracle, address indexed newOracle);

    /// @notice Maximum amount that can be deposited in a single transaction
    uint256 public maxDepositAmount;

    /// @notice Maximum amount that can be withdrawn in a single transaction
    uint256 public maxWithdrawAmount;

    /// @notice Minimum amount required for a deposit
    uint256 public minDepositAmount;

    /// @notice Minimum amount required for a withdrawal
    uint256 public minWithdrawAmount;

    /// @notice Deposit fee in basis points (1 bp = 0.0001%, 1,000,000 = 100%)
    uint256 public depositFeeBasisPoints;

    /// @notice Withdrawal fee in basis points (1 bp = 0.0001%, 1,000,000 = 100%)
    uint256 public withdrawFeeBasisPoints;

    /// @notice Accumulated fees collected by the bridge (in bridged asset units)
    uint256 public accumulatedFees;

    /// @notice Accumulated native COTI fees (used only by ERC20 bridges for per-operation native fee; not used by native bridge)
    uint256 public accumulatedCotiFees;

    /// @notice Fee divisor (1,000,000)
    uint256 public constant FEE_DIVISOR = 1000000;

    /// @notice Maximum fee allowed (10% = 100,000 units)
    uint256 public constant MAX_FEE_UNITS = 100000;

    /// @notice Flag to enable/disable deposits
    bool public isDepositEnabled = true;

    /// @notice Fee in native COTI for bridge operations
    uint256 public nativeCotiFee;


    // Privacy Bridge defines default Fees
    // those fees can be overwritten using
    // setDepositDynamicFee available for OPERATORS and ADMIN

    /// @notice Deposit fee floor in COTI wei
    uint256 public depositFixedFee = 10 ether;

    /// @notice Deposit percentage (500/1,000,000 = 0.05%)
    uint256 public depositPercentageBps = 500;

    /// @notice Deposit fee cap in COTI wei
    uint256 public depositMaxFee = 3000 ether;

    /// @notice Withdraw fee floor in COTI wei
    uint256 public withdrawFixedFee = 3 ether;

    /// @notice Withdraw percentage (250/1,000,000 = 0.025%)
    uint256 public withdrawPercentageBps = 250;

    /// @notice Withdraw fee cap in COTI wei
    uint256 public withdrawMaxFee = 1500 ether;

    // --- END OF DEFAULT FEES

    /// @notice CotiPriceConsumer contract address
    address public priceOracle;

    /// @notice Address where collected fees are sent
    address public feeRecipient;

    /// @notice Address where rescued funds are sent
    address public rescueRecipient;

    error AmountZero();
    error InsufficientEthBalance();
    error EthTransferFailed();
    error InvalidAddress();
    error DepositDisabled();
    error InsufficientCotiFee();
    error BridgePaused();
    error OracleTimestampMismatch(uint256 expected, uint256 actual);
    error FeeRecipientNotSet();

    // Limits errors
    error InvalidLimitConfiguration();
    error DepositBelowMinimum();
    error DepositExceedsMaximum();
    error WithdrawBelowMinimum();
    error WithdrawExceedsMaximum();
    error InvalidFee();
    error InvalidFeeConfiguration();
    error InsufficientAccumulatedFees();
    error WithdrawFeesMustBeOverridden();

    /// @notice Emitted when a user deposits tokens
    /// @param user        Address of the user
    /// @param grossAmount Total amount provided by the user before fees
    /// @param netAmount   Net amount credited to the user after fees
    event Deposit(address indexed user, uint256 grossAmount, uint256 netAmount);

    /// @notice Emitted when a user withdraws tokens
    /// @param user        Address of the user
    /// @param grossAmount Total amount of private tokens burned / requested
    /// @param netAmount   Net public/native amount sent to the user after fees
    event Withdraw(address indexed user, uint256 grossAmount, uint256 netAmount);

    /// @notice Emitted when deposit/withdrawal limits are updated
    event LimitsUpdated(
        uint256 minDeposit,
        uint256 maxDeposit,
        uint256 minWithdraw,
        uint256 maxWithdraw
    );

    /// @notice Emitted when fees are updated
    event FeeUpdated(string feeType, uint256 newFeeBasisPoints);

    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed to, uint256 amount);

    constructor(address _feeRecipient, address _rescueRecipient) Ownable() {
        if (_feeRecipient == address(0)) revert InvalidAddress();
        if (_rescueRecipient == address(0)) revert InvalidAddress();
        maxDepositAmount = type(uint256).max;
        maxWithdrawAmount = type(uint256).max;
        minDepositAmount = 1;
        minWithdrawAmount = 1;
        feeRecipient = _feeRecipient;
        rescueRecipient = _rescueRecipient;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    modifier onlyOperator() {
        _checkRole(OPERATOR_ROLE, msg.sender);
        _;
    }

    function addOperator(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (account == address(0)) revert InvalidAddress();
        _grantRole(OPERATOR_ROLE, account);
        emit OperatorAdded(account, msg.sender);
    }

    function removeOperator(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (account == address(0)) revert InvalidAddress();
        _revokeRole(OPERATOR_ROLE, account);
        emit OperatorRemoved(account, msg.sender);
    }

    function isOperator(address account) external view returns (bool) {
        return hasRole(OPERATOR_ROLE, account);
    }

    /**
     * @dev Overrides Ownable's transferOwnership to automatically grant roles to new owner
     *      and revoke all existing operators to prevent hidden privileged actors.
     */
    function transferOwnership(address newOwner) public override onlyOwner {
        if (newOwner == address(0)) revert InvalidAddress();

        // Revoke all existing operators before transferring
        uint256 operatorCount = getRoleMemberCount(OPERATOR_ROLE);
        for (uint256 i = operatorCount; i > 0; i--) {
            address op = getRoleMember(OPERATOR_ROLE, i - 1);
            _revokeRole(OPERATOR_ROLE, op);
        }

        // Revoke all existing admins
        uint256 adminCount = getRoleMemberCount(DEFAULT_ADMIN_ROLE);
        for (uint256 i = adminCount; i > 0; i--) {
            address admin = getRoleMember(DEFAULT_ADMIN_ROLE, i - 1);
            _revokeRole(DEFAULT_ADMIN_ROLE, admin);
        }

        super.transferOwnership(newOwner);
        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
        _grantRole(OPERATOR_ROLE, newOwner);
    }

    /**
     * @dev Disabled to prevent split-brain state between Ownable and AccessControl.
     *      Use transferOwnership instead.
     */
    function renounceOwnership() public override onlyOwner {
        revert("renounceOwnership disabled");
    }

    /**
     * @notice Update deposit and withdrawal limits
     * @dev Ensures min values are less than or equal to max values.
     *      Setting _maxDeposit or _maxWithdraw to 0 effectively disables deposits or withdrawals.
     * @param _minDeposit New minimum deposit amount
     * @param _maxDeposit New maximum deposit amount
     * @param _minWithdraw New minimum withdrawal amount
     * @param _maxWithdraw New maximum withdrawal amount
     */
    function setLimits(
        uint256 _minDeposit,
        uint256 _maxDeposit,
        uint256 _minWithdraw,
        uint256 _maxWithdraw
    ) external onlyOwner {
        if (_minDeposit > _maxDeposit) revert InvalidLimitConfiguration();
        if (_minWithdraw > _maxWithdraw) revert InvalidLimitConfiguration();
        minDepositAmount = _minDeposit;
        maxDepositAmount = _maxDeposit;
        minWithdrawAmount = _minWithdraw;
        maxWithdrawAmount = _maxWithdraw;

        emit LimitsUpdated(
            _minDeposit,
            _maxDeposit,
            _minWithdraw,
            _maxWithdraw
        );
    }

    /**
     * @notice Pause the bridge, preventing deposits and withdrawals
     * @dev Only the owner can call this function
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpause the bridge, allowing deposits and withdrawals again
     * @dev Only the owner can call this function
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Check if a deposit amount is within configured limits
     * @param amount The amount to check
     * @dev Reverts if amount is below minimum or above maximum
     */
    function _checkDepositLimits(uint256 amount) internal view {
        if (amount < minDepositAmount) revert DepositBelowMinimum();
        if (amount > maxDepositAmount) revert DepositExceedsMaximum();
    }

    /**
     * @notice Check if a withdrawal amount is within configured limits
     * @param amount The amount to check
     * @dev Reverts if amount is below minimum or exceeds maximum withdrawal limit
     */
    function _checkWithdrawLimits(uint256 amount) internal view {
        if (amount < minWithdrawAmount) revert WithdrawBelowMinimum();
        if (amount > maxWithdrawAmount) revert WithdrawExceedsMaximum();
    }

    /**
     * @notice Set the deposit fee
     * @param _feeBasisPoints New deposit fee in fee units (max 100,000 = 10%)
     * @dev Only the operator can call this function
     */
    function setDepositFee(uint256 _feeBasisPoints) external onlyOperator {
        if (_feeBasisPoints > MAX_FEE_UNITS) revert InvalidFee();
        depositFeeBasisPoints = _feeBasisPoints;
        emit FeeUpdated("deposit", _feeBasisPoints);
    }

    /**
     * @notice Set the withdrawal fee
     * @param _feeBasisPoints New withdrawal fee in fee units (max 100,000 = 10%)
     * @dev Only the operator can call this function
     */
    function setWithdrawFee(uint256 _feeBasisPoints) external onlyOperator {
        if (_feeBasisPoints > MAX_FEE_UNITS) revert InvalidFee();
        withdrawFeeBasisPoints = _feeBasisPoints;
        emit FeeUpdated("withdraw", _feeBasisPoints);
    }

    /**
     * @notice Toggle deposit functionality
     * @param _enabled True to enable, false to disable
     * @dev Only the operator can call this function
     */
    function setIsDepositEnabled(bool _enabled) external onlyOperator {
        isDepositEnabled = _enabled;
        emit DepositEnabledUpdated(_enabled, msg.sender);
    }

    /**
     * @notice Set the native COTI fee
     * @param _fee Amount in native tokens (wei-equivalent)
     * @dev Used by ERC20 bridges: they require msg.value >= this value and refund excess to the caller (best-effort).
     *      Only the operator can call this function. Operators are responsible for setting reasonable fees
     *      and can change fees back whenever needed.
     */
    function setNativeCotiFee(uint256 _fee) external virtual onlyOperator {
        nativeCotiFee = _fee;
        emit NativeCotiFeeUpdated(_fee, msg.sender);
    }

    /**
     * @notice Validate oracle timestamps for both COTI and a bridged token.
     * @dev Used by ERC20 bridges where the fee depends on two oracle prices.
     * @param expectedCotiTimestamp The COTI lastUpdated from the estimate call.
     * @param expectedTokenTimestamp The token lastUpdated from the estimate call.
     * @param tokenSymbol The Band oracle symbol for the bridged token.
     */
    function _validateOracleTimestamps(
        uint256 expectedCotiTimestamp,
        uint256 expectedTokenTimestamp,
        string memory tokenSymbol
    ) internal view {
        (, uint256 cotiLastUpdated,) = ICotiPriceConsumer(priceOracle).getPriceWithMeta("COTI");
        if (cotiLastUpdated != expectedCotiTimestamp) revert OracleTimestampMismatch(expectedCotiTimestamp, cotiLastUpdated);
        (, uint256 tokenLastUpdated,) = ICotiPriceConsumer(priceOracle).getPriceWithMeta(tokenSymbol);
        if (tokenLastUpdated != expectedTokenTimestamp) revert OracleTimestampMismatch(expectedTokenTimestamp, tokenLastUpdated);
    }

    /**
     * @notice Calculate the dynamic fee using the floor/cap formula
     * @param percentageFeeCoti The percentage-based fee component in COTI
     * @param fixedFee The minimum fee floor in COTI
     * @param maxFee The maximum fee cap in COTI
     * @return The computed fee: min(max(fixedFee, percentageFeeCoti), maxFee)
     */
    function _calculateDynamicFee(
        uint256 percentageFeeCoti,
        uint256 fixedFee,
        uint256 maxFee
    ) internal pure returns (uint256) {
        uint256 fee = percentageFeeCoti > fixedFee ? percentageFeeCoti : fixedFee;
        return fee > maxFee ? maxFee : fee;
    }

    /**
     * @notice Estimate functions are declared in derived contracts (Native and ERC20 bridges)
     *         with different return signatures:
     *         - Native: returns (fee, lastUpdated, blockTimestamp)
     *         - ERC20:  returns (fee, cotiLastUpdated, tokenLastUpdated, blockTimestamp)
     */

    /**
     * @notice Set the deposit dynamic fee parameters
     * @param _fixedFee New deposit fee floor in COTI wei
     * @param _percentageBps New deposit percentage (max MAX_FEE_UNITS = 10%)
     * @param _maxFee New deposit fee cap in COTI wei
     * @dev Only the operator can call this function
     */
    function setDepositDynamicFee(
        uint256 _fixedFee,
        uint256 _percentageBps,
        uint256 _maxFee
    ) external onlyOperator {
        if (_maxFee == 0) revert InvalidFeeConfiguration();
        if (_fixedFee > _maxFee) revert InvalidFeeConfiguration();
        if (_percentageBps > MAX_FEE_UNITS) revert InvalidFee();
        depositFixedFee = _fixedFee;
        depositPercentageBps = _percentageBps;
        depositMaxFee = _maxFee;
        emit DynamicFeeUpdated("deposit", _fixedFee, _percentageBps, _maxFee);
    }

    /**
     * @notice Set the withdraw dynamic fee parameters
     * @param _fixedFee New withdraw fee floor in COTI wei
     * @param _percentageBps New withdraw percentage (max MAX_FEE_UNITS = 10%)
     * @param _maxFee New withdraw fee cap in COTI wei
     * @dev Only the operator can call this function
     */
    function setWithdrawDynamicFee(
        uint256 _fixedFee,
        uint256 _percentageBps,
        uint256 _maxFee
    ) external onlyOperator {
        if (_maxFee == 0) revert InvalidFeeConfiguration();
        if (_fixedFee > _maxFee) revert InvalidFeeConfiguration();
        if (_percentageBps > MAX_FEE_UNITS) revert InvalidFee();
        withdrawFixedFee = _fixedFee;
        withdrawPercentageBps = _percentageBps;
        withdrawMaxFee = _maxFee;
        emit DynamicFeeUpdated("withdraw", _fixedFee, _percentageBps, _maxFee);
    }

    /**
     * @notice Set the price oracle address
     * @param _oracle Address of the CotiPriceConsumer contract
     * @dev Only the owner can call this function
     */
    function setPriceOracle(address _oracle) external onlyOwner {
        if (_oracle == address(0)) revert InvalidAddress();
        address oldOracle = priceOracle;
        priceOracle = _oracle;
        emit PriceOracleUpdated(oldOracle, _oracle);
    }


    /**
     * @notice Calculate fee amount based on the input amount and fee basis points
     * @param amount The amount to calculate fee for
     * @param feeBasisPoints Fee in basis points (100 bp = 1%)
     * @return The fee amount
     */
    function _calculateFeeAmount(
        uint256 amount,
        uint256 feeBasisPoints
    ) internal pure returns (uint256) {
        if (feeBasisPoints == 0) return 0;
        return Math.mulDiv(amount, feeBasisPoints, FEE_DIVISOR);
    }

    /**
     * @notice Deducts the bridged-asset fee from `grossAmount`, accumulates it, and returns the net amount.
     * @dev Reverts with {AmountZero} if the net amount after fee is zero.
     * @param grossAmount The gross token amount before fee deduction.
     * @param feeBasisPoints The fee rate to apply (deposit or withdraw basis points).
     * @return net The amount the user receives / the bridge releases after fee.
     */
    function _collectTokenFee(
        uint256 grossAmount,
        uint256 feeBasisPoints
    ) internal returns (uint256 net) {
        uint256 fee = _calculateFeeAmount(grossAmount, feeBasisPoints);
        net = grossAmount - fee;
        if (net == 0) revert AmountZero();
        accumulatedFees += fee;
    }

    /**
     * @notice Withdraw accumulated fees to the predefined feeRecipient
     * @param amount Amount of fees to withdraw
     * @dev Only the owner can call this function. Must be overridden in derived contracts
     *      to perform the actual token/native transfer; base implementation reverts.
     */
    function withdrawFees(
        uint256 amount
    ) external virtual onlyOwner {
        if (feeRecipient == address(0)) revert FeeRecipientNotSet();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedFees) revert InsufficientAccumulatedFees();
        revert WithdrawFeesMustBeOverridden();
    }

    event CotiFeesWithdrawn(address indexed to, uint256 amount);

    /**
     * @notice Withdraw accumulated native COTI fees to the predefined feeRecipient
     * @param amount Amount of native COTI fees to withdraw
     * @dev Only the owner can call this function.
     */
    function withdrawCotiFees(uint256 amount) external onlyOwner nonReentrant {
        if (feeRecipient == address(0)) revert FeeRecipientNotSet();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedCotiFees) revert InsufficientAccumulatedFees();
        if (amount > address(this).balance) revert InsufficientEthBalance();

        accumulatedCotiFees -= amount;

        (bool success, ) = feeRecipient.call{value: amount}("");
        if (!success) revert EthTransferFailed();

        emit CotiFeesWithdrawn(feeRecipient, amount);
    }
}
