// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PrivacyBridge
 * @notice Base contract for Privacy Bridge contracts containing common logic
 */
abstract contract PrivacyBridge is ReentrancyGuard, Pausable, Ownable {
    /// @notice Maximum amount that can be deposited in a single transaction
    uint256 public maxDepositAmount;

    /// @notice Maximum amount that can be withdrawn in a single transaction
    uint256 public maxWithdrawAmount;

    /// @notice Minimum amount required for a deposit
    uint256 public minDepositAmount;

    /// @notice Minimum amount required for a withdrawal
    uint256 public minWithdrawAmount;

    /// @notice Deposit fee in basis points (1 bp = 0.01%, 100 bp = 1%)
    uint256 public depositFeeBasisPoints;

    /// @notice Withdrawal fee in basis points (1 bp = 0.01%, 100 bp = 1%)
    uint256 public withdrawFeeBasisPoints;

    /// @notice Accumulated fees collected by the bridge
    uint256 public accumulatedFees;

    /// @notice Maximum fee allowed (10% = 1000 basis points)
    uint256 public constant MAX_FEE_BASIS_POINTS = 1000;

    error AmountZero();
    error InsufficientEthBalance();
    error EthTransferFailed();
    error InvalidAddress();
    
    // Limits errors
    error InvalidLimitConfiguration();
    error DepositBelowMinimum();
    error DepositExceedsMaximum();
    error WithdrawBelowMinimum();
    error WithdrawExceedsMaximum();
    error InvalidFee();
    error InsufficientAccumulatedFees();

    /// @notice Emitted when a user deposits tokens
    event Deposit(address indexed user, uint256 amount);
    
    /// @notice Emitted when a user withdraws tokens
    event Withdraw(address indexed user, uint256 amount);
    
    /// @notice Emitted when deposit/withdrawal limits are updated
    event LimitsUpdated(uint256 minDeposit, uint256 maxDeposit, uint256 minWithdraw, uint256 maxWithdraw);
    
    /// @notice Emitted when fees are updated
    event FeeUpdated(string feeType, uint256 newFeeBasisPoints);
    
    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed to, uint256 amount);

    constructor() Ownable(msg.sender) {
        maxDepositAmount = type(uint256).max;
        maxWithdrawAmount = type(uint256).max;
        minDepositAmount = 1;
        minWithdrawAmount = 1;
    }

    /**
     * @notice Update deposit and withdrawal limits
     * @dev Ensures min values are less than or equal to max values
     * @param _minDeposit New minimum deposit amount
     * @param _maxDeposit New maximum deposit amount
     * @param _minWithdraw New minimum withdrawal amount
     * @param _maxWithdraw New maximum withdrawal amount
     */
    function setLimits(uint256 _minDeposit, uint256 _maxDeposit, uint256 _minWithdraw, uint256 _maxWithdraw) external onlyOwner {
        if (_minDeposit > _maxDeposit) revert InvalidLimitConfiguration();
        if (_minWithdraw > _maxWithdraw) revert InvalidLimitConfiguration();
        minDepositAmount = _minDeposit;
        maxDepositAmount = _maxDeposit;
        minWithdrawAmount = _minWithdraw;
        maxWithdrawAmount = _maxWithdraw;
        
        emit LimitsUpdated(_minDeposit, _maxDeposit, _minWithdraw, _maxWithdraw);
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
     * @param _feeBasisPoints New deposit fee in basis points (max 1000 = 10%)
     * @dev Only the owner can call this function
     */
    function setDepositFee(uint256 _feeBasisPoints) external onlyOwner {
        if (_feeBasisPoints > MAX_FEE_BASIS_POINTS) revert InvalidFee();
        depositFeeBasisPoints = _feeBasisPoints;
        emit FeeUpdated("deposit", _feeBasisPoints);
    }

    /**
     * @notice Set the withdrawal fee
     * @param _feeBasisPoints New withdrawal fee in basis points (max 1000 = 10%)
     * @dev Only the owner can call this function
     */
    function setWithdrawFee(uint256 _feeBasisPoints) external onlyOwner {
        if (_feeBasisPoints > MAX_FEE_BASIS_POINTS) revert InvalidFee();
        withdrawFeeBasisPoints = _feeBasisPoints;
        emit FeeUpdated("withdraw", _feeBasisPoints);
    }

    /**
     * @notice Calculate fee amount based on the input amount and fee basis points
     * @param amount The amount to calculate fee for
     * @param feeBasisPoints Fee in basis points (100 bp = 1%)
     * @return The fee amount
     */
    function _calculateFeeAmount(uint256 amount, uint256 feeBasisPoints) internal pure returns (uint256) {
        if (feeBasisPoints == 0) return 0;
        return (amount * feeBasisPoints) / 10000;
    }

    /**
     * @notice Withdraw accumulated fees
     * @param to Address to send the fees to
     * @param amount Amount of fees to withdraw
     * @dev Only the owner can call this function
     */
    function withdrawFees(address to, uint256 amount) external virtual onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedFees) revert InsufficientAccumulatedFees();
        
        accumulatedFees -= amount;
        emit FeesWithdrawn(to, amount);
        
        // Note: Actual transfer implementation will be in derived contracts
        // since they handle the specific token type (ETH, ERC20, etc.)
    }
}
