// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../IPrivateERC20.sol";
import "@coti-io/coti-contracts/contracts/utils/mpc/MpcCore.sol";


/**
 * @dev Abstract base contract for ERC20 Token Privacy Bridges
 * @dev Handles the logic for bridging ERC20 tokens to their private counterparts.
 */
contract PrivacyBridgeERC20 is PrivacyBridge, ITokenReceiver {
    /// @notice The public ERC20 token being bridged (e.g., USDC, WETH)
    IERC20 public token;

    /// @notice Address of the private token contract
    address public privateTokenAddress;

    error InvalidTokenAddress();
    error InvalidPrivateTokenAddress();
    error InvalidScalingFactor();
    error AmountTooLarge();
    error AmountTooSmall();
    error InsufficientBridgeLiquidity();
    error TokenTransferFailed();
    error InvalidTokenSender();

    /// @notice Scaling factor to convert between public and private token decimals
    // SCALING_FACTOR removed (deprecated)

    /**
     * @notice Initialize the PrivacyBridgeERC20 contract
     * @param _token Address of the public ERC20 token
     * @param _privateToken Address of the private token
     */
    constructor(address _token, address _privateToken) PrivacyBridge() {
        if (_token == address(0)) revert InvalidTokenAddress();
        if (_privateToken == address(0)) revert InvalidPrivateTokenAddress();

        token = IERC20(_token);
        privateTokenAddress = _privateToken;
    }

    // Hooks removed: logic implemented directly using IPrivateERC20 interface

    /**
     * @notice Deposit public ERC20 tokens to receive equivalent private tokens
     * @param amount Amount of public ERC20 tokens to deposit
     */
    function deposit(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert AmountZero();
        
        _checkDepositLimits(amount);

        bool success = token.transferFrom(msg.sender, address(this), amount);
        if (!success) revert TokenTransferFailed();

        // Calculate and deduct deposit fee
        uint256 feeAmount = _calculateFeeAmount(amount, depositFeeBasisPoints);
        uint256 amountAfterFee = amount - feeAmount;
        accumulatedFees += feeAmount;

        IPrivateERC20(privateTokenAddress).mint(msg.sender, amountAfterFee);

        emit Deposit(msg.sender, amount);
    }

    /**
     * @notice Withdraw public ERC20 tokens by burning private tokens
     * @param amount Amount of private tokens to burn
     * @dev DEPRECATED: Use privateToken.transferAndCall(bridge, amount, "") instead
     *      This function requires prior approval which needs encrypted signature
     */
    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);
        
        // Calculate fee
        uint256 feeAmount = _calculateFeeAmount(amount, withdrawFeeBasisPoints);
        uint256 publicAmount = amount - feeAmount;
        accumulatedFees += feeAmount;
        
        uint256 bridgeBalance = token.balanceOf(address(this));
        if (bridgeBalance < publicAmount) revert InsufficientBridgeLiquidity();
        
        // Transfer private tokens from user to bridge (requires prior approval)
        gtUint256 memory gtAmount = MpcCore.setPublic256(amount);
        IPrivateERC20(privateTokenAddress).transferFrom(msg.sender, address(this), gtAmount);
        
        // Burn private tokens from bridge's balance
        IPrivateERC20(privateTokenAddress).burn(amount);
        
        // Transfer public tokens to user (minus fee)
        bool success = token.transfer(msg.sender, publicAmount);
        if (!success) revert TokenTransferFailed();
        
        emit Withdraw(msg.sender, amount);
    }

    /**
     * @notice Callback for receiving private tokens via transferAndCall
     * @param from The address that sent the tokens
     * @param amount The amount of tokens transferred
     * @param data Additional data (unused)
     * @return success Whether the callback succeeded
     * @dev This is the preferred withdrawal method - no approval needed!
     *      User calls: privateToken.transferAndCall(bridge, amount, "")
     */
    function onTokenReceived(address from, uint256 amount, bytes calldata data) external override nonReentrant whenNotPaused returns (bool) {
        // Only accept tokens from our private token contract
        if (msg.sender != privateTokenAddress) revert InvalidTokenSender();
        if (amount == 0) revert AmountZero();
        
        _checkWithdrawLimits(amount);
        
        // Calculate fee
        uint256 feeAmount = _calculateFeeAmount(amount, withdrawFeeBasisPoints);
        uint256 publicAmount = amount - feeAmount;
        accumulatedFees += feeAmount;
        
        uint256 bridgeBalance = token.balanceOf(address(this));
        if (bridgeBalance < publicAmount) revert InsufficientBridgeLiquidity();
        
        // Burn private tokens (already received by bridge via transfer)
        IPrivateERC20(privateTokenAddress).burn(amount);
        
        // Transfer public tokens to original sender (minus fee)
        bool success = token.transfer(from, publicAmount);
        if (!success) revert TokenTransferFailed();
        
        emit Withdraw(from, amount);
        return true;
    }

    /**
     * @notice Withdraw accumulated fees (ERC20 implementation)
     * @param to Address to send fees to
     * @param amount Amount of fees to withdraw
     * @dev Only the owner can call this function
     */
    function withdrawFees(address to, uint256 amount) external override onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedFees) revert InsufficientAccumulatedFees();
        
        accumulatedFees -= amount;
        
        // Transfer public ERC20 tokens
        bool success = token.transfer(to, amount);
        if (!success) revert TokenTransferFailed();
        
        emit FeesWithdrawn(to, amount);
    }

    /**
     * @dev Rescue ERC20 tokens sent to the contract
     */
    function rescueERC20(address _token, address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        
        bool success = IERC20(_token).transfer(to, amount);
        if (!success) revert TokenTransferFailed();
    }
}
