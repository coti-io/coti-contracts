// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "../tokens/PrivateCoti.sol";
import "../IPrivateERC20.sol";
import "@coti-io/coti-contracts/contracts/utils/mpc/MpcCore.sol";


/**
 * @title PrivacyBridgeCotiNative
 * @notice Bridge contract for converting between native COTI and privacy-preserving COTI.p tokens
 */
contract PrivacyBridgeCotiNative is PrivacyBridge, ITokenReceiver {
    PrivateCoti public privateCoti;
    
    // Scaling factor removed (using native 18 decimals due to uint256 upgrade)

    /**
     * @notice Initialize the Native Bridge
     * @param _privateCoti Address of the PrivateCoti token contract
     */
    constructor(address _privateCoti) PrivacyBridge() {
        if (_privateCoti == address(0)) revert InvalidAddress();
        privateCoti = PrivateCoti(_privateCoti);
    }

    /**
     * @notice Internal function to handle deposits
     * @param sender Address of the depositor
     */
    function _deposit(address sender) internal nonReentrant whenNotPaused {
        if (msg.value == 0) revert AmountZero();
        
        _checkDepositLimits(msg.value);
        
        // Calculate and deduct deposit fee
        uint256 feeAmount = _calculateFeeAmount(msg.value, depositFeeBasisPoints);
        uint256 amountAfterFee = msg.value - feeAmount;
        accumulatedFees += feeAmount;
        
        privateCoti.mint(sender, amountAfterFee);
        
        emit Deposit(sender, msg.value);
    }

    /**
     * @notice Deposit native COTI to receive private COTI (COTI.p)
     * @dev User sends native COTI with the transaction
     */
    function deposit() external payable {
        _deposit(msg.sender);
    }

    /**
     * @notice Withdraw native COTI by burning private COTI
     * @param amount Amount of private COTI to burn
     * @dev User must have approved the bridge to spend their private tokens.
     */
    /**
     * @notice Handle callback from PrivateCoti.transferAndCall
     * @dev Called when user transfers tokens to the bridge to withdraw
     * @param from Address of the sender
     * @param amount Amount of tokens received
     * @param data Additional data (unused)
     */
    function onTokenReceived(address from, uint256 amount, bytes calldata data) external nonReentrant whenNotPaused returns (bool) {
        if (msg.sender != address(privateCoti)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        
        _checkWithdrawLimits(amount);
        
        // Calculate fee
        uint256 feeAmount = _calculateFeeAmount(amount, withdrawFeeBasisPoints);
        uint256 publicAmount = amount - feeAmount;
        accumulatedFees += feeAmount;
        
        if (address(this).balance < publicAmount) revert InsufficientEthBalance();
        
        // Private tokens are already transferred to this contract by transferAndCall
        // We just need to burn them.
        privateCoti.burn(amount);
        
        (bool success, ) = from.call{value: publicAmount}("");
        if (!success) revert EthTransferFailed();
        
        emit Withdraw(from, amount);
        return true;
    }

    /**
     * @notice Deprecated: Withdraw native COTI by burning private COTI
     * @dev Kept for backward compatibility if needed, but transferAndCall is preferred
     */
    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);
        
        // Calculate fee
        uint256 feeAmount = _calculateFeeAmount(amount, withdrawFeeBasisPoints);
        uint256 publicAmount = amount - feeAmount;
        accumulatedFees += feeAmount;
        
        if (address(this).balance < publicAmount) revert InsufficientEthBalance();
        
        // Transfer private tokens from user to bridge (requires prior approval)
        gtUint256 memory gtAmount = MpcCore.setPublic256(amount);
        IPrivateERC20(address(privateCoti)).transferFrom(msg.sender, address(this), gtAmount);
        
        // Burn private tokens from bridge's balance
        privateCoti.burn(amount);
        
        (bool success, ) = msg.sender.call{value: publicAmount}("");
        if (!success) revert EthTransferFailed();
        
        emit Withdraw(msg.sender, amount);
    }

    /**
     * @notice Fallback function to handle direct COTI transfers as deposits
     */
    receive() external payable {
        _deposit(msg.sender);
    }
    
    /**
     * @notice Get the native COTI balance held by the bridge
     * @return The contract's balance in native units (wei-equivalent)
     */
    function getBridgeBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Withdraw accumulated fees (Native implementation)
     * @param to Address to send fees to
     * @param amount Amount of fees to withdraw
     * @dev Only the owner can call this function
     */
    function withdrawFees(address to, uint256 amount) external override onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedFees) revert InsufficientAccumulatedFees();
        
        accumulatedFees -= amount;
        
        // Transfer native COTI tokens
        (bool success, ) = to.call{value: amount}("");
        if (!success) revert EthTransferFailed();
        
        emit FeesWithdrawn(to, amount);
    }

    /**
     * @dev Rescue native COTI coins sent to the contract
     * @param to Address to send the coins to
     * @param amount Amount of coins to rescue
     * @notice Only the owner can call this function
     */
    function rescueNative(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > address(this).balance) revert InsufficientEthBalance();
        
        (bool success,) = to.call{value: amount}("");
        if (!success) revert EthTransferFailed();
    }

}
