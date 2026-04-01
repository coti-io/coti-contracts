// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "../token/PrivateERC20/tokens/PrivateCOTI.sol";
import "../token/PrivateERC20/ITokenReceiver.sol";

/**
 * @title PrivacyBridgeCotiNative
 * @notice Bridge contract for converting between native COTI and privacy-preserving COTI.p tokens
 */
contract PrivacyBridgeCotiNative is PrivacyBridge, ITokenReceiver {
    PrivateCOTI public privateCoti;

    error ExceedsRescueableAmount();
    error NativeCotiFeeNotApplicable();

    event NativeRescued(address indexed to, uint256 amount);

    // Scaling factor removed (using native 18 decimals due to uint256 upgrade)

    /**
     * @notice Initialize the Native Bridge
     * @param _privateCoti Address of the PrivateCoti token contract
     */
    constructor(address _privateCoti) PrivacyBridge() {
        if (_privateCoti == address(0)) revert InvalidAddress();
        privateCoti = PrivateCOTI(_privateCoti);
    }

    /**
     * @notice Internal function to handle deposits
     * @param sender Address of the depositor
     */
    function _deposit(address sender) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (msg.value == 0) revert AmountZero();

        _checkDepositLimits(msg.value);

        // Deduct bridged-asset deposit fee, get net amount to mint
        uint256 amountAfterFee = _collectTokenFee(msg.value, depositFeeBasisPoints);

        privateCoti.mint(sender, amountAfterFee);

        // Emit gross deposit amount and net private tokens minted
        emit Deposit(sender, msg.value, amountAfterFee);
    }

    /**
     * @notice Deposit native COTI to receive private COTI (COTI.p)
     * @dev User sends native COTI with the transaction
     */
    function deposit() external payable nonReentrant whenNotPaused {
        _deposit(msg.sender);
    }

    /**
     * @notice Withdraw native COTI by burning private COTI
     * @param amount Amount of private COTI to burn
     * @dev User must have approved the bridge to spend their private tokens.
     */
    /**
     * @notice Handle callback from PrivateCoti.transferAndCall
     * @dev Called when user transfers tokens to the bridge to withdraw. Third parameter (data) is required by ITokenReceiver but unused.
     * @param from Address of the sender
     * @param amount Amount of tokens received
     */
    function onTokenReceived(
        address from,
        uint256 amount,
        bytes calldata
    ) external nonReentrant whenNotPaused returns (bool) {
        if (msg.sender != address(privateCoti)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();

        _checkWithdrawLimits(amount);

        // Deduct bridged-asset withdrawal fee, get net amount to release
        uint256 publicAmount = _collectTokenFee(amount, withdrawFeeBasisPoints);

        if (address(this).balance < publicAmount)
            revert InsufficientEthBalance();

        // Private tokens are already transferred to this contract by transferAndCall
        // We just need to burn them.
        privateCoti.burn(amount);

        (bool success, ) = from.call{value: publicAmount}("");
        if (!success) revert EthTransferFailed();

        // Emit gross private amount burned and net native COTI sent
        emit Withdraw(from, amount, publicAmount);
        return true;
    }

    /**
     * @notice Withdraw native COTI by burning private COTI
     * @param amount Amount of private COTI to burn
     * @dev User must have approved the bridge to spend their private tokens.
     */
    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        _withdraw(msg.sender, amount);
    }

    function _withdraw(
        address to,
        uint256 amount
    ) internal {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);

        // Deduct bridged-asset withdrawal fee, get net amount to release
        uint256 publicAmount = _collectTokenFee(amount, withdrawFeeBasisPoints);

        if (address(this).balance < publicAmount)
            revert InsufficientEthBalance();

        // Pull and burn private tokens
        IPrivateERC20(address(privateCoti)).transferFrom(
            msg.sender,
            address(this),
            amount
        );
        privateCoti.burn(amount);

        (bool success, ) = to.call{value: publicAmount}("");
        if (!success) revert EthTransferFailed();

        emit Withdraw(to, amount, publicAmount);
    }

    /**
     * @notice Fallback function to handle direct COTI transfers as deposits
     */
    receive() external payable nonReentrant whenNotPaused {
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
    function withdrawFees(
        address to,
        uint256 amount
    ) external override onlyOperator nonReentrant {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedFees) revert InsufficientAccumulatedFees();
        if (amount > address(this).balance) revert InsufficientEthBalance();

        accumulatedFees -= amount;

        // Transfer native COTI tokens
        (bool success, ) = to.call{value: amount}("");
        if (!success) revert EthTransferFailed();

        emit FeesWithdrawn(to, amount);
    }

    /**
     * @dev Rescue native COTI coins mistakenly sent to the contract.
     *      Only excess over the accumulated fee reserve can be rescued.
     *      Owner must NOT rescue amounts that would remove liquidity needed for user withdrawals;
     *      doing so would break withdraw() and onTokenReceived() until new deposits restore balance.
     * @param to Address to send the coins to
     * @param amount Amount of coins to rescue
     * @notice Only the owner can call this function
     */
    function rescueNative(address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > address(this).balance) revert InsufficientEthBalance();
        if (address(this).balance < accumulatedFees) revert InsufficientEthBalance();
        if (amount > address(this).balance - accumulatedFees) revert ExceedsRescueableAmount();

        (bool success, ) = to.call{value: amount}("");
        if (!success) revert EthTransferFailed();

        emit NativeRescued(to, amount);
    }

    /**
     * @notice Native bridge does not use nativeCotiFee; always reverts.
     */
    function setNativeCotiFee(uint256) external pure override {
        revert NativeCotiFeeNotApplicable();
    }
}
