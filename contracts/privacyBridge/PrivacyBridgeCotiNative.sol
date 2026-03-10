// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "../token/PrivateERC20/tokens/PrivateCOTI.sol";
import "../token/PrivateERC20/ITokenReceiver.sol";
import "../utils/mpc/MpcCore.sol";

/**
 * @title PrivacyBridgeCotiNative
 * @notice Bridge contract for converting between native COTI and privacy-preserving COTI.p tokens
 */
contract PrivacyBridgeCotiNative is PrivacyBridge, ITokenReceiver {
    PrivateCOTI public privateCoti;

    error ExceedsRescueableAmount();

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
    function _deposit(
        address sender,
        bool isEncrypted,
        itUint256 memory encryptedAmount
    ) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (msg.value == 0) revert AmountZero();

        _checkDepositLimits(msg.value);

        // Calculate and deduct deposit fee
        uint256 feeAmount = _calculateFeeAmount(
            msg.value,
            depositFeeBasisPoints
        );
        uint256 amountAfterFee = msg.value - feeAmount;
        accumulatedFees += feeAmount;

        if (isEncrypted) {
            // Verify parity between msg.value and encrypted amount
            gtUint256 gtAmount = MpcCore.validateCiphertext(encryptedAmount);
            gtBool amountMatch = MpcCore.eq(
                gtAmount,
                MpcCore.setPublic256(amountAfterFee)
            );
            require(MpcCore.decrypt(amountMatch), "Encrypted amount mismatch");

            gtBool mintOk = privateCoti.mint(sender, encryptedAmount);
            require(MpcCore.decrypt(mintOk), "Mint failed");
        } else {
            privateCoti.mint(sender, amountAfterFee);
        }

        // Emit gross deposit amount and net private tokens minted
        emit Deposit(sender, msg.value, amountAfterFee);
    }

    /**
     * @notice Deposit native COTI to receive private COTI (COTI.p)
     * @dev User sends native COTI with the transaction
     */
    function deposit() external payable nonReentrant whenNotPaused {
        _deposit(
            msg.sender,
            false,
            itUint256(ctUint256(ctUint128.wrap(0), ctUint128.wrap(0)), "")
        );
    }

    /**
     * @notice Deposit native COTI with an encrypted amount for the private minting event
     * @param encryptedAmount Encrypted amount to mint
     */
    function deposit(itUint256 calldata encryptedAmount) external payable nonReentrant whenNotPaused {
        _deposit(msg.sender, true, encryptedAmount);
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

        // Calculate fee
        uint256 feeAmount = _calculateFeeAmount(amount, withdrawFeeBasisPoints);
        uint256 publicAmount = amount - feeAmount;
        accumulatedFees += feeAmount;

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
        _withdraw(
            msg.sender,
            amount,
            false,
            itUint256(ctUint256(ctUint128.wrap(0), ctUint128.wrap(0)), "")
        );
    }

    /**
     * @notice Withdraw native COTI by burning private COTI with an encrypted amount
     * @param amount Public amount to release
     * @param encryptedAmount Encrypted amount to burn
     */
    function withdraw(
        uint256 amount,
        itUint256 calldata encryptedAmount
    ) external nonReentrant whenNotPaused {
        _withdraw(msg.sender, amount, true, encryptedAmount);
    }

    function _withdraw(
        address to,
        uint256 amount,
        bool isEncrypted,
        itUint256 memory encryptedAmount
    ) internal {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);

        // Calculate fee on the public side
        uint256 feeAmount = _calculateFeeAmount(amount, withdrawFeeBasisPoints);
        uint256 publicAmount = amount - feeAmount;
        accumulatedFees += feeAmount;

        if (address(this).balance < publicAmount)
            revert InsufficientEthBalance();

        if (isEncrypted) {
            // Verify parity
            gtUint256 gtAmount = MpcCore.validateCiphertext(encryptedAmount);
            gtBool amountMatch = MpcCore.eq(
                gtAmount,
                MpcCore.setPublic256(amount)
            );
            require(MpcCore.decrypt(amountMatch), "Encrypted amount mismatch");

            // Use already-validated gt handle so PrivateCOTI does not re-call
            // validateCiphertext with a different contract context (signature mismatch)
            IPrivateERC20(address(privateCoti)).transferFromGT(
                msg.sender,
                address(this),
                gtAmount
            );
            gtBool burnOk = privateCoti.burnGt(gtAmount);
            require(MpcCore.decrypt(burnOk), "Burn failed");
        } else {
            // Standard withdrawal (public amount)
            IPrivateERC20(address(privateCoti)).transferFrom(
                msg.sender,
                address(this),
                amount
            );
            privateCoti.burn(amount);
        }

        (bool success, ) = to.call{value: publicAmount}("");
        if (!success) revert EthTransferFailed();

        emit Withdraw(to, amount, publicAmount);
    }

    /**
     * @notice Fallback function to handle direct COTI transfers as deposits
     */
    receive() external payable nonReentrant whenNotPaused {
        _deposit(
            msg.sender,
            false,
            itUint256(ctUint256(ctUint128.wrap(0), ctUint128.wrap(0)), "")
        );
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
    ) external override onlyOwner {
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
    function rescueNative(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > address(this).balance) revert InsufficientEthBalance();
        if (address(this).balance < accumulatedFees) revert InsufficientEthBalance();
        if (amount > address(this).balance - accumulatedFees) revert ExceedsRescueableAmount();

        (bool success, ) = to.call{value: amount}("");
        if (!success) revert EthTransferFailed();
    }
}
