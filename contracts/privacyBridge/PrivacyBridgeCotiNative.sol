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
    constructor(address _privateCoti, address _feeRecipient, address _rescueRecipient) PrivacyBridge(_feeRecipient, _rescueRecipient) {
        if (_privateCoti == address(0)) revert InvalidAddress();
        privateCoti = PrivateCOTI(_privateCoti);
    }

    /**
     * @notice Compute the dynamic fee in native COTI
     * @param cotiAmount The COTI amount to compute fee for
     * @param fixedFee The minimum fee floor in COTI wei
     * @param percentageBps The percentage in basis points (relative to FEE_DIVISOR)
     * @param maxFee The maximum fee cap in COTI wei
     * @return The computed fee in COTI wei
     */
    function _computeCotiFee(
        uint256 cotiAmount,
        uint256 fixedFee,
        uint256 percentageBps,
        uint256 maxFee
    ) internal view returns (uint256) {
        uint256 cotiUsdRate = ICotiPriceConsumer(priceOracle).getPrice("COTI");
        uint256 txValueUsd = (cotiAmount * cotiUsdRate) / 1e18;
        uint256 percentageFeeUsd = (txValueUsd * percentageBps) / FEE_DIVISOR;
        uint256 percentageFeeCoti = (percentageFeeUsd * 1e18) / cotiUsdRate;
        return _calculateDynamicFee(percentageFeeCoti, fixedFee, maxFee);
    }

    /**
     * @notice Estimate the deposit fee in COTI for a given COTI amount
     * @param cotiAmount The amount of native COTI to deposit
     * @return fee                The estimated fee in COTI wei
     * @return cotiLastUpdated    COTI oracle data last update timestamp
     * @return blockTimestamp     Current block.timestamp
     */
    function estimateDepositFee(uint256 cotiAmount) external view returns (uint256 fee, uint256 cotiLastUpdated, uint256 blockTimestamp) {
        fee = _computeCotiFee(cotiAmount, depositFixedFee, depositPercentageBps, depositMaxFee);
        (,cotiLastUpdated, blockTimestamp) = ICotiPriceConsumer(priceOracle).getPriceWithMeta("COTI");
    }

    /**
     * @notice Estimate the withdrawal fee in COTI for a given COTI amount
     * @param cotiAmount The amount of native COTI to withdraw
     * @return fee                The estimated fee in COTI wei
     * @return cotiLastUpdated    COTI oracle data last update timestamp
     * @return blockTimestamp     Current block.timestamp
     */
    function estimateWithdrawFee(uint256 cotiAmount) external view returns (uint256 fee, uint256 cotiLastUpdated, uint256 blockTimestamp) {
        fee = _computeCotiFee(cotiAmount, withdrawFixedFee, withdrawPercentageBps, withdrawMaxFee);
        (,cotiLastUpdated, blockTimestamp) = ICotiPriceConsumer(priceOracle).getPriceWithMeta("COTI");
    }

    /**
     * @notice Internal function to handle deposits
     * @param sender Address of the depositor
     */
    function _deposit(address sender, uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (msg.value == 0) revert AmountZero();

        _checkDepositLimits(msg.value);
        _validateOracleTimestamps(cotiOracleTimestamp, tokenOracleTimestamp, "COTI");

        // Compute dynamic fee in COTI
        uint256 fee = _computeCotiFee(msg.value, depositFixedFee, depositPercentageBps, depositMaxFee);
        uint256 netAmount = msg.value - fee;
        if (netAmount == 0) revert AmountZero();

        accumulatedCotiFees += fee;

        privateCoti.mint(sender, netAmount);

        // Emit gross deposit amount and net private tokens minted
        emit Deposit(sender, msg.value, netAmount);
    }

    /**
     * @notice Deposit native COTI to receive private COTI (COTI.p)
     * @param cotiOracleTimestamp The COTI oracle lastUpdated timestamp from estimateDepositFee
     * @param tokenOracleTimestamp The token oracle lastUpdated timestamp (same as cotiOracleTimestamp for native bridge)
     * @dev User sends native COTI with the transaction
     */
    function deposit(uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) external payable nonReentrant whenNotPaused {
        _deposit(msg.sender, cotiOracleTimestamp, tokenOracleTimestamp);
    }

    /**
     * @notice Handle callback from PrivateCoti.transferAndCall
     * @dev Called when user transfers tokens to the bridge to withdraw.
     *      The `data` parameter must be abi-encoded (uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp).
     * @param from Address of the sender
     * @param amount Amount of tokens received
     * @param data ABI-encoded (uint256, uint256) oracle timestamps from estimateWithdrawFee
     */
    function onTokenReceived(
        address from,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant whenNotPaused returns (bool) {
        if (msg.sender != address(privateCoti)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();

        (uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) = abi.decode(data, (uint256, uint256));
        _validateOracleTimestamps(cotiOracleTimestamp, tokenOracleTimestamp, "COTI");

        _checkWithdrawLimits(amount);

        // Compute dynamic withdrawal fee in COTI
        uint256 fee = _computeCotiFee(amount, withdrawFixedFee, withdrawPercentageBps, withdrawMaxFee);
        uint256 publicAmount = amount - fee;
        if (publicAmount == 0) revert AmountZero();

        accumulatedCotiFees += fee;

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
     * @param cotiOracleTimestamp The COTI oracle lastUpdated timestamp from estimateWithdrawFee
     * @param tokenOracleTimestamp The token oracle lastUpdated timestamp (same as cotiOracleTimestamp for native bridge)
     * @dev User must have approved the bridge to spend their private tokens.
     */
    function withdraw(uint256 amount, uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) external nonReentrant whenNotPaused {
        _withdraw(msg.sender, amount, cotiOracleTimestamp, tokenOracleTimestamp);
    }

    function _withdraw(
        address to,
        uint256 amount,
        uint256 cotiOracleTimestamp,
        uint256 tokenOracleTimestamp
    ) internal {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);
        _validateOracleTimestamps(cotiOracleTimestamp, tokenOracleTimestamp, "COTI");

        // Compute dynamic withdrawal fee in COTI
        uint256 fee = _computeCotiFee(amount, withdrawFixedFee, withdrawPercentageBps, withdrawMaxFee);
        uint256 publicAmount = amount - fee;
        if (publicAmount == 0) revert AmountZero();

        accumulatedCotiFees += fee;

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
     * @notice Internal deposit without oracle timestamp validation.
     * @dev Used by receive() for direct COTI transfers. Fee is computed at current oracle price
     *      without checking that the price hasn't changed since an estimate call.
     */
    function _directDeposit(address sender) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (msg.value == 0) revert AmountZero();

        _checkDepositLimits(msg.value);

        uint256 fee = _computeCotiFee(msg.value, depositFixedFee, depositPercentageBps, depositMaxFee);
        uint256 netAmount = msg.value - fee;
        if (netAmount == 0) revert AmountZero();

        accumulatedCotiFees += fee;

        privateCoti.mint(sender, netAmount);

        emit Deposit(sender, msg.value, netAmount);
    }

    /**
     * @notice Fallback function to handle direct COTI transfers as deposits.
     * @dev Mints private tokens at current oracle price without timestamp validation.
     *      For fee-protected deposits, use deposit(cotiOracleTimestamp, tokenOracleTimestamp) instead.
     */
    receive() external payable nonReentrant whenNotPaused {
        _directDeposit(msg.sender);
    }

    /**
     * @notice Get the native COTI balance held by the bridge
     * @return The contract's balance in native units (wei-equivalent)
     */
    function getBridgeBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Withdraw accumulated fees to feeRecipient (Native implementation)
     * @param amount Amount of fees to withdraw
     * @dev Only the owner can call this function
     */
    function withdrawFees(
        uint256 amount
    ) external override onlyOwner nonReentrant {
        if (feeRecipient == address(0)) revert FeeRecipientNotSet();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedCotiFees) revert InsufficientAccumulatedFees();
        if (amount > address(this).balance) revert InsufficientEthBalance();

        accumulatedCotiFees -= amount;

        // Transfer native COTI tokens to feeRecipient
        (bool success, ) = feeRecipient.call{value: amount}("");
        if (!success) revert EthTransferFailed();

        emit FeesWithdrawn(feeRecipient, amount);
    }

    /**
     * @dev Rescue native COTI coins mistakenly sent to the contract.
     *      Only excess over the accumulated fee reserve can be rescued.
     *      Sends to the predefined rescueRecipient address.
     * @param amount Amount of coins to rescue
     * @notice Only the owner can call this function
     */
    function rescueNative(uint256 amount) external onlyOwner nonReentrant {
        if (amount == 0) revert AmountZero();
        if (amount > address(this).balance) revert InsufficientEthBalance();
        if (address(this).balance < accumulatedFees) revert InsufficientEthBalance();
        if (amount > address(this).balance - accumulatedFees) revert ExceedsRescueableAmount();

        (bool success, ) = rescueRecipient.call{value: amount}("");
        if (!success) revert EthTransferFailed();

        emit NativeRescued(rescueRecipient, amount);
    }

    /**
     * @notice Native bridge does not use nativeCotiFee; always reverts.
     */
    function setNativeCotiFee(uint256) external pure override {
        revert NativeCotiFeeNotApplicable();
    }
}
