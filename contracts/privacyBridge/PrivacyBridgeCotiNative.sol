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
        uint256 cotiUsdRate = ICotiPriceConsumer(priceOracle).getCotiPrice();
        uint256 txValueUsd = (cotiAmount * cotiUsdRate) / 1e18;
        uint256 percentageFeeUsd = (txValueUsd * percentageBps) / FEE_DIVISOR;
        uint256 percentageFeeCoti = (percentageFeeUsd * 1e18) / cotiUsdRate;
        return _calculateDynamicFee(percentageFeeCoti, fixedFee, maxFee);
    }

    /**
     * @notice Estimate the deposit fee in COTI for a given COTI amount
     * @param cotiAmount The amount of native COTI to deposit
     * @return fee           The estimated fee in COTI wei
     * @return lastUpdated   Oracle data last update timestamp
     * @return threshold     Staleness cutoff timestamp (0 if disabled)
     * @return blockTimestamp Current block.timestamp
     */
    function estimateDepositFee(uint256 cotiAmount) external view override returns (uint256 fee, uint256 lastUpdated, uint256 threshold, uint256 blockTimestamp) {
        fee = _computeCotiFee(cotiAmount, depositFixedFee, depositPercentageBps, depositMaxFee);
        (,lastUpdated, threshold, blockTimestamp) = ICotiPriceConsumer(priceOracle).getPriceWithMeta("COTI");
    }

    /**
     * @notice Estimate the withdrawal fee in COTI for a given COTI amount
     * @param cotiAmount The amount of native COTI to withdraw
     * @return fee           The estimated fee in COTI wei
     * @return lastUpdated   Oracle data last update timestamp
     * @return threshold     Staleness cutoff timestamp (0 if disabled)
     * @return blockTimestamp Current block.timestamp
     */
    function estimateWithdrawFee(uint256 cotiAmount) external view override returns (uint256 fee, uint256 lastUpdated, uint256 threshold, uint256 blockTimestamp) {
        fee = _computeCotiFee(cotiAmount, withdrawFixedFee, withdrawPercentageBps, withdrawMaxFee);
        (,lastUpdated, threshold, blockTimestamp) = ICotiPriceConsumer(priceOracle).getPriceWithMeta("COTI");
    }

    /**
     * @notice Internal function to handle deposits
     * @param sender Address of the depositor
     */
    function _deposit(address sender, uint256 oracleTimestamp) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (msg.value == 0) revert AmountZero();

        _checkDepositLimits(msg.value);
        _validateOracleTimestamp(oracleTimestamp);

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
     * @param oracleTimestamp The oracle lastUpdated timestamp from estimateDepositFee (ensures fee hasn't changed)
     * @dev User sends native COTI with the transaction
     */
    function deposit(uint256 oracleTimestamp) external payable nonReentrant whenNotPaused {
        _deposit(msg.sender, oracleTimestamp);
    }

    /**
     * @notice Withdraw native COTI by burning private COTI
     * @param amount Amount of private COTI to burn
     * @dev User must have approved the bridge to spend their private tokens.
     */
    /**
     * @notice Handle callback from PrivateCoti.transferAndCall
     * @dev Called when user transfers tokens to the bridge to withdraw.
     *      The `data` parameter must be abi-encoded uint256 oracleTimestamp.
     * @param from Address of the sender
     * @param amount Amount of tokens received
     * @param data ABI-encoded uint256 oracleTimestamp from estimateWithdrawFee
     */
    function onTokenReceived(
        address from,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant whenNotPaused returns (bool) {
        if (msg.sender != address(privateCoti)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();

        uint256 oracleTimestamp = abi.decode(data, (uint256));
        _validateOracleTimestamp(oracleTimestamp);

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
     * @param oracleTimestamp The oracle lastUpdated timestamp from estimateWithdrawFee (ensures fee hasn't changed)
     * @dev User must have approved the bridge to spend their private tokens.
     */
    function withdraw(uint256 amount, uint256 oracleTimestamp) external nonReentrant whenNotPaused {
        _withdraw(msg.sender, amount, oracleTimestamp);
    }

    function _withdraw(
        address to,
        uint256 amount,
        uint256 oracleTimestamp
    ) internal {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);
        _validateOracleTimestamp(oracleTimestamp);

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
     * @notice Fallback to accept native COTI sent directly (e.g. for liquidity top-up).
     * @dev Does NOT trigger a deposit. Use deposit(oracleTimestamp) instead.
     */
    receive() external payable {}

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
    ) external override onlyOwner nonReentrant {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > accumulatedCotiFees) revert InsufficientAccumulatedFees();
        if (amount > address(this).balance) revert InsufficientEthBalance();

        accumulatedCotiFees -= amount;

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
