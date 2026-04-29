// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../token/PrivateERC20/IPrivateERC20.sol";

/// @dev Minimal interface to read decimals from tokens without modifying IPrivateERC20
interface IHasDecimals {
    function decimals() external view returns (uint8);
}

/**
 * @dev Abstract base contract for ERC20 Token Privacy Bridges
 * @dev Handles the logic for bridging ERC20 tokens to their private counterparts.
 * @dev The public ERC20 token must be standard (no fee-on-transfer, no rebasing); same decimals as private token.
 */
abstract contract PrivacyBridgeERC20 is PrivacyBridge {
    using SafeERC20 for IERC20;

    /// @notice The public ERC20 token being bridged (e.g., USDC, WETH)
    IERC20 public token;

    /// @notice Private token contract being minted/burned
    IPrivateERC20 public privateToken;

    /// @notice Band oracle symbol for the bridged token (e.g., "ETH", "WBTC", "ADA", "USDC", "USDT")
    string public tokenSymbol;

    error InvalidTokenAddress();
    error InvalidPrivateTokenAddress();
    error CannotRescueBridgeToken();
    error InvalidScalingFactor();
    error AmountTooLarge();
    error AmountTooSmall();
    error InsufficientBridgeLiquidity();
    error TokenTransferFailed();
    error InvalidTokenSender();
    error NativeFeeRequiredForTransferAndCallWithdraw();
    error DecimalsMismatch();

    event ERC20Rescued(address indexed token, address indexed to, uint256 amount);

    /**
     * @notice Compute the dynamic fee in COTI for an ERC20 bridge operation
     * @param tokenAmount The amount of ERC20 tokens being bridged
     * @param fixedFee The minimum fee floor in COTI
     * @param percentageBps The percentage in basis points (relative to FEE_DIVISOR)
     * @param maxFee The maximum fee cap in COTI
     * @return The computed fee in native COTI (18 decimals)
     */
    function _computeErc20Fee(
        uint256 tokenAmount,
        uint256 fixedFee,
        uint256 percentageBps,
        uint256 maxFee
    ) internal view returns (uint256) {
        ICotiPriceConsumer oracle = ICotiPriceConsumer(priceOracle);
        uint256 tokenUsdRate = oracle.getPrice(tokenSymbol);
        uint256 cotiUsdRate = oracle.getPrice("COTI");
        uint8 tokenDecimals = IHasDecimals(address(token)).decimals();
        uint256 txValueUsd = (tokenAmount * tokenUsdRate) / (10 ** tokenDecimals);
        uint256 percentageFeeUsd = (txValueUsd * percentageBps) / FEE_DIVISOR;
        uint256 percentageFeeCoti = (percentageFeeUsd * 1e18) / cotiUsdRate;
        return _calculateDynamicFee(percentageFeeCoti, fixedFee, maxFee);
    }

    /**
     * @notice Estimate the deposit fee in COTI for a given token amount
     * @param tokenAmount The amount of ERC20 tokens to deposit
     * @return fee                The estimated fee in native COTI (18 decimals)
     * @return cotiLastUpdated    COTI oracle data last update timestamp
     * @return tokenLastUpdated   Token oracle data last update timestamp
     * @return blockTimestamp     Current block.timestamp
     */
    function estimateDepositFee(uint256 tokenAmount) external view returns (uint256 fee, uint256 cotiLastUpdated, uint256 tokenLastUpdated, uint256 blockTimestamp) {
        fee = _computeErc20Fee(tokenAmount, depositFixedFee, depositPercentageBps, depositMaxFee);
        (,cotiLastUpdated, blockTimestamp) = ICotiPriceConsumer(priceOracle).getPriceWithMeta("COTI");
        (,tokenLastUpdated,) = ICotiPriceConsumer(priceOracle).getPriceWithMeta(tokenSymbol);
    }

    /**
     * @notice Estimate the withdrawal fee in COTI for a given token amount
     * @param tokenAmount The amount of ERC20 tokens to withdraw
     * @return fee                The estimated fee in native COTI (18 decimals)
     * @return cotiLastUpdated    COTI oracle data last update timestamp
     * @return tokenLastUpdated   Token oracle data last update timestamp
     * @return blockTimestamp     Current block.timestamp
     */
    function estimateWithdrawFee(uint256 tokenAmount) external view returns (uint256 fee, uint256 cotiLastUpdated, uint256 tokenLastUpdated, uint256 blockTimestamp) {
        fee = _computeErc20Fee(tokenAmount, withdrawFixedFee, withdrawPercentageBps, withdrawMaxFee);
        (,cotiLastUpdated, blockTimestamp) = ICotiPriceConsumer(priceOracle).getPriceWithMeta("COTI");
        (,tokenLastUpdated,) = ICotiPriceConsumer(priceOracle).getPriceWithMeta(tokenSymbol);
    }

    /**
     * @notice Collect the dynamic native COTI fee from msg.value and refund any excess
     * @param fee The computed fee in native COTI
     * @dev Reverts with {InsufficientCotiFee} if msg.value < fee.
     *      Excess above fee is refunded best-effort; if the refund fails, the excess is
     *      added to accumulatedCotiFees so it remains recoverable via {withdrawCotiFees}.
     */
    function _collectDynamicNativeFee(uint256 fee) internal {
        if (msg.value < fee) revert InsufficientCotiFee();
        accumulatedCotiFees += fee;
        if (msg.value > fee) {
            uint256 excess = msg.value - fee;
            (bool ok, ) = msg.sender.call{value: excess}("");
            if (!ok) {
                accumulatedCotiFees += excess;
            }
        }
    }

    /**
     * @notice Initialize the PrivacyBridgeERC20 contract
     * @param _token Address of the public ERC20 token (must be standard: no fee-on-transfer, no rebasing; same decimals as private token)
     * @param _privateToken Address of the private token
     * @param _tokenSymbol Band oracle symbol for the bridged token (e.g., "ETH", "WBTC") — required for Band Protocol compatibility check
     */
    constructor(address _token, address _privateToken, string memory _tokenSymbol, address _feeRecipient, address _rescueRecipient) PrivacyBridge(_feeRecipient, _rescueRecipient) {
        if (_token == address(0)) revert InvalidTokenAddress();
        if (_privateToken == address(0)) revert InvalidPrivateTokenAddress();

        // Verify decimal parity to prevent silent exchange rate corruption
        if (IHasDecimals(_token).decimals() != IHasDecimals(_privateToken).decimals())
            revert DecimalsMismatch();

        token = IERC20(_token);
        privateToken = IPrivateERC20(_privateToken);
        tokenSymbol = _tokenSymbol;
    }

    /**
     * @notice Deposit public ERC20 tokens to receive equivalent private tokens
     * @param amount Amount of public ERC20 tokens to deposit
     * @param cotiOracleTimestamp The COTI oracle lastUpdated timestamp from estimateDepositFee
     * @param tokenOracleTimestamp The token oracle lastUpdated timestamp from estimateDepositFee
     * @dev Native COTI fee: send msg.value >= computed fee. Excess is refunded best-effort.
     */
    function deposit(
        uint256 amount,
        uint256 cotiOracleTimestamp,
        uint256 tokenOracleTimestamp
    ) external payable nonReentrant whenNotPaused {
        _deposit(amount, cotiOracleTimestamp, tokenOracleTimestamp);
    }

    function _deposit(uint256 amount, uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (amount == 0) revert AmountZero();
        if (IHasDecimals(address(token)).decimals() != IHasDecimals(address(privateToken)).decimals())
            revert DecimalsMismatch();
        _checkDepositLimits(amount);
        _validateOracleTimestamps(cotiOracleTimestamp, tokenOracleTimestamp, tokenSymbol);

        // Step 1: compute dynamic fee in COTI
        uint256 fee = _computeErc20Fee(amount, depositFixedFee, depositPercentageBps, depositMaxFee);

        // Step 2: collect fee from msg.value (refunds excess to sender)
        _collectDynamicNativeFee(fee);

        // Step 3: pull full token amount from user
        uint256 balBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - balBefore;

        // Step 4: mint full private token amount
        privateToken.mint(msg.sender, received);

        emit Deposit(msg.sender, amount, received);
    }

    /**
     * @notice Withdraw public ERC20 tokens by burning private tokens
     * @param amount Amount of private tokens to burn
     * @param cotiOracleTimestamp The COTI oracle lastUpdated timestamp from estimateWithdrawFee
     * @param tokenOracleTimestamp The token oracle lastUpdated timestamp from estimateWithdrawFee
     * @dev Requires prior approval on the private token. Native COTI fee: send msg.value >= computed fee; excess refunded best-effort.
     */
    function withdraw(
        uint256 amount,
        uint256 cotiOracleTimestamp,
        uint256 tokenOracleTimestamp
    ) external payable nonReentrant whenNotPaused {
        _withdraw(amount, cotiOracleTimestamp, tokenOracleTimestamp);
    }

    function _withdraw(uint256 amount, uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) internal {
        if (amount == 0) revert AmountZero();
        if (IHasDecimals(address(token)).decimals() != IHasDecimals(address(privateToken)).decimals())
            revert DecimalsMismatch();
        _checkWithdrawLimits(amount);
        _validateOracleTimestamps(cotiOracleTimestamp, tokenOracleTimestamp, tokenSymbol);

        // Step 1: compute dynamic fee in COTI
        uint256 fee = _computeErc20Fee(amount, withdrawFixedFee, withdrawPercentageBps, withdrawMaxFee);

        // Step 2: collect fee from msg.value (refunds excess to sender)
        _collectDynamicNativeFee(fee);

        // Step 3: verify bridge has enough liquidity
        uint256 bridgeBalance = token.balanceOf(address(this));
        if (bridgeBalance < amount)
            revert InsufficientBridgeLiquidity();

        // Step 4: pull and burn full private token amount
        privateToken.transferFrom(msg.sender, address(this), amount);
        privateToken.burn(amount);

        // Step 5: release full public token amount to user
        token.safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, amount, amount);
    }


    /**
     * @dev Rescue ERC20 tokens sent to the contract (excluding private tokens).
     *      Sends to the predefined rescueRecipient address.
     */
    function rescueERC20(
        address _token,
        uint256 amount
    ) external onlyOwner nonReentrant {
        if (amount == 0) revert AmountZero();
        
        if ( _token == address(privateToken))
            revert CannotRescueBridgeToken();

        IERC20(_token).safeTransfer(rescueRecipient, amount);

        emit ERC20Rescued(_token, rescueRecipient, amount);
    }
}
