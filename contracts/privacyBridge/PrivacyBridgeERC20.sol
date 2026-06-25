// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
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
 * @dev The public ERC20 must match standard transfer semantics: {safeTransferFrom} of `amount` must
 *      increase the bridge balance by exactly `amount` ({UnexpectedTransferBalance} otherwise). This
 *      rejects common fee-on-transfer / deflationary patterns. Rebasing, blacklist hooks, and other
 *      non-standard behavior remain unsupported—deployment must still use a suitable asset.
 * @dev **Private token:** The constructor stores `_privateToken` as {IPrivateERC20} from
 *      `contracts/token/PrivateERC20/IPrivateERC20.sol` (same `pragma` family as this contract). Integrators should
 *      bind ABIs/codegen to that canonical interface in this repo; alternate compiler pipelines (e.g. via-IR-only)
 *      should still target the same ABI, not ad-hoc casts to incompatible shapes.
 */
abstract contract PrivacyBridgeERC20 is PrivacyBridge {
    using SafeERC20 for IERC20;

    /// @notice The public ERC20 token being bridged (e.g., USDC, WETH)
    IERC20 public token;

    /// @notice Private token contract being minted/burned
    IPrivateERC20 public privateToken;

    /// @notice Band oracle symbol for the bridged token (e.g., "ETH", "WBTC", "ADA", "USDC", "USDT")
    string public tokenSymbol;

    /// @notice Cached ERC20 decimals (matches private token; set in constructor).
    uint8 internal immutable bridgedTokenDecimals;

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
    /// @notice Pulled balance increase did not match `amount` (e.g. fee-on-transfer or deflationary token).
    error UnexpectedTransferBalance(uint256 expected, uint256 received);
    event ERC20Rescued(address indexed token, address indexed to, uint256 amount);

    function _computeErc20Fee(
        uint256 tokenAmount,
        uint256 fixedFee,
        uint256 percentageBps,
        uint256 maxFee
    ) internal view returns (uint256) {
        (uint256 fee,,,) = _computeErc20FeeAndMeta(tokenAmount, fixedFee, percentageBps, maxFee, tokenSymbol, bridgedTokenDecimals);
        return fee;
    }

    /**
     * @notice Simulate fee calculation for any token symbol and decimals.
     * @dev Public view — allows frontends/operators to preview fees with arbitrary parameters.
     *      Reads live oracle prices but accepts custom fee params and token config.
     * @param tokenAmount The token amount to simulate fee for (raw units; very large values can revert in fee math)
     * @param fixedFee The minimum fee floor in COTI wei
     * @param percentageBps The percentage in basis points (relative to {FEE_DIVISOR})
     * @param maxFee The maximum fee cap in COTI wei
     * @param _tokenSymbol The Band oracle symbol (e.g. "ETH", "WBTC", "ADA")
     * @param _tokenDecimals The decimal precision of the token (e.g. 18, 8, 6)
     * @return The computed fee in native COTI (18 decimals)
     */
    function computeErc20Fee(
        uint256 tokenAmount,
        uint256 fixedFee,
        uint256 percentageBps,
        uint256 maxFee,
        string calldata _tokenSymbol,
        uint8 _tokenDecimals
    ) external view returns (uint256) {
        (uint256 fee,,,) = _computeErc20FeeAndMeta(tokenAmount, fixedFee, percentageBps, maxFee, _tokenSymbol, _tokenDecimals);
        return fee;
    }

    /**
     * @dev ERC20 fee math + two {getPriceWithMeta} reads (token then COTI). Used by {_computeErc20Fee}
     *      and {estimateDepositFee}/{estimateWithdrawFee}. Each {Math.mulDiv} step truncates toward zero
     *      (see {PrivacyBridge.FEE_DIVISOR} NatSpec). Extreme `tokenAmount`×`tokenUsdRate` values can make
     *      {Math.mulDiv} revert—keep amounts within configured max deposit/withdraw limits.
     */
    function _computeErc20FeeAndMeta(
        uint256 tokenAmount,
        uint256 fixedFee,
        uint256 percentageBps,
        uint256 maxFee,
        string memory oracleTokenSymbol,
        uint8 tokenDecimals
    )
        internal
        view
        returns (uint256 fee, uint256 cotiLastUpdated, uint256 tokenLastUpdated, uint256 blockTimestamp)
    {
        _requirePriceOracle();
        ICotiPriceConsumer oracle = ICotiPriceConsumer(priceOracle);
        (uint256 tokenUsdRate, uint256 tokenLU,) = oracle.getPriceWithMeta(oracleTokenSymbol);
        (uint256 cotiUsdRate, uint256 cotiLU, uint256 cotiBts) = oracle.getPriceWithMeta("COTI");
        _requirePositiveOracleRate(tokenUsdRate);
        _requirePositiveOracleRate(cotiUsdRate);
        _requireOracleFreshness(tokenLU);
        _requireOracleFreshness(cotiLU);
        uint256 txValueUsd = Math.mulDiv(tokenAmount, tokenUsdRate, 10 ** uint256(tokenDecimals));
        uint256 percentageFeeUsd = Math.mulDiv(txValueUsd, percentageBps, FEE_DIVISOR);
        uint256 percentageFeeCoti = Math.mulDiv(percentageFeeUsd, 1e18, cotiUsdRate);
        fee = _calculateDynamicFee(percentageFeeCoti, fixedFee, maxFee);
        cotiLastUpdated = cotiLU;
        tokenLastUpdated = tokenLU;
        blockTimestamp = cotiBts;
    }

    /**
     * @notice Estimate the deposit fee in COTI for a given token amount
     * @param tokenAmount The amount of ERC20 tokens to deposit (raw token units; very large values can revert in fee math)
     * @return fee                The estimated fee in native COTI (18 decimals)
     * @return cotiLastUpdated    COTI oracle data last update timestamp
     * @return tokenLastUpdated   Token oracle data last update timestamp
     * @return blockTimestamp     Third field from the COTI oracle row (same as pre-refactor behavior)
     * @dev Pass the returned `cotiLastUpdated` and `tokenLastUpdated` verbatim into {deposit}/{withdraw} together
     *      with the same `tokenAmount` path; see {PrivacyBridge._validateOracleTimestamps} for strict equality UX.
     */
    function estimateDepositFee(uint256 tokenAmount) external view returns (uint256 fee, uint256 cotiLastUpdated, uint256 tokenLastUpdated, uint256 blockTimestamp) {
        (fee, cotiLastUpdated, tokenLastUpdated, blockTimestamp) = _computeErc20FeeAndMeta(
            tokenAmount,
            depositFixedFee,
            depositPercentageBps,
            depositMaxFee,
            tokenSymbol,
            bridgedTokenDecimals
        );
    }

    /**
     * @notice Estimate the withdrawal fee in COTI for a given token amount
     * @param tokenAmount The amount of ERC20 tokens to withdraw (raw units; very large values can revert in fee math)
     * @return fee                The estimated fee in native COTI (18 decimals)
     * @return cotiLastUpdated    COTI oracle data last update timestamp
     * @return tokenLastUpdated   Token oracle data last update timestamp
     * @return blockTimestamp     Third field from the COTI oracle row (same as pre-refactor behavior)
     * @dev Same timestamp handoff as {estimateDepositFee}: use return values unchanged on the subsequent {withdraw}.
     */
    function estimateWithdrawFee(uint256 tokenAmount) external view returns (uint256 fee, uint256 cotiLastUpdated, uint256 tokenLastUpdated, uint256 blockTimestamp) {
        (fee, cotiLastUpdated, tokenLastUpdated, blockTimestamp) = _computeErc20FeeAndMeta(
            tokenAmount,
            withdrawFixedFee,
            withdrawPercentageBps,
            withdrawMaxFee,
            tokenSymbol,
            bridgedTokenDecimals
        );
    }

    /**
     * @notice Collect the dynamic native COTI fee from msg.value and refund any excess
     * @param fee The computed fee in native COTI
     * @dev Reverts with {InsufficientCotiFee} if msg.value < fee.
     *      Excess above `fee` is sent back to `msg.sender` with a plain `call` (no receive hook guarantee).
     *      Smart wallets or contracts that revert or return false on unsolicited ETH will not receive the push;
     *      the excess is then credited to {refundableNativeExcess}[msg.sender] and emits `NativeRefundExcessPushFailed`
     *      (see {PrivacyBridge._creditRefundableNativeExcess} and {PrivacyBridge.claimRefundableNativeExcess}). Excess
     *      is never added to {accumulatedCotiFees}.
     */
    function _collectDynamicNativeFee(uint256 fee) internal {
        if (msg.value < fee) revert InsufficientCotiFee();
        // Verify contract balance covers the fee before accounting
        if (address(this).balance < fee) revert InsufficientEthBalance();
        accumulatedCotiFees += fee;
        if (msg.value > fee) {
            uint256 excess = msg.value - fee;
            (bool ok, ) = msg.sender.call{value: excess}("");
            if (!ok) {
                _creditRefundableNativeExcess(msg.sender, excess);
            }
        }
    }

    /**
     * @notice Initialize the PrivacyBridgeERC20 contract
     * @param _token Address of the public ERC20 token (must be standard: no fee-on-transfer, no rebasing; same decimals as private token)
     * @param _privateToken Address of the private token
     * @param _tokenSymbol Band oracle symbol for the bridged token (e.g., "ETH", "WBTC") — required for Band Protocol compatibility check
     * @param _priceOracle Non-zero price oracle (same requirement as {PrivacyBridge}'s constructor)
     * @dev **Decimals:** reads `decimals()` on both tokens at deploy; reverts {DecimalsMismatch} if they differ—so
     *      mis-paired tokens fail **at construction**, not on first user tx. {bridgedTokenDecimals} is then cached
     *      immutably for fee math. After deploy, a mismatch cannot appear unless token contracts were misconfigured
     *      at deploy time or an upgradeable token later changes `decimals()` (exceptional external risk; not re-checked on-chain).
     */
    constructor(
        address _token,
        address _privateToken,
        string memory _tokenSymbol,
        address _feeRecipient,
        address _rescueRecipient,
        address _priceOracle
    ) PrivacyBridge(_feeRecipient, _rescueRecipient, _priceOracle) {
        if (_token == address(0)) revert InvalidTokenAddress();
        if (_privateToken == address(0)) revert InvalidPrivateTokenAddress();

        uint8 pubDecimals = IHasDecimals(_token).decimals();
        if (pubDecimals != IHasDecimals(_privateToken).decimals()) revert DecimalsMismatch();
        bridgedTokenDecimals = pubDecimals;

        token = IERC20(_token);
        privateToken = IPrivateERC20(_privateToken);
        tokenSymbol = _tokenSymbol;
    }

    /**
     * @notice Deposit public ERC20 tokens to receive equivalent private tokens
     * @param amount Amount of public ERC20 tokens to deposit
     * @param cotiOracleTimestamp COTI `lastUpdated` from the latest `estimateDepositFee` (must still equal on-chain at execution).
     * @param tokenOracleTimestamp Token `lastUpdated` from the same estimate (must still equal on-chain at execution).
     * @dev Native COTI fee: send msg.value >= computed fee. Excess native is push-refunded then pull-credited on failure
     *      ({_collectDynamicNativeFee}). If the Band row advances before inclusion, tx reverts with {OracleTimestampMismatch}—re-estimate and resubmit (see {_validateOracleTimestamps}).
     */
    function deposit(
        uint256 amount,
        uint256 cotiOracleTimestamp,
        uint256 tokenOracleTimestamp
    ) external payable nonReentrant whenNotPaused notBlacklisted {
        _deposit(amount, cotiOracleTimestamp, tokenOracleTimestamp);
    }

    /**
     * @dev Pulls public tokens before collecting the native COTI fee so a non-standard transfer
     *      (e.g. fee-on-transfer) reverts before debiting `msg.value`, and insufficient `msg.value`
     *      still reverts the whole tx including the token transfer.
     */
    function _deposit(uint256 amount, uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (amount == 0) revert AmountZero();
        _checkDepositLimits(amount);
        _validateOracleTimestamps(cotiOracleTimestamp, tokenOracleTimestamp, tokenSymbol);

        uint256 fee = _computeErc20Fee(amount, depositFixedFee, depositPercentageBps, depositMaxFee);

        uint256 balBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - balBefore;
        if (received != amount) revert UnexpectedTransferBalance(amount, received);

        _collectDynamicNativeFee(fee);

        totalUserLiability += received;
        privateToken.mint(msg.sender, received);

        emit Deposit(msg.sender, amount, received);
    }

    /**
     * @notice Withdraw public ERC20 tokens by burning private tokens
     * @param amount Amount of private tokens to burn
     * @param cotiOracleTimestamp COTI `lastUpdated` from the latest `estimateWithdrawFee` (must still equal on-chain at execution).
     * @param tokenOracleTimestamp Token `lastUpdated` from the same estimate (must still equal on-chain at execution).
     * @dev Requires prior approval on the private token. Send `msg.value >= fee`; native fee is
     *      collected only after the public token transfer succeeds (mirrors {deposit} ordering). Oracle
     *      timestamp rules match {deposit} / {_validateOracleTimestamps}. Native excess handling matches {deposit}.
     */
    function withdraw(
        uint256 amount,
        uint256 cotiOracleTimestamp,
        uint256 tokenOracleTimestamp
    ) external payable nonReentrant whenNotPaused notBlacklisted {
        _withdraw(amount, cotiOracleTimestamp, tokenOracleTimestamp);
    }

    /**
     * @dev Mirrors {_deposit}: native fee is collected only after the ERC20 leg succeeds by standard
     *      semantics (here: burn + public transfer with full `userGain`). Insufficient `msg.value`
     *      then reverts the entire withdrawal including private burn and public transfer.
     */
    function _withdraw(uint256 amount, uint256 cotiOracleTimestamp, uint256 tokenOracleTimestamp) internal {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);
        _validateOracleTimestamps(cotiOracleTimestamp, tokenOracleTimestamp, tokenSymbol);

        uint256 fee = _computeErc20Fee(amount, withdrawFixedFee, withdrawPercentageBps, withdrawMaxFee);

        uint256 bridgeBalance = token.balanceOf(address(this));
        if (bridgeBalance < amount) revert InsufficientBridgeLiquidity();

        totalUserLiability -= amount;
        privateToken.transferFrom(msg.sender, address(this), amount);
        privateToken.burn(amount);

        uint256 userBalBefore = token.balanceOf(msg.sender);
        token.safeTransfer(msg.sender, amount);
        uint256 userGain = token.balanceOf(msg.sender) - userBalBefore;
        if (userGain != amount) revert UnexpectedTransferBalance(amount, userGain);

        _collectDynamicNativeFee(fee);

        emit Withdraw(msg.sender, amount, amount);
    }

    /**
     * @notice Move ERC20 from this contract to {rescueRecipient} while the bridge is paused.
     * @dev Requires {whenPaused} for every `_token` so rescue never runs concurrently with user flows.
     *      For the live public {token}, `amount` can be the full balance—including all TVL backing withdrawals.
     *      Same governance risk as {PrivacyBridgeCotiNative.rescueNative}: owner + pause can send user funds
     *      to {rescueRecipient}; see {PrivacyBridge} contract @dev (3). Private token cannot be rescued here
     *      ({CannotRescueBridgeToken}). {totalUserLiability} is intentionally **not** updated here: rescue only
     *      moves collateral to {rescueRecipient}; it does not burn private tokens or unwind user obligations on
     *      this ledger, so outstanding claims can exceed {token} held by this contract until a separate migration
     *      path makes users whole.
     */
    function rescueERC20(
        address _token,
        uint256 amount
    ) external onlyOwner nonReentrant whenPaused {
        if (amount == 0) revert AmountZero();

        if (_token == address(privateToken)) revert CannotRescueBridgeToken();

        IERC20(_token).safeTransfer(rescueRecipient, amount);

        emit ERC20Rescued(_token, rescueRecipient, amount);
    }
}
