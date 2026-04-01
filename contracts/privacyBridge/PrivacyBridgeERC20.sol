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
     * @notice Collects the flat native COTI per-operation fee from msg.value and refunds any excess to the sender.
     * @dev Reverts with {InsufficientCotiFee} if msg.value < nativeCotiFee.
     *      Excess above nativeCotiFee is refunded best-effort; if the refund fails (e.g. sender is a
     *      contract that cannot receive native tokens), the excess is added to accumulatedCotiFees so
     *      it remains recoverable via {withdrawCotiFees} rather than being permanently stranded.
     */
    function _collectNativeFee() internal {
        if (msg.value < nativeCotiFee) revert InsufficientCotiFee();
        accumulatedCotiFees += nativeCotiFee;
        if (msg.value > nativeCotiFee) {
            uint256 excess = msg.value - nativeCotiFee;
            (bool ok, ) = msg.sender.call{value: excess}("");
            if (!ok) {
                accumulatedCotiFees += excess; // unrefundable; recoverable via withdrawCotiFees
            }
        }
    }

    /**
     * @notice Initialize the PrivacyBridgeERC20 contract
     * @param _token Address of the public ERC20 token (must be standard: no fee-on-transfer, no rebasing; same decimals as private token)
     * @param _privateToken Address of the private token
     */
    constructor(address _token, address _privateToken) PrivacyBridge() {
        if (_token == address(0)) revert InvalidTokenAddress();
        if (_privateToken == address(0)) revert InvalidPrivateTokenAddress();

        // Verify decimal parity to prevent silent exchange rate corruption
        if (IHasDecimals(_token).decimals() != IHasDecimals(_privateToken).decimals())
            revert DecimalsMismatch();

        token = IERC20(_token);
        privateToken = IPrivateERC20(_privateToken);
    }

    /**
     * @notice Deposit public ERC20 tokens to receive equivalent private tokens
     * @param amount Amount of public ERC20 tokens to deposit
     * @dev Native COTI fee: send msg.value >= nativeCotiFee. Excess is refunded best-effort;
     *      if refund fails (e.g. sender cannot receive native token), excess remains in the contract and deposit still succeeds.
     *      Send exactly nativeCotiFee or ensure sender can receive native token to avoid leaving excess in the contract.
     */
    function deposit(
        uint256 amount
    ) external payable nonReentrant whenNotPaused {
        _deposit(amount);
    }

    function _deposit(uint256 amount) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (amount == 0) revert AmountZero();
        _checkDepositLimits(amount);

        // Step 1: collect flat native COTI fee (refunds excess to sender)
        _collectNativeFee();

        // Step 2: pull tokens and measure actual received amount (fee-on-transfer safe)
        uint256 balBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - balBefore;

        // Step 3: deduct bridged-asset deposit fee, get net amount to mint
        uint256 amountAfterFee = _collectTokenFee(received, depositFeeBasisPoints);

        // Step 4: mint private tokens
        privateToken.mint(msg.sender, amountAfterFee);

        emit Deposit(msg.sender, received, amountAfterFee);
    }

    /**
     * @notice Withdraw public ERC20 tokens by burning private tokens
     * @param amount Amount of private tokens to burn
     * @dev Requires prior approval on the private token. Native COTI fee: send msg.value >= nativeCotiFee; excess refunded best-effort (see deposit).
     */
    function withdraw(
        uint256 amount
    ) external payable nonReentrant whenNotPaused {
        _withdraw(amount);
    }

    function _withdraw(uint256 amount) internal {
        if (amount == 0) revert AmountZero();
        _checkWithdrawLimits(amount);

        // Step 1: collect flat native COTI fee (refunds excess to sender)
        _collectNativeFee();

        // Step 2: deduct bridged-asset withdrawal fee, get net amount to release
        uint256 amountAfterFee = _collectTokenFee(amount, withdrawFeeBasisPoints);

        // Step 3: verify bridge has enough liquidity (reserves fee balance)
        uint256 bridgeBalance = token.balanceOf(address(this));
        if (bridgeBalance < accumulatedFees + amountAfterFee)
            revert InsufficientBridgeLiquidity();

        // Step 4: pull and burn private tokens
        privateToken.transferFrom(msg.sender, address(this), amount);
        privateToken.burn(amount);

        // Step 5: release public tokens to user
        token.safeTransfer(msg.sender, amountAfterFee);

        emit Withdraw(msg.sender, amount, amountAfterFee);
    }

    /**
     * @notice Withdraw accumulated fees (ERC20 implementation)
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

        accumulatedFees -= amount;

        // Transfer public ERC20 tokens
        token.safeTransfer(to, amount);

        emit FeesWithdrawn(to, amount);
    }

    /**
     * @dev Rescue ERC20 tokens sent to the contract (excluding bridge and private tokens)
     */
    function rescueERC20(
        address _token,
        address to,
        uint256 amount
    ) external onlyOwner nonReentrant {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        
        if ( _token == address(privateToken))
            revert CannotRescueBridgeToken();

        IERC20(_token).safeTransfer(to, amount);

        emit ERC20Rescued(_token, to, amount);
    }
}
