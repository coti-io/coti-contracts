// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../token/PrivateERC20/IPrivateERC20.sol";
import "../utils/mpc/MpcCore.sol";

/**
 * @dev Abstract base contract for ERC20 Token Privacy Bridges
 * @dev Handles the logic for bridging ERC20 tokens to their private counterparts.
 * @dev The public ERC20 token must be standard (no fee-on-transfer, no rebasing); same decimals as private token.
 */
contract PrivacyBridgeERC20 is PrivacyBridge {
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

    /**
     * @notice Initialize the PrivacyBridgeERC20 contract
     * @param _token Address of the public ERC20 token
     * @param _privateToken Address of the private token
     */
    constructor(address _token, address _privateToken) PrivacyBridge() {
        if (_token == address(0)) revert InvalidTokenAddress();
        if (_privateToken == address(0)) revert InvalidPrivateTokenAddress();

        token = IERC20(_token);
        privateToken = IPrivateERC20(_privateToken);
    }

    /**
     * @notice Deposit public ERC20 tokens to receive equivalent private tokens
     * @param amount Amount of public ERC20 tokens to deposit
     * @dev Native COTI fee: send msg.value >= nativeCotiFee; excess is refunded to caller.
     */
    function deposit(
        uint256 amount
    ) external payable nonReentrant whenNotPaused {
        _deposit(
            amount,
            false,
            itUint256(ctUint256(ctUint128.wrap(0), ctUint128.wrap(0)), "")
        );
    }

    /**
     * @notice Deposit public ERC20 tokens with an encrypted amount for the private minting event
     * @param amount Public amount of tokens to lock
     * @param encryptedAmount Encrypted amount to mint
     * @dev Native COTI fee: send msg.value >= nativeCotiFee; excess is refunded to caller.
     */
    function deposit(
        uint256 amount,
        itUint256 calldata encryptedAmount
    ) external payable nonReentrant whenNotPaused {
        _deposit(amount, true, encryptedAmount);
    }

    function _deposit(
        uint256 amount,
        bool isEncrypted,
        itUint256 memory encryptedAmount
    ) internal {
        if (!isDepositEnabled) revert DepositDisabled();
        if (amount == 0) revert AmountZero();
        if (msg.value < nativeCotiFee) revert InsufficientCotiFee();

        _checkDepositLimits(amount);

        // Handle native COTI fee (excess refunded to sender)
        accumulatedCotiFees += nativeCotiFee;

        token.safeTransferFrom(msg.sender, address(this), amount);

        // Calculate and deduct deposit fee (in tokens)
        uint256 feeAmount = _calculateFeeAmount(amount, depositFeeBasisPoints);
        uint256 amountAfterFee = amount - feeAmount;
        accumulatedFees += feeAmount;

        if (isEncrypted) {
            // Verify parity between public amount and encrypted amount
            gtUint256 gtAmount = MpcCore.validateCiphertext(encryptedAmount);
            gtBool amountMatch = MpcCore.eq(
                gtAmount,
                MpcCore.setPublic256(amountAfterFee)
            );
            require(MpcCore.decrypt(amountMatch), "Encrypted amount mismatch");

            gtBool mintOk = privateToken.mint(msg.sender, encryptedAmount);
            require(MpcCore.decrypt(mintOk), "Mint failed");
        } else {
            privateToken.mint(msg.sender, amountAfterFee);
        }

        // Emit gross deposit amount and net private tokens minted
        emit Deposit(msg.sender, amount, amountAfterFee);

        // Refund excess native COTI fee
        if (msg.value > nativeCotiFee) {
            uint256 excess = msg.value - nativeCotiFee;
            (bool ok, ) = msg.sender.call{value: excess}("");
            require(ok, "Refund failed");
        }
    }

    /**
     * @notice Withdraw public ERC20 tokens by burning private tokens
     * @param amount Amount of private tokens to burn
     * @dev Requires prior approval on the private token. Native COTI fee: send msg.value >= nativeCotiFee; excess is refunded.
     */
    function withdraw(
        uint256 amount
    ) external payable nonReentrant whenNotPaused {
        _withdraw(
            amount,
            false,
            itUint256(ctUint256(ctUint128.wrap(0), ctUint128.wrap(0)), "")
        );
    }

    /**
     * @notice Withdraw public ERC20 tokens by burning private tokens with an encrypted amount
     * @param amount Public amount to release
     * @param encryptedAmount Encrypted amount to burn
     * @dev Native COTI fee: send msg.value >= nativeCotiFee; excess is refunded to caller.
     */
    function withdraw(
        uint256 amount,
        itUint256 calldata encryptedAmount
    ) external payable nonReentrant whenNotPaused {
        _withdraw(amount, true, encryptedAmount);
    }

    function _withdraw(
        uint256 amount,
        bool isEncrypted,
        itUint256 memory encryptedAmount
    ) internal {
        if (amount == 0) revert AmountZero();
        if (msg.value < nativeCotiFee) revert InsufficientCotiFee();
        _checkWithdrawLimits(amount);

        // Handle native COTI fee (excess refunded to sender)
        accumulatedCotiFees += nativeCotiFee;

        // Calculate fee on the public side
        uint256 feeAmount = _calculateFeeAmount(amount, withdrawFeeBasisPoints);
        uint256 amountAfterFee = amount - feeAmount;
        accumulatedFees += feeAmount;

        uint256 bridgeBalance = token.balanceOf(address(this));
        if (bridgeBalance < amountAfterFee)
            revert InsufficientBridgeLiquidity();

        if (isEncrypted) {
            // Verify parity
            gtUint256 gtAmount = MpcCore.validateCiphertext(encryptedAmount);
            gtBool amountMatch = MpcCore.eq(
                gtAmount,
                MpcCore.setPublic256(amount)
            );
            require(MpcCore.decrypt(amountMatch), "Encrypted amount mismatch");

            // Transfer and burn (encrypted input)
            privateToken.transferFrom(msg.sender, address(this), encryptedAmount);
            gtBool burnOk = privateToken.burn(encryptedAmount);
            require(MpcCore.decrypt(burnOk), "Burn failed");
        } else {
            // Standard withdrawal (public amount)
            privateToken.transferFrom(msg.sender, address(this), amount);
            privateToken.burn(amount);
        }

        // Transfer public tokens
        token.safeTransfer(msg.sender, amountAfterFee);

        emit Withdraw(msg.sender, amount, amountAfterFee);

        // Refund excess native COTI fee
        if (msg.value > nativeCotiFee) {
            uint256 excess = msg.value - nativeCotiFee;
            (bool ok, ) = msg.sender.call{value: excess}("");
            require(ok, "Refund failed");
        }
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
    ) external override onlyOwner {
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
    ) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (_token == address(token) || _token == address(privateToken)) revert CannotRescueBridgeToken();

        IERC20(_token).safeTransfer(to, amount);
    }
}
