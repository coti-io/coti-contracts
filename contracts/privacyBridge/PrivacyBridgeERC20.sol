// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PrivacyBridge.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../privateERC20/IPrivateERC20.sol";
import "../utils/mpc/MpcCore.sol";

/**
 * @dev Abstract base contract for ERC20 Token Privacy Bridges
 * @dev Handles the logic for bridging ERC20 tokens to their private counterparts.
 */
contract PrivacyBridgeERC20 is PrivacyBridge {
    /// @notice The public ERC20 token being bridged (e.g., USDC, WETH)
    IERC20 public token;

    /// @notice Private token contract being minted/burned
    IPrivateERC20 public privateToken;

    error InvalidTokenAddress();
    error InvalidPrivateTokenAddress();
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
        if (msg.value != nativeCotiFee) revert InsufficientCotiFee();

        _checkDepositLimits(amount);

        // Handle native COTI fee (exact fee enforced)
        accumulatedCotiFees += msg.value;

        bool success = token.transferFrom(msg.sender, address(this), amount);
        if (!success) revert TokenTransferFailed();

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

            privateToken.mint(msg.sender, encryptedAmount);
        } else {
            privateToken.mint(msg.sender, amountAfterFee);
        }

        // Emit gross deposit amount and net private tokens minted
        emit Deposit(msg.sender, amount, amountAfterFee);
    }

    /**
     * @notice Withdraw public ERC20 tokens by burning private tokens
     * @param amount Amount of private tokens to burn
     * @dev This function requires prior approval on the private token and a native COTI fee.
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
        if (msg.value != nativeCotiFee) revert InsufficientCotiFee();
        _checkWithdrawLimits(amount);

        // Handle native COTI fee
        accumulatedCotiFees += msg.value;

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

            // Transfer and burn
            privateToken.transferFrom(msg.sender, address(this), gtAmount);
            privateToken.burn(encryptedAmount);
        } else {
            // Standard withdrawal
            gtUint256 gtAmount = MpcCore.setPublic256(amount);
            privateToken.transferFrom(msg.sender, address(this), gtAmount);
            privateToken.burn(amount);
        }

        // Transfer public tokens
        bool success = token.transfer(msg.sender, amountAfterFee);
        if (!success) revert TokenTransferFailed();

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
    ) external override onlyOwner {
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
    function rescueERC20(
        address _token,
        address to,
        uint256 amount
    ) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();

        bool success = IERC20(_token).transfer(to, amount);
        if (!success) revert TokenTransferFailed();
    }
}
