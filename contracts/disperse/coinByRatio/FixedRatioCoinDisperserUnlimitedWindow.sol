// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title FixedRatioCoinDisperserUnlimitedWindow
 * @notice Redeem ERC20 "points" for native ETH payout pool
 *         - Fixed-index redemption set at finalize()
 *         - Pull-based withdrawals (DoS safe)
 *         - Optional push for EOAs only
 *         - Native ETH payouts
 *
 */
contract FixedRatioCoinDisperserUnlimitedWindow is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    // --- Custom Errors ---
    error TokenZeroAddress();
    error OwnerZeroAddress();
    error AlreadyFinalized();
    error PoolZero();
    error SupplyZero();
    error NotFinalized();
    error NoDust();
    error ContractMustPull();
    error NothingToWithdraw();
    error ContractPaused();
    error AmountZero();
    error SnapshotZero();
    error NoPointsLeft();
    error OverCapacity();
    error BalanceManipulation();
    error PayoutZero();
    error InvalidAddress();
    error InsufficientEthBalance();
    error EthTransferFailed();

    // --- Events ---
    event Funded(address indexed from, uint256 amount);
    event Finalized(uint256 totalPayoutPool, uint256 totalRedeemablePoints, uint256 accPayoutPerPoint);
    event Redeemed(address indexed user, uint256 pointsRequested, uint256 pointsReceived, uint256 payout, bool pushed);
    event Paused(bool isPaused);
    event DustWithdrawn(uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /// @notice Emitted when the payout index is updated via external source sync.
    event AccPayoutPerPointUpdated(uint256 previousAccPayoutPerPoint, uint256 newAccPayoutPerPoint);

    // --- Config ---
    IERC20 public immutable POINTS_TOKEN;

    // --- Lifecycle ---
    bool public finalized;
    bool public paused;

    // --- Accounting ---
    uint256 public totalPayoutPool;          // ETH reserved for redemptions (snapshot at finalize)
    uint256 public totalRedeemablePoints;    // points supply snapshot at finalize
    uint256 public accPayoutPerPoint;        // index = totalPayoutPool * 1e18 / totalRedeemablePoints
    uint256 public totalPointsRedeemed;      // cumulative points locked
    uint256 public totalPayoutSent;          // cumulative ETH sent

    // --- Pull ledger ---
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public pendingTotal;

    uint256 private constant ONE = 1e18;

    /**
     * @dev Constructor
     * @param _pointsToken Address of the ERC20 points token that can be redeemed
     * @param _owner Address that will have admin privileges (can pause, finalize, etc.)
     */
    constructor(address _pointsToken, address _owner) {
        if (_pointsToken == address(0)) revert TokenZeroAddress();
        if (_owner == address(0)) revert OwnerZeroAddress();

        POINTS_TOKEN = IERC20(_pointsToken);
        _transferOwnership(_owner);
    }

    // --- Admin ---

    /**
     * @dev Pause or unpause the redemption system
     * @notice Only the owner can call this function
     * @notice When paused, users cannot redeem points but can still withdraw pending amounts
     */
    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit Paused(_paused);
    }

    /**
     * @dev Fund the contract with ETH for redemptions
     * @notice Only the owner can call this function
     * @notice The ETH sent will be used to pay out redemptions
     * @notice Can be called multiple times to add more ETH
     * @notice Cannot be called after finalization.
     */
    function fundEth() external payable onlyOwner {
        if (finalized) revert AlreadyFinalized();
        if (msg.value == 0) revert AmountZero();

        totalPayoutPool += msg.value;
        emit Funded(msg.sender, msg.value);
    }

    /**
     * @dev Move existing contract balance to the payout pool (pre-finalize only)
     * @notice Only owner can call this function
     * @notice Prevents double-counting by only adding (balance - totalPayoutPool) if positive
     */
    function moveBalanceToPool() external onlyOwner {
        if (finalized) revert AlreadyFinalized();

        uint256 balance = address(this).balance;
        if (balance == 0) revert PoolZero();

        uint256 currentPool = totalPayoutPool;
        if (balance > currentPool) {
            uint256 difference = balance - currentPool;
            totalPayoutPool += difference;
            emit Funded(msg.sender, difference);
        }
    }

    /**
     * @dev Finalize the redemption system and calculate payout rates
     * @notice Only the owner can call this function
     * @notice Can only be called once
     * @notice Snapshot the current ETH balance and points token supply
     * @notice Calculate the payout rate per point (ETH per point)
     * @notice After finalization, redemptions can begin (window no longer enforced)
     */
    function finalize() external onlyOwner {
        if (finalized) revert AlreadyFinalized();

        uint256 pool = address(this).balance;
        uint256 supply = POINTS_TOKEN.totalSupply();
        if (pool == 0) revert PoolZero();
        if (supply == 0) revert SupplyZero();

        uint256 index = Math.mulDiv(pool, ONE, supply);

        totalPayoutPool = pool;
        totalRedeemablePoints = supply;
        accPayoutPerPoint = index;
        finalized = true;

        emit Finalized(pool, supply, index);
    }

    // --- Owner utilities ---

    /**
     * @dev Withdraw excess ETH that is not needed for redemptions
     * @notice Only the owner can call this function
     * @notice Can only be called after finalization and redemption window closes
     * @notice Withdraws ETH in excess of what's needed for pending withdrawals
     * @notice ETH is sent to the owner address
     *
     * @dev NOTE: Redemption window is no longer enforced; this can be called any time after finalization.
     */
    function withdrawDust() external onlyOwner nonReentrant {
        if (!finalized) revert NotFinalized();
        // NOTE: redemption window no longer enforced

        uint256 requiredReserve = pendingTotal;
        uint256 bal = address(this).balance;
        if (bal <= requiredReserve) revert NoDust();

        uint256 amount = bal - requiredReserve;
        (bool success,) = owner().call{value: amount}("");
        if (!success) revert EthTransferFailed();

        emit DustWithdrawn(amount);
    }

    // --- Redeem API ---

    /**
     * @dev Redeem points for ETH using pull pattern (user must call withdraw later)
     * @param amount Amount of points to redeem
     * @notice User must have approved the contract to spend their points
     * @notice ETH payout is added to user's pending withdrawals
     * @notice User must call withdraw() later to receive the ETH
     * @notice Can only be called when finalized and not paused (window no longer enforced)
     */
    function redeemPull(uint256 amount) external nonReentrant {
        (uint256 payout, uint256 received) = _redeemCore(msg.sender, amount);
        pendingWithdrawals[msg.sender] += payout;
        pendingTotal += payout;

        emit Redeemed(msg.sender, amount, received, payout, false);
    }

    /**
     * @dev Redeem points for ETH using push pattern (immediate ETH transfer)
     * @param amount Amount of points to redeem
     * @notice User must have approved the contract to spend their points
     * @notice ETH is sent directly to the user's address
     * @notice Only works for EOA (externally owned accounts), not contracts
     * @notice Can only be called when finalized and not paused (window no longer enforced)
     */
    function redeemPush(uint256 amount) external nonReentrant {
        if (!_isEoa(msg.sender)) revert ContractMustPull();

        (uint256 payout, uint256 received) = _redeemCore(msg.sender, amount);

        (bool success,) = msg.sender.call{value: payout}("");
        if (!success) revert EthTransferFailed();

        emit Redeemed(msg.sender, amount, received, payout, true);
    }

    /**
     * @dev Withdraw pending ETH from pull redemptions
     * @notice Withdraws all pending ETH for the caller
     * @notice ETH is sent directly to the caller's address
     * @notice Can be called anytime after a pull redemption
     * @notice Sets caller's pending balance to zero after withdrawal
     */
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToWithdraw();

        pendingWithdrawals[msg.sender] = 0;
        pendingTotal -= amount;

        (bool success,) = msg.sender.call{value: amount}("");
        if (!success) revert EthTransferFailed();

        emit Withdrawal(msg.sender, amount);
    }

    // --- Core math ---

    /**
     * @dev Internal function that handles the core redemption logic
     * @param user Address of the user redeeming points
     * @param amount Amount of points to redeem
     * @return payout Amount of ETH to be paid out
     * @return received Actual amount of points received (transferred to contract)
     * @notice Handles all validation, point transfer, and payout calculation
     * @notice Points are transferred from user to contract and locked forever
     * @notice Updates global accounting (totalPointsRedeemed, totalPayoutSent)
     */
    function _redeemCore(address user, uint256 amount)
        internal
        returns (uint256 payout, uint256 received)
    {
        if (!finalized) revert NotFinalized();
        if (paused) revert ContractPaused();
        if (amount == 0) revert AmountZero();

        uint256 trp = totalRedeemablePoints;
        uint256 tpr = totalPointsRedeemed;
        if (trp == 0) revert SnapshotZero();

        uint256 remaining = trp - tpr;
        if (remaining == 0) revert NoPointsLeft();

        // Pull points token (requires allowance from user)
        uint256 beforeBal = POINTS_TOKEN.balanceOf(address(this));
        POINTS_TOKEN.safeTransferFrom(user, address(this), amount);
        uint256 afterBal = POINTS_TOKEN.balanceOf(address(this));
        received = afterBal - beforeBal;

        if (received == 0) revert PayoutZero();
        if (received > amount) revert BalanceManipulation();
        if (received > remaining) revert OverCapacity();

        payout = Math.mulDiv(received, accPayoutPerPoint, ONE);

        // Cap payout by safe reserve / balance
        uint256 reserve = _safeRemainingReserve();
        if (payout > reserve) payout = reserve;
        if (payout == 0) revert PayoutZero();

        // Check if contract has enough ETH (defensive; reserve already caps by balance)
        if (payout > address(this).balance) revert InsufficientEthBalance();

        unchecked {
            totalPointsRedeemed = tpr + received;
            totalPayoutSent += payout;
        }
    }

    // --- Views ---

    /**
     * @dev Check if redemptions are currently open
     * @return True if redemptions are open (finalized and not paused)
     */
    function isRedemptionOpen() public view returns (bool) {
        return finalized && !paused;
    }

    /**
     * @dev Get the remaining ETH reserve available for redemptions
     * @return Amount of ETH still available for redemptions
     * @notice Returns 0 if not finalized or if all ETH has been paid out
     */
    function remainingReserve() public view returns (uint256) {
        if (!finalized) return 0;
        if (totalPayoutSent >= totalPayoutPool) return 0;
        return totalPayoutPool - totalPayoutSent;
    }

    /**
     * @dev Internal function to get the safe remaining reserve
     * @return The minimum of theoretical reserve and actual ETH balance
     * @notice Ensures we don't try to pay out more ETH than we actually have
     */
    function _safeRemainingReserve() internal view returns (uint256) {
        if (!finalized) return 0;
        uint256 theoreticalReserve =
            totalPayoutSent >= totalPayoutPool ? 0 : (totalPayoutPool - totalPayoutSent);
        uint256 actualBalance = address(this).balance;
        return theoreticalReserve > actualBalance ? actualBalance : theoreticalReserve;
    }

    /**
     * @dev Preview the ETH payout for a given amount of points
     * @param amount Amount of points to redeem
     * @return Expected ETH payout amount
     * @notice This is an estimate and actual payout may be lower due to reserve limits
     * @notice Returns 0 if not finalized, no points left, or amount exceeds remaining points
     */
    function previewPayout(uint256 amount) external view returns (uint256) {
        if (!finalized || amount == 0) return 0;

        uint256 trp = totalRedeemablePoints;
        if (trp == 0) return 0;

        uint256 tpr = totalPointsRedeemed;
        if (tpr >= trp) return 0;

        uint256 remaining = trp - tpr;
        if (amount > remaining) return 0;

        uint256 est = Math.mulDiv(amount, accPayoutPerPoint, ONE);
        uint256 reserve = remainingReserve();
        return est > reserve ? reserve : est;
    }

    // --- Governance / Admin override ---

    /**
     * @dev Owner can directly update the payout rate per point.
     * @param newAccPayoutPerPoint New payout index (ETH per point, scaled by 1e18)
     * @notice Only callable after finalization.
     * @notice Does NOT retroactively adjust past payouts; only affects future redemptions.
     */
    function setAccPayoutPerPoint(uint256 newAccPayoutPerPoint) external onlyOwner {
        if (!finalized) revert NotFinalized();
        if (newAccPayoutPerPoint == 0) revert PayoutZero();

        uint256 prev = accPayoutPerPoint;
        accPayoutPerPoint = newAccPayoutPerPoint;

        emit AccPayoutPerPointUpdated(prev, newAccPayoutPerPoint);
    }

    // Rescue (window no longer enforced)

    /**
     * @dev Rescue ERC20 tokens sent to the contract after redemption window closes
     * @param tokenAddr Address of the ERC20 token to rescue
     * @param to Address to send the tokens to
     * @param amount Amount of tokens to rescue
     * @notice Only the owner can call this function
     * @notice Can only be called after finalization and redemption window closes
     * @notice Used to recover accidentally sent tokens
     *
     * @dev NOTE: Redemption window is no longer enforced; this can be called any time after finalization.
     */
    function rescueTokens(address tokenAddr, address to, uint256 amount) external onlyOwner {
        if (!finalized) revert NotFinalized();
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        IERC20(tokenAddr).safeTransfer(to, amount);
    }

    /**
     * @dev Rescue ETH sent to the contract after redemption window closes
     * @param to Address to send the ETH to
     * @param amount Amount of ETH to rescue
     * @notice Only the owner can call this function
     * @notice Can only be called after finalization and redemption window closes
     * @notice Used to recover accidentally sent ETH
     *
     * @dev NOTE: Redemption window is no longer enforced; this can be called any time after finalization.
     */
    function rescueEth(address to, uint256 amount) external onlyOwner {
        if (!finalized) revert NotFinalized();
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountZero();
        if (amount > address(this).balance) revert InsufficientEthBalance();

        (bool success,) = to.call{value: amount}("");
        if (!success) revert EthTransferFailed();
    }

    // --- Utils ---

    /**
     * @dev Check if an address is an externally owned account (EOA)
     * @param a Address to check
     * @return True if the address is an EOA (no code), false if it's a contract
     * @notice Used to determine if push redemptions are allowed
     */
    function _isEoa(address a) internal view returns (bool) {
        return a.code.length == 0;
    }

    /**
     * @dev Allow the contract to receive ETH from any sender.
     * @notice This is triggered automatically when ETH is sent directly (no data).
     * @notice The ETH is NOT automatically added to the redemption pool.
     * @notice Use fundEth() or moveBalanceToPool() to add ETH to the pool.
     */
    receive() external payable {
        if (msg.value == 0) return; // ignore zero-value sends to save gas
    }
}
