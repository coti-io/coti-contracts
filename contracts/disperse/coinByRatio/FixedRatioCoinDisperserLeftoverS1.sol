// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;
    modifier nonReentrant() {
        require(_status != _ENTERED, "REENTRANCY");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

/**
 * @title FixedRatioCoinDisperser
 * @notice Redeem ERC20 "points" for native ETH payout pool
 *         - Order-independent fixed-index redemption
 *         - Pull-based withdrawals (DoS safe)
 *         - Optional push for EOAs only
 *         - Native ETH payouts
 */
contract FixedRatioCoinDisperser is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // --- Custom Errors ---
    error TokenZeroAddress();
    error OwnerZeroAddress();
    error InvalidBlockRange();
    error NotOwner();
    error AlreadyFinalized();
    error PoolZero();
    error SupplyZero();
    error NotFinalized();
    error NoExcess();
    error WindowActive();
    error NoDust();
    error WithdrawFailed();
    error ContractMustPull();
    error NothingToWithdraw();
    error ContractPaused();
    error OutOfWindow();
    error AmountZero();
    error SnapshotZero();
    error NoPointsLeft();
    error OverCapacity();
    error BalanceManipulation();
    error PayoutZero();
    error RedemptionNotClosed();
    error InvalidAddress();
    error InsufficientBalance();
    error InsufficientEthBalance();
    error EthTransferFailed();

    // --- Events ---
    event Funded(address indexed from, uint256 amount);
    event Finalized(uint256 totalPayoutPool, uint256 totalRedeemablePoints, uint256 accPayoutPerPoint);
    event Redeemed(address indexed user, uint256 pointsRequested, uint256 pointsReceived, uint256 payout, bool pushed);
    event Paused(bool isPaused);
    event DustWithdrawn(uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Withdrawal(address indexed user, uint256 amount);

    /// @notice Emitted when the payout index is updated via external source sync.
    event AccPayoutPerPointUpdated(uint256 previousAccPayoutPerPoint, uint256 newAccPayoutPerPoint);

    // --- Config ---
    IERC20 public immutable POINTS_TOKEN;
    address public owner;

    // --- Redemption window ---
    uint256 public immutable START_BLOCK;
    uint256 public immutable END_BLOCK;

    // NOTE:
    // START_BLOCK / END_BLOCK are retained for ABI compatibility, but are no longer enforced.

    // --- Lifecycle ---
    bool public finalized;
    bool public paused;

    // --- Accounting ---
    uint256 public totalPayoutPool;          // ETH reserved for redemptions (snapshot)
    uint256 public totalRedeemablePoints;    // points supply snapshot at finalize
    uint256 public accPayoutPerPoint;        // index = totalPayoutPool * 1e18 / totalRedeemablePoints
    uint256 public totalPointsRedeemed;      // cumulative points locked
    uint256 public totalPayoutSent;          // cumulative ETH sent

    // --- Pull ledger ---
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public pendingTotal;

    uint256 private constant ONE = 1e18;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /**
     * @dev Constructor to initialize the FixedRatioCoinDisperser contract
     * @param _pointsToken Address of the ERC20 points token that can be redeemed
     * @param _owner Address that will have admin privileges (can pause, finalize, etc.)
     * @param _startBlock Block number when redemption window opens (retained for ABI compatibility)
     * @param _endBlock Block number when redemption window closes (retained for ABI compatibility)
     */
    constructor(
        address _pointsToken,
        address _owner,
        uint256 _startBlock,
        uint256 _endBlock
    ) {
        if (_pointsToken == address(0)) revert TokenZeroAddress();
        if (_owner == address(0)) revert OwnerZeroAddress();
        if (_endBlock <= _startBlock) revert InvalidBlockRange();

        POINTS_TOKEN = IERC20(_pointsToken);
        owner = _owner;
        START_BLOCK = _startBlock;
        END_BLOCK = _endBlock;
    }

    // --- Admin ---

    /**
     * @dev Pause or unpause the redemption system
     * @param _paused True to pause redemptions, false to unpause
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
     * @dev Move existing contract balance to the payout pool
     * @notice Only owner can call this function
     * @notice Can only be called before finalization
     * @notice Moves all ETH currently in contract balance to totalPayoutPool
     */
    function moveBalanceToPool() external onlyOwner {
        if (finalized) revert AlreadyFinalized();
        uint256 balance = address(this).balance;
        if (balance == 0) revert PoolZero();

        // Only add the difference to avoid double-counting
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
        (bool success,) = owner.call{value: amount}("");
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
        // NOTE: block window validation removed to allow redemption anytime after finalize.
        if (amount == 0) revert AmountZero();

        uint256 trp = totalRedeemablePoints;
        uint256 tpr = totalPointsRedeemed;
        if (trp == 0) revert SnapshotZero();

        uint256 remaining = trp - tpr;
        if (remaining == 0) revert NoPointsLeft();

        // --- Pull points token (requires allowance from user)
        uint256 beforeBal = POINTS_TOKEN.balanceOf(address(this));
        POINTS_TOKEN.safeTransferFrom(user, address(this), amount);
        uint256 afterBal = POINTS_TOKEN.balanceOf(address(this));
        received = afterBal - beforeBal;

        if (received == 0) revert PayoutZero();
        if (received > amount) revert BalanceManipulation();
        if (received > remaining) revert OverCapacity();

        payout = Math.mulDiv(received, accPayoutPerPoint, ONE);

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
        uint256 theoreticalReserve = totalPayoutSent >= totalPayoutPool ? 0 : (totalPayoutPool - totalPayoutSent);
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
     * @dev Owner can update the payout rate per point by reading it from an already-deployed contract.
     * @param source Address of the deployed contract exposing accPayoutPerPoint()
     * @notice Only callable after finalization.
     * @notice Reads value via staticcall (no compile-time ABI dependency).
     * @notice Does NOT retroactively adjust past payouts; only affects future redemptions.
     */
    function setAccPayoutPerPointFromSource(address source) external onlyOwner {
        if (!finalized) revert NotFinalized();
        if (source == address(0) || source.code.length == 0) revert InvalidAddress();

        (bool success, bytes memory data) =
            source.staticcall(abi.encodeWithSignature("accPayoutPerPoint()"));

        if (!success || data.length < 32) revert PayoutZero();

        uint256 newValue = abi.decode(data, (uint256));
        if (newValue == 0) revert PayoutZero();

        uint256 prev = accPayoutPerPoint;
        accPayoutPerPoint = newValue;

        emit AccPayoutPerPointUpdated(prev, newValue);
    }

    // --- Ownership ---

    /**
     * @dev Transfer ownership of the contract to a new address
     * @param newOwner Address of the new owner
     * @notice Only the current owner can call this function
     * @notice New owner cannot be zero address
     * @notice Emits OwnershipTransferred event
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert OwnerZeroAddress();
        address prev = owner;
        owner = newOwner;
        emit OwnershipTransferred(prev, newOwner);
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
