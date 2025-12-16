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
 * @title FixedRatioCoinDisperserUnlimitedWindow
 * @notice Redeem ERC20 "points" for native ETH payout pool
 *         - Order-independent fixed-index redemption (snapshot at finalize)
 *         - No claim windows
 *         - Pull-based withdrawals (DoS safe)
 *         - Optional push for EOAs only
 *         - Native ETH payouts
 *
 * Bonus logic:
 * - Bonus percentage is configurable at deploy (basis points)
 * - Eligibility is binary and provided at redeem time
 * - Bonus is applied ONLY if eligibleForBonus == true
 *
 * IMPORTANT:
 * - Eligibility is trusted/off-chain for now
 * - This does NOT yet enforce proportional distribution
 */
contract FixedRatioCoinDisperserUnlimitedWindow is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // --- Custom Errors ---
    error TokenZeroAddress();
    error OwnerZeroAddress();
    error InvalidBonusBps();
    error NotOwner();
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
    event Finalized(
        uint256 totalPayoutPool,
        uint256 totalRedeemablePoints,
        uint256 bonusPointsSupply,
        uint256 accPayoutPerPoint
    );
    event Redeemed(
        address indexed user,
        uint256 pointsRequested,
        uint256 pointsReceived,
        uint256 payout,
        bool bonusApplied,
        bool pushed
    );
    event Paused(bool isPaused);
    event DustWithdrawn(uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Withdrawal(address indexed user, uint256 amount);

    // --- Constants ---
    uint256 private constant ONE = 1e18;
    uint256 private constant BPS = 10_000;

    // --- Config ---
    IERC20 public immutable POINTS_TOKEN;
    address public owner;

    /// @notice Bonus percentage in basis points (e.g. 1500 = 15%)
    uint256 public immutable bonusBps;

    /// @notice Unclaimed TPS from previous season (off-chain calculated)
    uint256 public immutable unclaimedTPSPrevSeason;

    // --- Lifecycle ---
    bool public finalized;
    bool public paused;

    // --- Accounting ---
    uint256 public totalPayoutPool;
    uint256 public totalRedeemablePoints;
    uint256 public bonusPointsSupply;
    uint256 public accPayoutPerPoint;
    uint256 public totalPointsRedeemed;
    uint256 public totalPayoutSent;

    // --- Pull ledger ---
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public pendingTotal;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /**
     * @param _pointsToken ERC20 points token (TPS002)
     * @param _owner contract owner
     * @param _bonusBps bonus percentage in basis points (e.g. 1500 = 15%)
     * @param _unclaimedTPSPrevSeason total unclaimed TPS from previous season
     */
    constructor(
        address _pointsToken,
        address _owner,
        uint256 _bonusBps,
        uint256 _unclaimedTPSPrevSeason
    ) {
        if (_pointsToken == address(0)) revert TokenZeroAddress();
        if (_owner == address(0)) revert OwnerZeroAddress();
        if (_bonusBps > BPS) revert InvalidBonusBps();

        POINTS_TOKEN = IERC20(_pointsToken);
        owner = _owner;
        bonusBps = _bonusBps;
        unclaimedTPSPrevSeason = _unclaimedTPSPrevSeason;
    }

    // --- Admin ---

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit Paused(_paused);
    }

    function fundEth() external payable onlyOwner {
        if (msg.value == 0) revert AmountZero();
        totalPayoutPool += msg.value;
        emit Funded(msg.sender, msg.value);
    }

    function moveBalanceToPool() external onlyOwner {
        if (finalized) revert AlreadyFinalized();
        uint256 bal = address(this).balance;
        if (bal == 0) revert PoolZero();

        if (bal > totalPayoutPool) {
            uint256 diff = bal - totalPayoutPool;
            totalPayoutPool += diff;
            emit Funded(msg.sender, diff);
        }
    }

    /**
     * @dev Snapshot ETH balance and points supply
     */
    function finalize() external onlyOwner {
        if (finalized) revert AlreadyFinalized();

        uint256 pool = address(this).balance;
        uint256 supply = POINTS_TOKEN.totalSupply();
        if (pool == 0) revert PoolZero();
        if (supply == 0) revert SupplyZero();

        uint256 index = Math.mulDiv(pool, ONE, supply);
        uint256 bonusSupply = Math.mulDiv(supply, bonusBps, BPS);

        totalPayoutPool = pool;
        totalRedeemablePoints = supply;
        bonusPointsSupply = bonusSupply;
        accPayoutPerPoint = index;
        finalized = true;

        emit Finalized(pool, supply, bonusSupply, index);
    }

    // --- Owner utilities ---

    function rescueEth(address to) external onlyOwner nonReentrant {
        if (to == address(0)) revert InvalidAddress();

        uint256 bal = address(this).balance;
        if (bal <= pendingTotal) revert NoDust();

        uint256 amount = bal - pendingTotal;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert EthTransferFailed();

        emit DustWithdrawn(amount);
    }

    // --- Redeem ---

    function redeemPull(uint256 amount, bool eligibleForBonus) external nonReentrant {
        (uint256 payout, uint256 received, bool bonusApplied) =
            _redeemCore(msg.sender, amount, eligibleForBonus);

        pendingWithdrawals[msg.sender] += payout;
        pendingTotal += payout;

        emit Redeemed(msg.sender, amount, received, payout, bonusApplied, false);
    }

    function redeemPush(uint256 amount, bool eligibleForBonus) external nonReentrant {
        if (!_isEoa(msg.sender)) revert ContractMustPull();

        (uint256 payout, uint256 received, bool bonusApplied) =
            _redeemCore(msg.sender, amount, eligibleForBonus);

        (bool ok,) = msg.sender.call{value: payout}("");
        if (!ok) revert EthTransferFailed();

        emit Redeemed(msg.sender, amount, received, payout, bonusApplied, true);
    }

    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToWithdraw();

        pendingWithdrawals[msg.sender] = 0;
        pendingTotal -= amount;

        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert EthTransferFailed();

        emit Withdrawal(msg.sender, amount);
    }

    // --- Core ---

    function _redeemCore(
        address user,
        uint256 amount,
        bool eligibleForBonus
    )
        internal
        returns (uint256 payout, uint256 received, bool bonusApplied)
    {
        if (!finalized) revert NotFinalized();
        if (paused) revert ContractPaused();
        if (amount == 0) revert AmountZero();

        uint256 remaining = totalRedeemablePoints - totalPointsRedeemed;
        if (remaining == 0) revert NoPointsLeft();

        uint256 beforeBal = POINTS_TOKEN.balanceOf(address(this));
        POINTS_TOKEN.safeTransferFrom(user, address(this), amount);
        uint256 afterBal = POINTS_TOKEN.balanceOf(address(this));
        received = afterBal - beforeBal;

        if (received == 0) revert PayoutZero();
        if (received > amount) revert BalanceManipulation();
        if (received > remaining) revert OverCapacity();

        uint256 basePayout = Math.mulDiv(received, accPayoutPerPoint, ONE);
        if (basePayout == 0) revert PayoutZero();

        payout = basePayout;
        bonusApplied = false;

        if (eligibleForBonus && bonusBps > 0) {
            uint256 bonus = Math.mulDiv(basePayout, bonusBps, BPS);
            payout += bonus;
            bonusApplied = true;
        }

        if (payout > address(this).balance) revert InsufficientEthBalance();

        unchecked {
            totalPointsRedeemed += received;
            totalPayoutSent += payout;
        }
    }

    // --- Ownership & utils ---

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert OwnerZeroAddress();
        address prev = owner;
        owner = newOwner;
        emit OwnershipTransferred(prev, newOwner);
    }

    function _isEoa(address a) internal view returns (bool) {
        return a.code.length == 0;
    }

    receive() external payable {}
}
