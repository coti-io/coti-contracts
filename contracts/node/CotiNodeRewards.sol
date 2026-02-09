// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title CotiNodeRewards
 * @notice Manages eligibility rules and native COTI rewards for the COTI node ecosystem.
 * @dev COTI is the chain's native token (like ETH). Owner funds the contract by sending native COTI,
 *      sets eligibility rules, allocates claimable rewards; users claim and receive native COTI.
 * @dev Decimals: USDC = 6 ({DECIMALS_USDC}), native COTI = 18 ({DECIMALS_COTI}). Reward amounts are in COTI wei.
 */
contract CotiNodeRewards is Ownable, ReentrancyGuard {

    // ============ Decimals ============
    /// @notice USDC uses 6 decimals (amounts in eligibility rules for USDC are in 10^6 units)
    uint8 public constant DECIMALS_USDC = 6;
    /// @notice Native COTI uses 18 decimals (reward amounts and contract balance are in wei, 10^18 units)
    uint8 public constant DECIMALS_COTI = 18;

    // ============ Eligibility rules: rule name (bytes32) => value ============
    /// @dev Use getEligibilityRule(string) or predefined keys (e.g. PLATFORM_USDC_AMOUNT)
    mapping(bytes32 => uint256) public eligibilityRules;

    /// @notice Predefined rule key: Platform USDC amount (value in USDC smallest unit, 6 decimals; e.g. 10 * 10^6 = 10 USDC)
    bytes32 public constant RULE_PLATFORM_USDC_AMOUNT = keccak256("Platform_USDC_amount");
    /// @notice Predefined rule key: Platform COTI amount (value in COTI smallest unit, 18 decimals; e.g. 5e18 = 5 COTI)
    bytes32 public constant RULE_PLATFORM_COTI_AMOUNT = keccak256("Platform_COTI_amount");
    /// @notice Predefined rule key: Full node uptime percentage threshold (e.g. 98 for 98%)
    bytes32 public constant RULE_FULL_NODE_UPTIME_PERCENTAGE_THRESHOLD = keccak256("Full_node_up_time_percentage_threshold");

    // ============ Reward state ============
    /// @notice Per address: total COTI ever claimed by this address
    mapping(address => uint256) public totalPerAddressClaimedCotiToken;
    /// @notice Per address: COTI currently claimable (not yet claimed)
    mapping(address => uint256) public totalPerAddressClaimableCotiToken;
    /// @notice Per address: last epoch in which this wallet was rewarded (used to prevent double rewards per epoch)
    mapping(address => uint256) public lastRewardEpoch;

    /// @notice Total COTI ever allocated as claimable (sum of all rewards ever added)
    uint256 public totalRewardedCoti;
    /// @notice Total COTI ever claimed by all users
    uint256 public totalClaimedCoti;
    /// @notice Sum of all current claimable amounts (invariant: contract native balance must be >= this)
    uint256 public totalClaimableCoti;

    // ============ Events ============
    event EligibilityRuleSet(bytes32 indexed ruleKey, uint256 value);
    event RewardAdded(address indexed wallet, uint256 amount);
    event Claimed(address indexed wallet, uint256 amount);

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientContractBalance();
    error NothingToClaim();
    error ArrayLengthMismatch();
    error TransferFailed();
    error AlreadyRewardedInEpoch(address wallet, uint256 epoch);
    error InvalidEpoch(uint256 epoch);

    constructor() Ownable() {
        eligibilityRules[RULE_PLATFORM_COTI_AMOUNT] = 100_000 * 10**DECIMALS_COTI;   // 100k COTI
        eligibilityRules[RULE_PLATFORM_USDC_AMOUNT] = 50_000 * 10**DECIMALS_USDC;    // 50k USDC
        eligibilityRules[RULE_FULL_NODE_UPTIME_PERCENTAGE_THRESHOLD] = 98;          // 98%
    }

    /// @notice Accept native COTI so the contract can be funded for rewards.
    receive() external payable {}

    // ============ Eligibility rules (owner) ============

    /**
     * @notice Set an eligibility rule by key and value.
     * @param ruleKey Rule identifier (use constants or keccak256("name"))
     * @param value Rule value (e.g. threshold, amount in smallest units)
     */
    function setEligibilityRule(bytes32 ruleKey, uint256 value) external onlyOwner {
        eligibilityRules[ruleKey] = value;
        emit EligibilityRuleSet(ruleKey, value);
    }

    /**
     * @notice Get eligibility rule value by string name (e.g. "Platform_USDC_amount").
     */
    function getEligibilityRule(string calldata ruleName) external view returns (uint256) {
        return eligibilityRules[keccak256(bytes(ruleName))];
    }

    // ============ Reward allocation (owner) ============

    /**
     * @dev Increases the claimable native COTI amount for a wallet for a specific epoch. Owner only.
     *      Each wallet can only be rewarded once per epoch, and epochs must be strictly increasing per wallet.
     *      Contract must have sufficient native balance to cover existing claimable + new amount.
     * @param wallet Address to reward
     * @param amount Native COTI amount in wei (18 decimals, {DECIMALS_COTI}) to add to claimable
     * @param epoch  Logical epoch identifier for this reward (must be greater than the wallet's lastRewardEpoch)
     */
    function rewardWallet(address wallet, uint256 amount, uint256 epoch) external onlyOwner {
        if (wallet == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (epoch == 0) revert InvalidEpoch(epoch);
        if (epoch <= lastRewardEpoch[wallet]) revert AlreadyRewardedInEpoch(wallet, epoch);

        uint256 newTotalClaimable = totalClaimableCoti + amount;
        if (address(this).balance < newTotalClaimable) revert InsufficientContractBalance();

        totalPerAddressClaimableCotiToken[wallet] += amount;
        totalClaimableCoti = newTotalClaimable;
        totalRewardedCoti += amount;
        lastRewardEpoch[wallet] = epoch;

        emit RewardAdded(wallet, amount);
    }

    /**
     * @notice Add claimable rewards for multiple wallets in one call, for a specific epoch. Owner only.
     *         Each wallet can only be rewarded once per epoch, and epochs must be strictly increasing per wallet.
     * @param wallets Addresses to reward
     * @param amounts Native COTI amounts in wei to add to claimable for each wallet
     * @param epoch   Logical epoch identifier for this reward batch
     */
    function rewardWallets(address[] calldata wallets, uint256[] calldata amounts, uint256 epoch) external onlyOwner {
        uint256 len = wallets.length;
        if (len != amounts.length) revert ArrayLengthMismatch();
        if (epoch == 0) revert InvalidEpoch(epoch);

        uint256 added;
        for (uint256 i; i < len; ) {
            address wallet = wallets[i];
            uint256 amount = amounts[i];
            if (wallet == address(0)) revert ZeroAddress();
            if (amount != 0) {
                if (epoch <= lastRewardEpoch[wallet]) revert AlreadyRewardedInEpoch(wallet, epoch);
                totalPerAddressClaimableCotiToken[wallet] += amount;
                added += amount;
                lastRewardEpoch[wallet] = epoch;
                emit RewardAdded(wallet, amount);
            }
            unchecked { ++i; }
        }
        if (added != 0) {
            uint256 newTotalClaimable = totalClaimableCoti + added;
            if (address(this).balance < newTotalClaimable) revert InsufficientContractBalance();
            totalClaimableCoti = newTotalClaimable;
            totalRewardedCoti += added;
        }
    }

    // ============ Claim (user) ============

    /**
     * @dev Lets msg.sender claim their claimable native COTI. Reduces total_per_address_claimable_Coti_token
     *      and adds the claimed amount to total_per_address_claimed_coti_token; sends native COTI (18 decimals) to the user.
     */
    function claimReward() external nonReentrant {
        uint256 amount = totalPerAddressClaimableCotiToken[msg.sender];
        if (amount == 0) revert NothingToClaim();

        totalPerAddressClaimableCotiToken[msg.sender] = 0;
        totalPerAddressClaimedCotiToken[msg.sender] += amount;
        totalClaimableCoti -= amount;
        totalClaimedCoti += amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) revert TransferFailed();
        emit Claimed(msg.sender, amount);
    }

    /**
     * @notice Returns the claimable COTI amount for the caller.
     */
    function claimableOf(address account) external view returns (uint256) {
        return totalPerAddressClaimableCotiToken[account];
    }

    // ============ Admin withdrawal ============

    /**
     * @notice Withdraw excess native COTI that is not reserved for current rewards.
     * @dev Ensures that after withdrawal, the contract still holds at least `totalClaimableCoti`.
     * @param to Recipient address for the withdrawn native COTI.
     * @param amount Native COTI amount in wei to withdraw.
     */
    function withdrawExcess(address payable to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        uint256 balance = address(this).balance;
        if (balance < totalClaimableCoti) revert InsufficientContractBalance();

        uint256 available = balance - totalClaimableCoti;
        if (amount > available) revert InsufficientContractBalance();

        (bool success, ) = to.call{value: amount}("");
        if (!success) revert TransferFailed();
    }
}
