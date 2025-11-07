// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title TokenDisperser
 * @notice Owner-controlled utility contract for distributing ERC20 tokens to multiple recipients
 * @dev Supports two distribution methods:
 *      - disperseFunds: Pulls tokens from a sender's balance (requires approval)
 *      - disperseFundsFromContract: Distributes from this contract's own token balance
 * @dev Tracks distributions by ID to prevent duplicate payouts to same recipient
 * @dev Uses OpenZeppelin's SafeERC20 for secure token transfers
 */
contract TokenDisperser {
    using SafeERC20 for IERC20;

    /// @notice Contract owner with permissions to execute distributions
    address public immutable owner;

    /// @notice ERC20 token that will be distributed
    IERC20 public immutable token;

    /// @notice Mapping: distributionId => recipient => amount received
    /// @dev Used to prevent duplicate distributions to same recipient per distributionId
    mapping(uint256 => mapping(address => uint256)) private _fundsReceived;

    /**
     * @notice Reverts if caller is not the owner
     */
    modifier onlyOwner {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }

    /**
     * @notice Initialize the TokenDisperser contract
     * @param token_ Address of the ERC20 token to distribute
     * @dev Sets deployer as owner and stores the token address
     */
    constructor(address token_) {
        owner = msg.sender;
        token = IERC20(token_);
    }

    /**
     * @notice Query how much each recipient received in a distribution
     * @param distributionId The distribution ID to query
     * @param recipients Array of recipient addresses to check
     * @return Array of amounts received (same order as recipients)
     * @dev Returns 0 for addresses that haven't received funds in this distribution
     */
    function fundsReceived(uint256 distributionId, address[] calldata recipients) external view returns (uint256[] memory) {
        uint256[] memory fundsReceived_ = new uint256[](recipients.length);

        for (uint256 i = 0; i < recipients.length; ++i) {
            fundsReceived_[i] = _fundsReceived[distributionId][recipients[i]];
        }

        return fundsReceived_;
    }

    /**
     * @notice Distribute tokens from a sender's balance to multiple recipients
     * @param distributionId Unique ID for this distribution batch
     * @param totalAmount Sum of all amounts (used for validation)
     * @param sender Address that has tokens and approved this contract to spend them
     * @param recipients Array of recipient addresses
     * @param amounts Array of token amounts (must match recipients length)
     * @dev Only owner can call this function
     * @dev Requires sender to have approved this contract
     * @dev Prevents duplicate distributions to same recipient within same distributionId
     * @dev Reverts if amounts don't sum to totalAmount
     * @dev Uses safeTransferFrom to pull tokens from sender
     */
    function disperseFunds(
        uint256 distributionId,
        uint256 totalAmount,
        address sender,
        address[] calldata recipients,
        uint256[] calldata amounts
    )
            external
        onlyOwner
    {
        uint256 currentAmount = 0;

        for (uint256 i = 0; i < recipients.length; ++i) {
            require(_fundsReceived[distributionId][recipients[i]] == 0, "Duplicate recipient");

            token.safeTransferFrom(sender, recipients[i], amounts[i]);

            currentAmount += amounts[i];

            _fundsReceived[distributionId][recipients[i]] = amounts[i];
        }

        require(currentAmount == totalAmount, "Incorrect amount");
    }

    /**
     * @notice Distribute tokens from this contract's own balance to multiple recipients
     * @param distributionId Unique ID for this distribution batch
     * @param totalAmount Sum of all amounts (used for validation)
     * @param recipients Array of recipient addresses
     * @param amounts Array of token amounts (must match recipients length)
     * @dev Only owner can call this function
     * @dev Requires contract to have sufficient token balance
     * @dev Prevents duplicate distributions to same recipient within same distributionId
     * @dev Reverts if amounts don't sum to totalAmount or contract lacks balance
     * @dev Uses safeTransfer to send from contract's own balance
     */
    function disperseFundsFromContract(
        uint256 distributionId,
        uint256 totalAmount,
        address[] calldata recipients,
        uint256[] calldata amounts
    )
            external
        onlyOwner
    {
        uint256 currentAmount = 0;

        for (uint256 i = 0; i < recipients.length; ++i) {
            require(_fundsReceived[distributionId][recipients[i]] == 0, "Duplicate recipient");

            // Transfer from this contract's own balance directly
            token.safeTransfer(recipients[i], amounts[i]);

            currentAmount += amounts[i];

            _fundsReceived[distributionId][recipients[i]] = amounts[i];
        }

        require(currentAmount == totalAmount, "Incorrect amount");
    }
}