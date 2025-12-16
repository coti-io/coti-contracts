// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IMintableERC20 {
    function mint(address to, uint256 amount) external;
}

interface IOwnable {
    function transferOwnership(address newOwner) external;
}

/**
 * @title MintDisperser
 * @notice Owner-controlled utility contract for minting ERC20 tokens to multiple recipients in a single transaction
 * @dev The target token must expose a mint(address,uint256) function and the
 *      MintDisperser contract must have permission to mint (e.g., MINTER_ROLE/owner).
 * @dev Supports two distribution methods:
 *      - mintSameAmount: Mints the same amount to all recipients
 *      - mint: Mints different amounts to each recipient
 */
contract MintDisperser is Ownable {
    /**
     * @notice Initialize the MintDisperser contract
     * @param initialOwner Address that will have owner privileges to execute minting operations
     * @dev Sets the initial owner of the contract using OpenZeppelin's Ownable pattern
     */
    constructor(address initialOwner) {
        _transferOwnership(initialOwner);
    }

    /**
     * @notice Mint the same amount of tokens to multiple recipients
     * @param token Address of the ERC20 token contract that supports minting
     * @param recipients Array of recipient addresses that will receive tokens
     * @param amountPerRecipient Amount of tokens to mint to each recipient
     * @dev Only the contract owner can call this function
     * @dev Reverts if:
     *      - token is the zero address
     *      - amountPerRecipient is zero
     *      - recipients array is empty
     *      - any recipient address is the zero address
     * @dev The token contract must allow this contract to mint tokens (typically by being the owner or having MINTER_ROLE)
     * @dev All recipients receive the same amount of tokens
     */
    function mintSameAmount(
        address token,
        address[] calldata recipients,
        uint256 amountPerRecipient
    ) external onlyOwner {
        require(token != address(0), "token=0");
        require(amountPerRecipient > 0, "amount=0");
        uint256 len = recipients.length;
        require(len > 0, "no recipients");

        for (uint256 i = 0; i < len; ++i) {
            address to = recipients[i];
            require(to != address(0), "recipient=0");
            IMintableERC20(token).mint(to, amountPerRecipient);
        }
    }

    /**
     * @notice Mint different amounts of tokens to multiple recipients
     * @param token Address of the ERC20 token contract that supports minting
     * @param recipients Array of recipient addresses that will receive tokens
     * @param amounts Array of token amounts to mint to each recipient (must match recipients array length)
     * @dev Only the contract owner can call this function
     * @dev Reverts if:
     *      - token is the zero address
     *      - recipients array is empty
     *      - recipients and amounts arrays have different lengths
     *      - any recipient address is the zero address
     *      - any amount is zero
     * @dev The token contract must allow this contract to mint tokens (typically by being the owner or having MINTER_ROLE)
     * @dev Each recipient receives the corresponding amount from the amounts array at the same index
     */
    function mint(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external onlyOwner {
        require(token != address(0), "token=0");
        uint256 len = recipients.length;
        require(len > 0, "no recipients");
        require(len == amounts.length, "length mismatch");

        for (uint256 i = 0; i < len; ++i) {
            address to = recipients[i];
            uint256 amt = amounts[i];
            require(to != address(0), "recipient=0");
            require(amt > 0, "amount=0");
            IMintableERC20(token).mint(to, amt);
        }
    }

    /**
     * @notice Transfers ownership of an Ownable ERC20 token from this contract to a new owner
     * @param token Address of the Ownable token contract whose ownership will be transferred
     * @param newOwner Address that will become the new owner of the token contract
     * @dev Only the contract owner can call this function
     * @dev Reverts if:
     *      - token is the zero address
     *      - newOwner is the zero address
     *      - this contract is not the current owner of the token contract
     * @dev This function is useful for transferring token ownership after the MintDisperser has been granted ownership
     *      to enable minting operations. After minting is complete, ownership can be transferred back or to another address.
     * @dev The token contract must implement the IOwnable interface with a transferOwnership function
     */
    function transferTokenOwnership(
        address token,
        address newOwner
    ) external onlyOwner {
        require(token != address(0), "token=0");
        require(newOwner != address(0), "newOwner=0");

        IOwnable(token).transferOwnership(newOwner);
    }
}
