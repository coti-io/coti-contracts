// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IMintableERC20 {
    function mint(address to, uint256 amount) external;
}

// MintDisperser lets the owner mint tokens to many recipients in one tx.
// The target token must expose a mint(address,uint256) function and the
// MintDisperser contract must have permission to mint (e.g., MINTER_ROLE/owner).
contract MintDisperser is Ownable {
    constructor(address initialOwner) {
        _transferOwnership(initialOwner);
    }

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
}

