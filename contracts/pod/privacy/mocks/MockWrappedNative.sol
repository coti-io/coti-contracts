// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../utils/IWrappedNative.sol";
import "./MockERC20.sol";

/// @dev WETH-like wrapper for native portal tests.
contract MockWrappedNative is MockERC20, IWrappedNative {
    constructor(string memory name_, string memory symbol_) MockERC20(name_, symbol_, 18) {}

    receive() external payable {
        deposit();
    }

    function deposit() public payable override {
        _mint(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public override {
        _burn(msg.sender, amount);
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "MockWrappedNative: withdraw failed");
    }
}
