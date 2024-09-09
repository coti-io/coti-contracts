// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/PrivateERC20.sol";

contract PrivateERC20Mock is PrivateERC20 {
    constructor() PrivateERC20("PrivateERC20Mock", "PE20M") {}

    function mint(address account, uint64 amount) external {
        _mint(account, MpcCore.setPublic64(amount));
    }

    function burn(address account, uint64 amount) external {
        _burn(account, MpcCore.setPublic64(amount));
    }
}