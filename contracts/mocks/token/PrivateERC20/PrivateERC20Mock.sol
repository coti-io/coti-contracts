// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/PrivateERC20.sol";

contract PrivateERC20Mock is PrivateERC20 {
    constructor() PrivateERC20("PrivateERC20Mock", "PE20M") {}

}