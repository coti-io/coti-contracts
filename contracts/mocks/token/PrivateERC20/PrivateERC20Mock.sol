// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/PrivateERC20.sol";
import "../../../utils/mpc/MpcCore.sol";

contract PrivateERC20Mock is PrivateERC20 {
    constructor() PrivateERC20("PrivateERC20Mock", "PE20M") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address account, uint256 amount) public override nonReentrant returns (bool) {
        gtBool success = _mint(account, MpcCore.setPublic256(amount));
        return MpcCore.decrypt(success);
    }

    function burn(address account, uint256 amount) public nonReentrant {
        _burn(account, MpcCore.setPublic256(amount));
    }
}