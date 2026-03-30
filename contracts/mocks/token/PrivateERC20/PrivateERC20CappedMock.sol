// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/PrivateERC20.sol";

/// @dev Minimal capped token for testing {supplyCap} enforcement in {_update}.
contract PrivateERC20CappedMock is PrivateERC20 {
    uint256 private immutable _cap;

    constructor(uint256 cap_) PrivateERC20("PrivateERC20CappedMock", "PECAP") {
        _cap = cap_;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function supplyCap() public view override returns (uint256) {
        return _cap;
    }
}

