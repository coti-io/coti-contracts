// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/IPrivateERC20.sol";
import "../../../utils/mpc/MpcCore.sol";

/**
 * @dev Helper that calls the GT overloads using `MpcCore.setPublic256(amount)` to build a gtUint256.
 * Used to test the GT entrypoints without needing an off-chain gtUint256 constructor.
 */
contract PrivateERC20GtCallerMock {
    function transferGT(address token, address to, uint256 amount) external {
        IPrivateERC20(token).transferGT(to, MpcCore.setPublic256(amount));
    }

    function approveGT(address token, address spender, uint256 amount) external {
        IPrivateERC20(token).approveGT(spender, MpcCore.setPublic256(amount));
    }

    function transferFromGT(address token, address from, address to, uint256 amount) external {
        IPrivateERC20(token).transferFromGT(from, to, MpcCore.setPublic256(amount));
    }

    function burnGt(address token, uint256 amount) external {
        IPrivateERC20(token).burnGt(MpcCore.setPublic256(amount));
    }
}

