// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/IPrivateERC20.sol";
import "../../../utils/mpc/MpcCore.sol";

contract PrivateERC20WalletMock {
    constructor() {}

    function setAccountEncryptionAddress(address token, address accountEncryptionAddress) public returns (bool) {
        return IPrivateERC20(token).setAccountEncryptionAddress(accountEncryptionAddress);
    }

    function transfer(address token, address to, uint256 value) public returns (gtBool) {
        return IPrivateERC20(token).transfer(to, MpcCore.setPublic256(value));
    }

    function approve(address token, address spender, uint256 value) public returns (bool) {
        return IPrivateERC20(token).approve(spender, MpcCore.setPublic256(value));
    }

    function transferFrom(address token, address from, address to, uint256 value) public returns (gtBool) {
        return IPrivateERC20(token).transferFrom(from, to, MpcCore.setPublic256(value));
    }
}