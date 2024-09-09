// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/IPrivateERC20.sol";

contract PrivateERC20WalletMock {
    constructor() {}

    function setAccountEncryptionAddress(address token, address accountEncryptionAddress) public returns (bool) {
        return IPrivateERC20(token).setAccountEncryptionAddress(accountEncryptionAddress);
    }

    function transfer(address token, address to, uint64 value) public returns (gtBool) {
        return IPrivateERC20(token).transfer(to, MpcCore.setPublic64(value));
    }

    function approve(address token, address spender, uint64 value) public returns (bool) {
        return IPrivateERC20(token).approve(spender, MpcCore.setPublic64(value));
    }

    function transferFrom(address token, address from, address to, uint64 value) public returns (gtBool) {
        return IPrivateERC20(token).transferFrom(from, to, MpcCore.setPublic64(value));
    }
}