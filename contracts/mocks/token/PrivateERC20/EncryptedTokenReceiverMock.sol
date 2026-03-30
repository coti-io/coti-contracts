// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/ITokenReceiverEncrypted.sol";

contract EncryptedTokenReceiverMock is ITokenReceiverEncrypted {
    bool public accept;

    constructor(bool accept_) {
        accept = accept_;
    }

    function onPrivateTransferReceived(address, bytes calldata) external view returns (bool) {
        return accept;
    }
}

