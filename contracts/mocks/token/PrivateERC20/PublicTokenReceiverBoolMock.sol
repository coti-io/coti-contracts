// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/ITokenReceiver.sol";

contract PublicTokenReceiverBoolMock is ITokenReceiver {
    bool public accept;

    constructor(bool accept_) {
        accept = accept_;
    }

    function onTokenReceived(address, uint256, bytes calldata) external view returns (bool) {
        return accept;
    }
}

