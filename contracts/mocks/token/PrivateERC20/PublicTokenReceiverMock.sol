// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/ITokenReceiver.sol";

contract PublicTokenReceiverMock is ITokenReceiver {
    function onTokenReceived(address, uint256, bytes calldata) external pure returns (bool) {
        return true;
    }
}

