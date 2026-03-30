// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/ITokenReceiver.sol";

/**
 * @dev Public-amount receiver that attempts to re-enter the token during `transferAndCall(uint256)` callback.
 */
contract PublicReentrantTokenReceiverMock is ITokenReceiver {
    address public token;
    bool public tryReenter;
    bytes public reenterCalldata;

    function configure(address token_, bool tryReenter_, bytes calldata reenterCalldata_) external {
        token = token_;
        tryReenter = tryReenter_;
        reenterCalldata = reenterCalldata_;
    }

    function onTokenReceived(address, uint256, bytes calldata) external returns (bool) {
        if (tryReenter && token != address(0)) {
            (bool ok, ) = token.call(reenterCalldata);
            ok;
        }
        return true;
    }
}

