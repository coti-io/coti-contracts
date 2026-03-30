// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/ITokenReceiverEncrypted.sol";

interface IPrivateERC20TransferAndCallEncrypted {
    function transferAndCall(
        address to,
        bytes calldata itUint256Value,
        bytes calldata data
    ) external;
}

/**
 * @dev Receiver that attempts to re-enter the token during {transferAndCall} encrypted callback.
 * Used to test {ReentrancyGuard} in PrivateERC20.
 */
contract PrivateERC20ReentrantReceiverMock is ITokenReceiverEncrypted {
    address public token;
    bool public tryReenter;
    bytes public reenterCalldata;

    function configure(address token_, bool tryReenter_, bytes calldata reenterCalldata_) external {
        token = token_;
        tryReenter = tryReenter_;
        reenterCalldata = reenterCalldata_;
    }

    function onPrivateTransferReceived(address, bytes calldata) external returns (bool) {
        if (tryReenter && token != address(0)) {
            // Low-level call to avoid needing full interface/types here.
            (bool ok, ) = token.call(reenterCalldata);
            ok; // ignore; we only care that the outer tx reverts or not
        }
        return true;
    }
}

