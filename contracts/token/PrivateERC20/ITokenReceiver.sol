// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/**
 * @dev Interface for receiving Private ERC-20 tokens.
 */
interface ITokenReceiver {
    function onTokenReceived(
        address from,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
}
