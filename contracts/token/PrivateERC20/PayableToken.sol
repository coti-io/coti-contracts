// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {PrivateERC20} from "./PrivateERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "../../utils/mpc/MpcCore.sol";
import "./IERC1363Receiver.sol";

/**
 * @title PayableToken
 * @dev Extension of PrivateERC20 that adds ERC-1363-like transferAndCall functionality.
 *
 * NOTE: For privacy, {onTransferReceived} is called with `value` set to 0. Receivers must not
 * rely on the amount parameter; use `data` or other mechanisms if amount-related logic is needed.
 */
contract PayableToken is PrivateERC20, ReentrancyGuard {
    /// @dev Reverts when the recipient is the token contract itself (no self-callback).
    error PayableTokenInvalidReceiver(address to);

    /// @dev Reverts when the recipient is not a contract (transferAndCall requires a contract to callback).
    error PayableTokenReceiverNotContract(address to);

    constructor(string memory name_, string memory symbol_) PrivateERC20(name_, symbol_) {}

    // =============================================================
    // ERC-1363 Callbacks Implementation
    // =============================================================

    /**
     * @dev Transfers tokens to a contract then invokes {onTransferReceived} on the recipient.
     * The callback receives value=0 for privacy (amount is confidential).
     * Reverts if the recipient is not a contract, or if the transfer failed (e.g. insufficient balance).
     */
    function _transferAndCall(address from, address to, gtUint64 value, bytes calldata data) internal returns (gtBool) {
        if (to == address(this)) {
            revert PayableTokenInvalidReceiver(to);
        }
        if (to.code.length == 0) {
            revert PayableTokenReceiverNotContract(to);
        }

        // 1. Perform standard encrypted transfer
        gtBool success = _transfer(from, to, value);
        require(MpcCore.decrypt(success), "TransferAndCall: transfer failed");

        // 2. Callback: invoke onTransferReceived on the recipient contract
        try IERC1363Receiver(to).onTransferReceived(_msgSender(), from, value, data) returns (bytes4 retval) {
            require(retval == IERC1363Receiver.onTransferReceived.selector, "TransferAndCall: Invalid callback return");
        } catch (bytes memory reason) {
            if (reason.length == 0) {
                revert("TransferAndCall: Transfer to non-ERC1363Receiver implementer");
            } else {
                assembly {
                    revert(add(32, reason), mload(reason))
                }
            }
        }

        return success;
    }

    function transferAndCall(address to, itUint64 calldata value, bytes calldata data) public virtual nonReentrant returns (gtBool) {
        gtUint64 gtValue = MpcCore.validateCiphertext(value);
        return _transferAndCall(_msgSender(), to, gtValue, data);
    }
    
    function transferAndCall(address to, uint64 value, bytes calldata data) public virtual nonReentrant returns (gtBool) {
        gtUint64 gtValue = MpcCore.setPublic64(value);
        return _transferAndCall(_msgSender(), to, gtValue, data);
    }
}
