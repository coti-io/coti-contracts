// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {PrivateERC20} from "./PrivateERC20.sol";
import "../../utils/mpc/MpcCore.sol";
import "./IERC1363Receiver.sol";

/**
 * @title PayableToken
 * @dev Extension of PrivateERC20 that adds ERC-1363-like transferAndCall functionality.
 */
contract PayableToken is PrivateERC20 {
    
    constructor(string memory name_, string memory symbol_) PrivateERC20(name_, symbol_) {}

    // =============================================================
    // ERC-1363 Callbacks Implementation
    // =============================================================

    function _transferAndCall(address from, address to, gtUint64 value, bytes calldata data) internal returns (gtBool) {
        // 1. Perform standard encrypted transfer
        gtBool success = _transfer(from, to, value);

        // 2. Optimistic callback: Call the recipient if it is a contract
        if (to.code.length > 0) {
            try IERC1363Receiver(to).onTransferReceived(_msgSender(), from, 0, data) returns (bytes4 retval) {
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
        }

        return success;
    }

    function transferAndCall(address to, itUint64 calldata value, bytes calldata data) public virtual returns (gtBool) {
        gtUint64 gtValue = MpcCore.validateCiphertext(value);
        return _transferAndCall(_msgSender(), to, gtValue, data);
    }
    
    function transferAndCall(address to, uint64 value, bytes calldata data) public virtual returns (gtBool) {
        gtUint64 gtValue = MpcCore.setPublic64(value);
        return _transferAndCall(_msgSender(), to, gtValue, data);
    }
}
