// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../../utils/mpc/MpcCore.sol";

import "../mpc/PodLib.sol";
import "../mpc/PodLibBase.sol";

/// @title MpcAdder
/// @notice Example dApp: 64-bit encrypted add over the inbox using {PodLib}.
contract MpcAdder is PodLib {
    event AddRequest(bytes32 requestId);

    ctUint64 private _result;

    /// @notice Create an MPC adder bound to an inbox.
    /// @param _inbox The inbox contract address.
    constructor(address _inbox) PodLibBase(msg.sender) {
        setInbox(_inbox);
    }

    /// @notice Send an MPC add request using encrypted inputs.
    /// @param a Encrypted input a (itUint64).
    /// @param b Encrypted input b (itUint64).
    /// @param callbackFeeLocalWei Wei slice for callback leg; total inbox payment is `msg.value`.
    function add(itUint64 calldata a, itUint64 calldata b, uint256 callbackFeeLocalWei) external payable {
        bytes32 requestId = add64(
            a,
            b,
            msg.sender,
            MpcAdder.receiveC.selector,
            PodLibBase.onDefaultMpcError.selector,
            msg.value,
            callbackFeeLocalWei
        );
        emit AddRequest(requestId);
    }

    /// @notice Receive the response and store the ciphertext result.
    /// @param data The response payload containing the ciphertext.
    function receiveC(bytes memory data) external virtual onlyMpcExecutor {
        _receiveResult(data);
    }

    /// @dev Allows {MpcAdderPausable} to gate delivery without duplicating storage.
    function _receiveResult(bytes memory data) internal virtual {
        _result = abi.decode(data, (ctUint64));
    }

    /// @notice Return the last received ciphertext result.
    function resultCiphertext() external view returns (ctUint64) {
        return _result;
    }
}



