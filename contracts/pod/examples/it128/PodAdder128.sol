// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

import "../../mpc/PodLib.sol";
import "../../mpc/PodLibBase.sol";

/// @title PodAdder128
/// @notice Example 128-bit MPC adder using {PodLib}.
contract PodAdder128 is PodLib {
    event AddRequest(bytes32 requestId);

    ctUint128 private _result;

    /// @notice Create an MPC adder bound to an inbox.
    /// @param _inbox The inbox contract address.
    constructor(address _inbox) PodLibBase(msg.sender) {
        setInbox(_inbox);
    }

    /// @notice Send an MPC add request using encrypted inputs.
    /// @param a Encrypted input a (itUint128).
    /// @param b Encrypted input b (itUint128).
    function add(itUint128 calldata a, itUint128 calldata b, uint256 callbackFeeLocalWei) external payable {
        bytes32 requestId = add128(
            a,
            b,
            msg.sender,
            PodAdder128.receiveC.selector,
            PodLibBase.onDefaultMpcError.selector,
            msg.value,
            callbackFeeLocalWei
        );
        emit AddRequest(requestId);
    }

    /// @notice Receive the response and store the ciphertext result.
    /// @param data The response payload containing the ciphertext.
    function receiveC(bytes memory data) external onlyInbox {
        _result = abi.decode(data, (ctUint128));
    }

    /// @notice Return the last received ciphertext result.
    function resultCiphertext() external view returns (ctUint128) {
        return _result;
    }
}
