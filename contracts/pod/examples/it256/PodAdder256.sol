// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

import "../../mpc/PodLib.sol";
import "../../mpc/PodLibBase.sol";

/// @title PodAdder256
/// @notice Example 256-bit MPC adder using {PodLib}.
contract PodAdder256 is PodLib {
    event AddRequest(bytes32 requestId);

    ctUint256 private _result;

    /// @notice Create an MPC adder bound to an inbox.
    /// @param _inbox The inbox contract address.
    constructor(address _inbox) PodLibBase(msg.sender) {
        setInbox(_inbox);
    }

    /// @notice Send an MPC add request using encrypted inputs.
    /// @param a Encrypted input a (itUint256).
    /// @param b Encrypted input b (itUint256).
    function add(itUint256 calldata a, itUint256 calldata b, uint256 callbackFeeLocalWei) external payable {
        bytes32 requestId = add256(
            a,
            b,
            msg.sender,
            PodAdder256.receiveC.selector,
            PodLibBase.onDefaultMpcError.selector,
            msg.value,
            callbackFeeLocalWei
        );
        emit AddRequest(requestId);
    }

    /// @notice Receive the response and store the ciphertext result.
    /// @param data The response payload containing the ciphertext.
    function receiveC(bytes memory data) external onlyInbox {
        _result = abi.decode(data, (ctUint256));
    }

    /// @notice Return the last received ciphertext result.
    function resultCiphertext() external view returns (ctUint256 memory) {
        return _result;
    }
}