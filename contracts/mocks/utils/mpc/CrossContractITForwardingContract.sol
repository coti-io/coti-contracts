// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title CrossContractITForwardingContract
 * @notice Contract that accepts IT-types and validates them (instead of receiving GT-types)
 * @dev This tests if IT-types (with signatures) can be passed between contracts
 */
contract CrossContractITForwardingContract {
    
    // Events
    event ITValidated(address indexed sender, string operation);
    event OperationCompleted(address indexed sender, string operation);
    
    /**
     * @notice Validate and add two IT-type uint128 values
     * @dev Accepts IT-types directly from another contract
     * @param a First encrypted value (IT-type with signature)
     * @param b Second encrypted value (IT-type with signature)
     * @return Result as ctUint128 encrypted for the sender
     */
    function validateAndAdd128(
        itUint128 calldata a,
        itUint128 calldata b
    ) external returns (ctUint128) {
        emit ITValidated(msg.sender, "add128");
        
        // Validate IT-types (this should work even when called from another contract)
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        // Perform operation
        gtUint128 result = MpcCore.add(gtA, gtB);
        
        emit OperationCompleted(msg.sender, "add128");
        
        // Return encrypted for the calling contract (msg.sender)
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Validate and multiply two IT-type uint128 values
     */
    function validateAndMul128(
        itUint128 calldata a,
        itUint128 calldata b
    ) external returns (ctUint128) {
        emit ITValidated(msg.sender, "mul128");
        
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.mul(gtA, gtB);
        
        emit OperationCompleted(msg.sender, "mul128");
        
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Validate and add two IT-type uint256 values
     */
    function validateAndAdd256(
        itUint256 calldata a,
        itUint256 calldata b
    ) external returns (ctUint256 memory) {
        emit ITValidated(msg.sender, "add256");
        
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.add(gtA, gtB);
        
        emit OperationCompleted(msg.sender, "add256");
        
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Validate and multiply two IT-type uint256 values
     */
    function validateAndMul256(
        itUint256 calldata a,
        itUint256 calldata b
    ) external returns (ctUint256 memory) {
        emit ITValidated(msg.sender, "mul256");
        
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.mul(gtA, gtB);
        
        emit OperationCompleted(msg.sender, "mul256");
        
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Complex operation: validate three IT-types and compute (a + b) * c
     */
    function validateAndCompute128(
        itUint128 calldata a,
        itUint128 calldata b,
        itUint128 calldata c
    ) external returns (ctUint128) {
        emit ITValidated(msg.sender, "complex128");
        
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        gtUint128 gtC = MpcCore.validateCiphertext(c);
        
        gtUint128 sum = MpcCore.add(gtA, gtB);
        gtUint128 result = MpcCore.mul(sum, gtC);
        
        emit OperationCompleted(msg.sender, "complex128");
        
        return MpcCore.offBoardToUser(result, msg.sender);
    }
}

