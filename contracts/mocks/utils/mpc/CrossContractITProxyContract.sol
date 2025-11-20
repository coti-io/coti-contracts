// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";
import "./CrossContractITForwardingContract.sol";

/**
 * @title CrossContractITProxyContract
 * @notice Proxy that forwards IT-types to target contracts (without validating first)
 * @dev This tests if IT-types with signatures can be passed between contracts
 *      Pattern: User → Proxy (forwards IT as-is) → Target (validates IT)
 */
contract CrossContractITProxyContract {
    
    CrossContractITForwardingContract public targetContract;
    
    // Events
    event ITForwarded(address indexed user, string operation, address target);
    event ResultReceived(address indexed user, string operation);
    
    constructor(address _targetContract) {
        targetContract = CrossContractITForwardingContract(_targetContract);
    }
    
    /**
     * @notice Forward IT-types to target for validation and operation
     * @dev This forwards the IT-types without converting to GT first
     * @param a First IT-type value (with signature from user)
     * @param b Second IT-type value (with signature from user)
     * @return Encrypted result from target contract
     */
    function forwardAdd128(
        itUint128 calldata a,
        itUint128 calldata b
    ) external returns (ctUint128) {
        emit ITForwarded(msg.sender, "forwardAdd128", address(targetContract));
        
        // Forward IT-types directly to target (target will validate)
        ctUint128 result = targetContract.validateAndAdd128(a, b);
        
        emit ResultReceived(msg.sender, "forwardAdd128");
        
        return result;
    }
    
    /**
     * @notice Forward IT-types for multiplication
     */
    function forwardMul128(
        itUint128 calldata a,
        itUint128 calldata b
    ) external returns (ctUint128) {
        emit ITForwarded(msg.sender, "forwardMul128", address(targetContract));
        
        ctUint128 result = targetContract.validateAndMul128(a, b);
        
        emit ResultReceived(msg.sender, "forwardMul128");
        
        return result;
    }
    
    /**
     * @notice Forward IT-types for uint256 addition
     */
    function forwardAdd256(
        itUint256 calldata a,
        itUint256 calldata b
    ) external returns (ctUint256 memory) {
        emit ITForwarded(msg.sender, "forwardAdd256", address(targetContract));
        
        ctUint256 memory result = targetContract.validateAndAdd256(a, b);
        
        emit ResultReceived(msg.sender, "forwardAdd256");
        
        return result;
    }
    
    /**
     * @notice Forward IT-types for uint256 multiplication
     */
    function forwardMul256(
        itUint256 calldata a,
        itUint256 calldata b
    ) external returns (ctUint256 memory) {
        emit ITForwarded(msg.sender, "forwardMul256", address(targetContract));
        
        ctUint256 memory result = targetContract.validateAndMul256(a, b);
        
        emit ResultReceived(msg.sender, "forwardMul256");
        
        return result;
    }
    
    /**
     * @notice Forward three IT-types for complex operation
     */
    function forwardComplex128(
        itUint128 calldata a,
        itUint128 calldata b,
        itUint128 calldata c
    ) external returns (ctUint128) {
        emit ITForwarded(msg.sender, "forwardComplex128", address(targetContract));
        
        ctUint128 result = targetContract.validateAndCompute128(a, b, c);
        
        emit ResultReceived(msg.sender, "forwardComplex128");
        
        return result;
    }
    
    /**
     * @notice Hybrid approach: Validate one IT-type in proxy, forward another as-is
     * @dev This tests mixed patterns
     */
    function hybridAdd128(
        itUint128 calldata a,  // Will validate here
        itUint128 calldata b   // Will forward to target
    ) external returns (ctUint128) {
        emit ITForwarded(msg.sender, "hybridAdd128", address(targetContract));
        
        // Validate first IT-type here (IT → GT)
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        
        // Forward second IT-type to target for validation
        // Note: This tests if we can mix GT and IT in cross-contract calls
        ctUint128 result = targetContract.validateAndAdd128(
            a,  // Forward original IT
            b   // Forward original IT
        );
        
        emit ResultReceived(msg.sender, "hybridAdd128");
        
        return result;
    }
}

